mod parsing;

use std::{fmt::Debug, io::Write, ops::{Deref, Range}, process::{Command, Stdio}};

use goblin::elf::{Elf, ProgramHeader};
use region::{Protection, protect};
use mmap::{MapOption, MemoryMap};

type Addr = u64;

struct Segment(ProgramHeader);

impl Deref for Segment {
    type Target = ProgramHeader;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Segment {
    fn file_range(&self) -> Range<Addr> {
        self.p_offset..(self.p_offset + self.p_filesz)
    }

    fn mem_range(&self) -> Range<Addr> {
        self.p_vaddr..(self.p_vaddr + self.p_memsz)
    }
}

impl Debug for Segment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "file {:04x?} | mem {:08x?} | align {:04x?} | {}{}{} {:?}",
            self.file_range(),
            self.mem_range(),
            self.p_align,
            if self.is_read() { "r" } else { "-" },
            if self.is_write() { "w" } else { "-" },
            if self.is_executable() { "x" } else { "-" },
            self.p_type,
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SegmentType {
    Null = 0x0,
    Load = 0x1,
    Dynamic = 0x2,
    Interp = 0x3,
    Note = 0x4,
    ShLib = 0x5,
    PHdr = 0x6,
    TLS = 0x7,
    LoOS = 0x6000_0000,
    HiOS = 0x6FFF_FFFF,
    LoProc = 0x7000_0000,
    HiProc = 0x7FFF_FFFF,
    GnuEhFrame = 0x6474_E550,
    GnuStack = 0x6474_E551,
    GnuRelRo = 0x6474_E552,
    GnuProperty = 0x6474_E553,
}

fn main() {
    let path = std::env::args().nth(1).expect("no path provided");

    println!("Analyzing {:?}...", path);
    let content = std::fs::read(path).unwrap();
    let parsed = Elf::parse(&content).unwrap();

    println!("Entry point: 0x{:x}", parsed.entry);
    println!("Segments:");
    for segm in &parsed.program_headers {
        println!("{:?}", Segment(segm.clone()));
    }

    println!();

    println!("Disassembling...");
    let code_segm = parsed
        .program_headers
        .iter()
        .map(|ph| Segment(ph.clone()))
        .find(|ph| ph.mem_range().contains(&parsed.entry))
        .expect("segment with entry point not found");

    let code = &content[code_segm.p_offset as usize..];
    let code = &code[..code_segm.p_filesz as usize];
    ndisasm(code);

    println!();

    println!("Mapping in memory...");
    let mut mappings = vec![];
    for ph in parsed
        .program_headers
        .iter()
        .filter(|ph| ph.p_type == SegmentType::Load as u32)
        .map(|ph| Segment(ph.clone()))
    {
        println!("Mapping segment @ {:?} with {:?}", ph.mem_range(), ph.p_flags);

        let mem_range = ph.mem_range();
        let min_len: usize = (mem_range.end - mem_range.start) as usize;
        let addr = mem_range.start as *mut u8;

        let map = MemoryMap::new(min_len, &[MapOption::MapWritable, MapOption::MapAddr(addr)]).expect("failed to map");

        println!("Copying segment data...");
        unsafe { std::slice::from_raw_parts_mut(addr, min_len) }
            .copy_from_slice(&content[ph.0.file_range()]);

        println!("Adjusting protection...");
        let mut protection = Protection::NONE;
        if ph.p_flags & (1 << 1) == (1 << 1) { protection |= Protection::READ }
        if ph.p_flags & (1 << 2) == (1 << 2) { protection |= Protection::WRITE }
        if ph.p_flags & (1 << 3) == (1 << 3) { protection |= Protection::EXECUTE }
        unsafe { protect(addr, min_len, protection) }.expect("Failed to protect");

        mappings.push(map);
    }

    println!("Jumping...");
    unsafe {
        region::protect(
            code.as_ptr(),
            code.len(),
            Protection::READ_WRITE_EXECUTE
        ).unwrap();
        jmp(code.as_ptr());
    }
}
