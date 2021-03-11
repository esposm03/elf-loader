use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};

use delf::components::segment::{SegmentContents, SegmentType};
use mmap::{MapOption, MemoryMap};
use region::{protect, Protection};

fn main() {
    // General steps:
    // - load and parse the Elf file
    // - Map every segment that is `Load` to the right place in memory
    // - Set the correct memory protection for each mapping
    // - For each segment, copy its data from the file to memory
    // - Jump to the entry point

    let input_path = std::env::args().nth(1).expect("Usage: elk <path>");
    let content = fs::read(&input_path).expect("Failed to read file");

    println!("Analysing...");
    let file = delf::File::parse_or_print_error(&content).expect("Failed to parse file");
    println!("Entry point: {:X}", file.entry_point.0);
    println!("Program Headers: {:#?}", file.program_headers);

    println!("Dynamic entries:");
    if let Some(ds) = file
        .program_headers
        .iter()
        .find(|ph| ph.r#type == SegmentType::Dynamic)
    {
        if let SegmentContents::Dynamic(ref table) = ds.contents {
            for entry in table {
                println!("- {:?}", entry);
            }
        }
    }

    println!();
    println!("Disassembling...");
    let code_ph = file
        .program_headers
        .iter()
        .find(|ph| ph.mem_range().contains(&file.entry_point))
        .expect("segment with entry point not found");
    ndisasm(&code_ph.data[..], file.entry_point);

    // --- MAPPING SEGMENTS ---

    println!("Mapping {:?} in memory...", input_path);

    let mut mappings = Vec::new();
    let base = 0x400000;

    for ph in file
        .program_headers
        .iter()
        .filter(|ph| ph.r#type == SegmentType::Load)
        .filter(|ph| !ph.mem_range().is_empty())
    {
        let mem_range = ph.mem_range();
        let len: usize = (mem_range.end - mem_range.start).into();

        let start = mem_range.start.0 + base;
        let aligned_start = align_lo(start);
        let padding = start - aligned_start;
        let len = len + padding as usize;

        println!(
            "Mapping segment @ virt {:?}, adjusted {:X}..{:X}, padding {:X}",
            ph.mem_range(),
            ph.mem_range().start.0 + base,
            ph.mem_range().end.0 + base,
            padding
        );

        let addr = aligned_start as *mut u8;
        let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)]).unwrap();

        println!("Copying segment data to addr {:?}...", addr);
        let addr = (aligned_start + padding) as *mut u8;
        let segment_data = unsafe { std::slice::from_raw_parts_mut(addr, ph.data.len()) };
        segment_data.copy_from_slice(&ph.data[..]);

        println!("Adjusting permissions...");
        let mut protection = Protection::NONE;
        for flag in ph.flags.iter() {
            protection |= match flag {
                delf::SegmentFlag::Read => Protection::READ,
                delf::SegmentFlag::Write => Protection::WRITE,
                delf::SegmentFlag::Execute => Protection::EXECUTE,
            }
        }
        unsafe {
            protect(addr, len, protection).unwrap();
        }
        mappings.push(map);
    }

    // --- JUMPING ---

    let to_jmp = (file.entry_point.0 + base as u64) as *const u8;
    println!("Jumping to entry point @ {:?}...", to_jmp);
    unsafe {
        jmp(to_jmp);
    }
}

/// Jump to the given address
pub unsafe fn jmp(addr: *const u8) {
    let addr: fn() = std::mem::transmute(addr);
    addr();
}

/// Disassemble the given code
pub fn ndisasm(code: &[u8], origin: delf::Addr) {
    let mut child = Command::new("ndisasm")
        .arg("-b")
        .arg("64")
        .arg("-o")
        .arg(format!("{}", origin.0))
        .arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("Failed to execute `ndisasm`");

    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(code)
        .expect("Failed to write code to `ndisasm`");
    let output = child.wait_with_output().unwrap();

    println!("{}", String::from_utf8_lossy(&output.stdout));
}

/// Truncates a usize value to the left-adjacent (low) 4KiB boundary.
fn align_lo(x: u64) -> u64 {
    x & !0xFFF
}
