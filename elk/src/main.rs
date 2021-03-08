use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};

use mmap::{MapOption, MemoryMap};
use region::{protect, Protection};

fn main() {
    let input_path = std::env::args().nth(1).expect("Usage: elk <path>");
    let content = fs::read(&input_path).expect("Failed to read file");

    println!("Analysing...");
    let file = delf::File::parse_or_print_error(&content).expect("Failed to parse file");
    println!("{:#?}", file);

    println!("Disassembling...");
    let code_ph = file
        .program_headers
        .iter()
        .find(|ph| ph.mem_range().contains(&file.entry_point))
        .expect("segment with entry point not found");
    ndisasm(&code_ph.data[..], file.entry_point);

    println!("Mapping {:?} in memory...", input_path);

    // we'll need to hold onto our "mmap::MemoryMap", because dropping them
    // unmaps them!
    let mut mappings = Vec::new();
    let base = 0x400000;
    let addr = 0x1000;
    println!("{:X} + {:X} = {:X}", addr, base, addr+base);

    // we're only interested in "Load" segments
    for ph in file
        .program_headers
        .iter()
        .filter(|ph| ph.r#type == delf::SegmentType::Load)
        .filter(|ph| !ph.mem_range().is_empty())
    {
        println!("Mapping segment @ virt {:?}, adjusted {:X}..{:X}, flags {:?}", ph.mem_range(), ph.mem_range().start.0 + base, ph.mem_range().end.0 + base, ph.flags);
        let mem_range = ph.mem_range();
        let len: usize = (mem_range.end - mem_range.start).into();

        let start = mem_range.start.0 + base;
        let aligned_start = align_lo(start);
        let padding = start - aligned_start;
        let len = len + padding as usize;

        let addr = aligned_start as *mut u8;
        let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)]).unwrap();

        println!("Copying segment data...");
        unsafe { std::slice::from_raw_parts_mut(addr, ph.data.len()) }
            .copy_from_slice(&ph.data[..]);

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

    println!("u64: {:X}, *const u8: {:X?}", file.entry_point.0 + base as u64, (file.entry_point.0 + base as u64) as *const u8);
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
