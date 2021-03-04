use std::{fs, io::Write, process::{Command, Stdio}};

use mmap::{MapOption, MemoryMap};
use region::{Protection, protect};

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

    // we're only interested in "Load" segments
    for ph in file
        .program_headers
        .iter()
        .filter(|ph| ph.r#type == delf::SegmentType::Load)
    {
        println!("Mapping segment @ {:?} with {:?}", ph.mem_range(), ph.flags);
        // note: mmap-ing would fail if the segments weren't aligned on pages,
        // but luckily, that is the case in the file already. That is not a coincidence.
        let mem_range = ph.mem_range();
        let len: usize = (mem_range.end - mem_range.start).into();
        // `as` is the "cast" operator, and `_` is a placeholder to force rustc
        // to infer the type based on other hints (here, the left-hand-side declaration)
        let addr: *mut u8 = mem_range.start.0 as _;
        // at first, we want the memory area to be writable, so we can copy to it.
        // we'll set the right permissions later
        let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)]).unwrap();

        println!("Copying segment data...");
        {
            let dst = unsafe { std::slice::from_raw_parts_mut(addr, ph.data.len()) };
            dst.copy_from_slice(&ph.data[..]);
        }

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

    println!("Jumping to entry point @ {:?}...", file.entry_point);
    unsafe {
        jmp(file.entry_point.0 as _);
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
