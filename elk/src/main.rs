#![allow(unused_imports)]
#![allow(unused_variables)]
#![allow(dead_code)]

mod process;

use std::{error::Error, fs, io::Write, process::{Command, Stdio}};

use delf::components::{rela::{KnownRelType, RelType}, segment::{DynamicTag, SegmentContents, SegmentFlag, SegmentType}};
use mmap::{MapOption, MemoryMap};
use process::Process;
use region::{protect, Protection};

fn main() -> Result<(), Box<dyn Error>> {
    let input_path = std::env::args().nth(1).expect("Usage: elk <path>");

    let mut proc = Process::new();
    let exec = proc.load_obj_and_deps(&input_path).unwrap();
    //println!("{:#?}", proc);

    Ok(())
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
