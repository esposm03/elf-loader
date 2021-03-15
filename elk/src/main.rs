use std::{
    fs,
    io::Write,
    process::{Command, Stdio},
};

use delf::components::{
    rela::{KnownRelType, RelType},
    segment::{SegmentFlag, SegmentType},
};
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

    println!("Analyzing {:?}...", input_path);
    let file = match delf::File::parse_or_print_error(&content) {
        Some(f) => f,
        None => std::process::exit(1),
    };
    println!("Entry point: {:X}", file.entry_point.0);
    println!("Program Headers: {:#?}", file.program_headers);

    let mut mappings = Vec::new();
    let rela_entries = file.read_rela_entries().unwrap_or_else(|e| {
        println!("Failed to read relocations: {:?}", e);
        Vec::new()
    });
    let base = 0x400000;

    println!();
    println!("Loading with base address 0x{:X}", base);

    let non_empty_program_headers = file
        .program_headers
        .iter()
        .filter(|ph| ph.r#type == SegmentType::Load)
        .filter(|ph| !ph.mem_range().is_empty());

    for ph in non_empty_program_headers {
        println!("Mapping {:?} - {:?}", ph.mem_range(), ph.flags);

        let mem_range = ph.mem_range();
        let len: usize = (mem_range.end - mem_range.start).into();

        let start = mem_range.start.0 + base;
        let aligned_start = align_lo(start);
        let padding = start - aligned_start;
        let len = len + padding as usize;

        let addr = aligned_start as *mut u8;
        if padding > 0 {
            println!("(With 0x{:X} bytes of padding at the start)", padding);
        }

        let map = MemoryMap::new(len, &[MapOption::MapWritable, MapOption::MapAddr(addr)]).unwrap();

        // Copy segment data
        let addr = (aligned_start + padding) as *mut u8;
        let segment_data = unsafe { std::slice::from_raw_parts_mut(addr, ph.data.len()) };
        segment_data.copy_from_slice(&ph.data[..]);

        // Apply relocations
        let mut num_relocs = 0;
        for reloc in &rela_entries {
            if mem_range.contains(&reloc.offset) {
                num_relocs += 1;
                unsafe {
                    use std::mem::transmute as trans;
                    let real_segment_start = addr.add(padding as usize);

                    let specified_reloc_offset = reloc.offset;
                    let specified_segment_start = mem_range.start;
                    let offset_into_segment = specified_reloc_offset - specified_segment_start;

                    let reloc_addr: *mut u64 =
                        trans(real_segment_start.add(offset_into_segment.into()));
                    match reloc.r#type {
                        RelType::Known(t) => {
                            num_relocs += 1;
                            if let KnownRelType::Relative = t {
                                let reloc_value: _ = reloc.addend + delf::Addr(base as u64);
                                *reloc_addr = reloc_value.0;
                            } else {
                                panic!(format!("Unsupported relocation type {:?}", t));
                            }
                        }
                        RelType::Unknown(i) => {
                            println!("(Found unknown relocation type {})", i);
                        }
                    }
                }
            }
        }

        if num_relocs > 0 {
            println!("(Applied {} relocations)", num_relocs);
        }

        // Changing memory area permissions
        let mut protection = Protection::NONE;
        for flag in ph.flags.iter() {
            protection |= match flag {
                SegmentFlag::Read => Protection::READ,
                SegmentFlag::Write => Protection::WRITE,
                SegmentFlag::Execute => Protection::EXECUTE,
            }
        }
        unsafe {
            protect(addr, len, protection).unwrap();
        }
        mappings.push(map);
    }

    // --- JUMPING ---

    let to_jmp = (file.entry_point.0 + base as u64) as *const u8;
    println!("Jumping to entry point @ {:?}...\n", to_jmp);
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
