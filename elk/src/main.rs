pub(crate) mod name;
mod process;
use process::Process;

use std::error::Error;

fn main() {
    if let Err(e) = do_main() {
        eprintln!("Fatal error: {}", e);
    }
}

fn do_main() -> Result<(), Box<dyn Error>> {
    let input_path = std::env::args().nth(1).expect("Usage: elk <path>");

    let mut proc = Process::new();
    let exec = proc.load_obj_and_deps(&input_path)?;
    println!("Obj and deps loaded");
    proc.apply_relocations()?;
    proc.adjust_protections()?;

    let obj = &proc.objects[exec];
    let entry_point: delf::Addr = obj.file.entry_point + obj.base;
    unsafe { jmp(entry_point.as_ptr()) }

    Ok(())
}

/// Jump to the given address
pub unsafe fn jmp(addr: *const u8) {
    let addr: fn() = std::mem::transmute(addr);
    addr();
}
