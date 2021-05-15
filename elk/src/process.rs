//! Loading of ELF objects, with dependencies

use delf::{
    components::{dynamic::DynamicTag, section::SectionType},
    errors::{ReadRelaError, ReadSymsError},
};

use std::{
    cmp::{max, min},
    collections::HashMap,
    mem,
    ops::Range,
};
use std::{
    fs,
    io::Read,
    os::unix::io::AsRawFd,
    path::{Path, PathBuf},
};

use custom_debug_derive::Debug as CustomDebug;
use enumflags2::BitFlags;
use mmap::{MapOption, MemoryMap};

use delf::{
    components::{
        rela::{Rela, RelocationType},
        segment::{SegmentFlag, SegmentType},
        sym::Sym,
    },
    Addr, ParsedElf,
};

/// An executable process in memory
///
/// A process may need several different ELF objects. Take, for example, a
/// process with a main executable, `dummy`, that depends on a dynamically
/// linked library, `liba.so`. Both `dummy` and `liba.so` are ELF objects
/// (files), that need to be mapped (loaded) in different memory areas, with
/// the right permission
///
/// This struct represents a list of [`Object`]s
#[derive(Debug)]
pub struct Process {
    pub objects: Vec<Object>,
    pub search_path: Vec<PathBuf>,
    pub objects_by_path: HashMap<PathBuf, usize>,
    pub files: Vec<Vec<u8>>,
}

impl<'a> Process {
    /// Create a new, empty [`Process`]
    pub fn new() -> Self {
        Self {
            objects: vec![],
            search_path: vec!["/usr/lib".into()],
            objects_by_path: HashMap::new(),
            files: vec![],
        }
    }

    /// Load an object, without its dependencies
    ///
    /// This method reads the file at the given `path`, parses it,
    /// and maps it to memory. However, if that file has some
    /// dependencies, they will get skipped. If that's not desidred,
    /// you may be looking for the [`load_obj_and_deps`](Self::load_obj_and_deps)
    /// method
    pub fn load_object<T: AsRef<Path>>(&mut self, path: T) -> Result<usize, LoadError> {
        let path = path
            .as_ref()
            .canonicalize()
            .map_err(|e| LoadError::IO(path.as_ref().to_path_buf(), e))?;
        let origin = path
            .parent()
            .ok_or_else(|| LoadError::InvalidPath(path.clone()))?
            .to_str()
            .ok_or_else(|| LoadError::InvalidPath(path.clone()))?;

        let mut input = Box::leak(Box::default());
        let mut fs_file: _ = fs::File::open(&path).map_err(|e| LoadError::IO(path.clone(), e))?;
        fs_file
            .read_to_end(&mut input)
            .map_err(|e| LoadError::IO(path.clone(), e))?;

        println!("Loading {:?}", path);
        let file = ParsedElf::parse_or_print_error(input)
            .ok_or_else(|| LoadError::ParseError(path.clone()))?;

        let load_segments = || {
            file.program_headers
                .iter()
                .filter(|&ph| ph.typ == SegmentType::Load)
        };

        // Add `DT_RUNPATH` members to the search path
        let _ = file
            .dynamic_section()
            .map(|sect| Box::leak(Box::new(sect)).entry_with_tag(DynamicTag::RPath))
            .flatten()
            .map(|entry| Box::leak(Box::new(entry.addr)).unwrap_string())
            .map(|path| path.replace("$ORIGIN", &origin))
            .map(|path| path.split(':').map(|i| i.to_string()).collect::<Vec<_>>())
            .map(|strs| {
                strs.iter()
                    .filter(|i| !i.contains("/nix/store"))
                    .map(PathBuf::from)
                    .for_each(|rpath| self.search_path.push(rpath))
            });

        let mem_range = load_segments()
            .map(|ph| ph.mem_range())
            .fold(None, |acc, range| match acc {
                None => Some(range),
                Some(acc) => Some(convex_hull(acc, range)),
            })
            .ok_or(LoadError::NoLoadSegments)?;

        let mem_size: usize = (mem_range.end - mem_range.start).into();
        let mem_map = MemoryMap::new(mem_size, &[MapOption::MapWritable, MapOption::MapReadable])?;
        let base = Addr(mem_map.data() as _);
        mem::forget(mem_map); // Forget the mapping, so it doesn't get dropped
        println!("Base {:?}", base);

        let segments = load_segments()
            .filter(|&ph| ph.memsz.0 > 0)
            .map(|ph| -> Result<_, LoadError> {
                let vaddr = delf::Addr(ph.vaddr.0 & !0xFFF);
                let padding = ph.vaddr - vaddr;
                let offset = ph.offset - padding;
                let filesz = ph.filesz + padding;
                let map = MemoryMap::new(
                    filesz.into(),
                    &[
                        MapOption::MapReadable,
                        MapOption::MapWritable,
                        MapOption::MapFd(fs_file.as_raw_fd()),
                        MapOption::MapOffset(offset.into()),
                        MapOption::MapAddr(unsafe { (base + vaddr).as_ptr() }),
                    ],
                )?;

                // Zero out BSS
                if ph.memsz > ph.filesz {
                    let mut zero_start = base + ph.mem_range().start + ph.filesz;
                    let zero_len = ph.memsz - ph.filesz;
                    unsafe {
                        for i in zero_start.as_mut_slice(zero_len.into()) {
                            *i = 0u8;
                        }
                    }
                }

                Ok(Segment {
                    map,
                    padding,
                    flags: ph.flags,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // let syms = file.read_syms()?;
        // let syms: Vec<_> = syms
        // .into_iter()
        // .map(|sym| {
        // let name = Name::owned(file.strtab.at(sym.name).expect("No symbol name").as_bytes());
        // NamedSym { sym, name }
        // })
        // .collect();

        // let sym_map = MultiMap::new();
        // for sym in &syms {
        //    sym_map.insert(sym.name.clone(), sym.clone());
        // }

        self.objects.push(Object {
            path: path.clone(),
            base,
            mem_range,
            file,
            segments,
        });

        self.objects_by_path.insert(path, self.objects.len() - 1);
        Ok(self.objects.len() - 1)
    }

    /// Load an object and all its dependencies
    ///
    /// This method reads the file at the given `path`, and loads it
    /// to memory, with all its dependencies
    pub fn load_obj_and_deps<T: AsRef<Path>>(&mut self, path: T) -> Result<usize, LoadError> {
        let index = self.load_object(path)?;

        let mut a = vec![index];
        while !a.is_empty() {
            use DynamicTag::Needed;
            a = a
                .into_iter()
                .map(|index| self.objects[index].file.clone())
                .flat_map(|file| {
                    let file = Box::leak(Box::new(file));
                    let dyn_sect = Box::leak(Box::new(file.dynamic_section()?));
                    let dyn_entry = Box::leak(Box::new(dyn_sect.entry_with_tag(Needed)?));
                    Some(dyn_entry.addr.unwrap_string())
                })
                .collect::<Vec<_>>()
                .into_iter()
                .map(|dep| self.get_object(&dep))
                .collect::<Result<Vec<_>, _>>()?
                .into_iter()
                .filter_map(GetResult::fresh)
                .collect();
        }

        Ok(index)
    }

    /// Find an object in the search path, and return its location
    pub fn object_path(&self, name: &str) -> Result<PathBuf, LoadError> {
        self.search_path
            .iter()
            .filter_map(|prefix| prefix.join(name).canonicalize().ok())
            .find(|path| path.exists())
            .ok_or_else(|| LoadError::NotFound(name.into()))
    }

    /// Retrieve an object by name
    ///
    /// This method gives a `Cached(obj)` if the object was
    /// already loaded, or a `Fresh(obj)` if it wasn't, and
    /// a lookup was necessary.
    pub fn get_object(&mut self, name: &str) -> Result<GetResult, LoadError> {
        let path = self.object_path(name)?;
        self.objects_by_path
            .get(&path)
            .map(|&index| Ok(GetResult::Cached(index)))
            .unwrap_or_else(|| self.load_object(path).map(GetResult::Fresh))
    }

    /// Lookup a symbol from the ones defined in the process
    pub fn lookup_symbol(&self, name: &str) -> Option<(&Object, Sym)> {
        print!("Looking up symbol {}... ", name);
        for obj in self.objects.iter().rev() {
            let symtab_index = obj.file.section_with_type(SectionType::SymTab)?;
            let symtab = Box::leak(Box::new(obj.file.symtab(symtab_index)?));

            for sym in symtab.syms() {
                if sym.name == name {
                    println!(
                        "found in object {:?} with val {}",
                        obj.path.file_name().unwrap(),
                        sym.value
                    );
                    return Some((obj, sym.clone()));
                }
            }
        }
        None
    }

    /// Apply all the relocations of this process
    pub fn apply_relocations(&self) -> Result<(), RelocationError> {
        let rels: Vec<_> = self
            .objects
            .iter()
            .rev()
            .flat_map(|obj| {
                let rela_table_index = obj.file.section_with_type(SectionType::Rela)?;

                let rela_table = Box::leak(Box::new(obj.file.rela(rela_table_index)?));
                Some(rela_table.iter().map(move |rel| ObjectRel {
                    relobj: &obj,
                    rel: rel.clone(),
                }))
            })
            .flatten()
            .collect();

        for rel in rels {
            self.apply_relocation(rel)?;
        }
        Ok(())
    }

    /// Apply a single relocation
    fn apply_relocation(&self, objrel: ObjectRel) -> Result<(), RelocationError> {
        use RelocationType as RT;

        let rel = &objrel.rel;
        let reltype = rel.typ;
        let addend = rel.addend;

        // Perform symbol lookup early
        let (obj, found) = self
            .lookup_symbol(rel.sym.name.as_ref())
            .ok_or_else(|| RelocationError::UndefinedSymbol(rel.sym.name.to_string()))?;

        match reltype {
            RT::_64 => unsafe {
                objrel.addr().set(found.value + obj.base + addend);
            },
            RT::Relative => unsafe {
                objrel.addr().set(obj.base + addend);
            },
            RT::Copy => unsafe {
                objrel
                    .addr()
                    .write((found.value + obj.base).as_slice(found.size as usize));
            },
            RT::IRelative => unsafe {
                let function: fn() -> *const u8 =
                    std::mem::transmute((rel.addend + objrel.relobj.base).as_ptr::<u8>());
                function();
                objrel.addr().set(function() as u64);
            },
            _ => return Err(RelocationError::UnimplementedRelocation(reltype)),
        }
        Ok(())
    }

    /// Set the correct protection for the segments of this process
    pub fn adjust_protections(&self) -> Result<(), region::Error> {
        use region::{protect, Protection};

        for obj in &self.objects {
            for seg in &obj.segments {
                let mut protection = Protection::NONE;
                for flag in seg.flags.iter() {
                    protection |= match flag {
                        SegmentFlag::Read => Protection::READ,
                        SegmentFlag::Write => Protection::WRITE,
                        SegmentFlag::Execute => Protection::EXECUTE,
                    }
                }
                unsafe {
                    protect(seg.map.data(), seg.map.len(), protection)?;
                }
            }
        }
        Ok(())
    }
}

/// An ELF object
#[derive(CustomDebug)]
pub struct Object {
    pub path: PathBuf,
    pub base: Addr,
    pub mem_range: Range<Addr>,

    #[debug(skip)]
    pub file: ParsedElf<'static>,
    #[debug(skip)]
    pub segments: Vec<Segment>,
}

/// A segment for an [`Object`]
#[derive(CustomDebug)]
pub struct Segment {
    #[debug(skip)]
    pub map: MemoryMap,
    pub padding: Addr,
    pub flags: BitFlags<SegmentFlag>,
}

#[derive(Debug, Clone)]
pub struct ObjectSym<'a> {
    obj: &'a Object,
    sym: &'a Sym<'a>,
}

#[derive(Debug)]
pub struct ObjectRel<'a> {
    relobj: &'a Object,
    rel: Rela<'a>,
}

impl ObjectRel<'_> {
    fn addr(&self) -> Addr {
        self.relobj.base + self.rel.offset
    }
}

/// Get a range that contains both `a` and `b`
pub fn convex_hull(a: Range<Addr>, b: Range<Addr>) -> Range<Addr> {
    min(a.start, b.start)..max(a.end, b.end)
}

/// Dump the memory maps of the current process
#[allow(dead_code)]
pub fn dump_maps(msg: &str) {
    println!("======== MEMORY MAPS: {}", msg);
    fs::read_to_string(format!("/proc/{pid}/maps", pid = std::process::id()))
        .unwrap()
        .lines()
        .filter(|line| line.contains("hello-dl") || line.contains("libmsg.so"))
        .for_each(|line| println!("{}", line));
    println!("=============================");
}

#[derive(thiserror::Error, Debug)]
pub enum LoadError {
    #[error("ELF object not found: {0}")]
    NotFound(String),
    #[error("An invalid or unsupported path was encountered")]
    InvalidPath(PathBuf),
    #[error("I/O Error: {0}")]
    IO(PathBuf, std::io::Error),
    #[error("ELF object could not be parsed: {0}")]
    ParseError(PathBuf),
    #[error("ELF object has no load segments")]
    NoLoadSegments,
    #[error("ELF object could not be mapped to memory: {0}")]
    MapError(#[from] mmap::MapError),
    #[error("Could not read symbols from ELF object: {0}")]
    ReadSymsError(#[from] ReadSymsError),
    #[error("Could not read relocations from ELF object: {0}")]
    ReadRelaError(#[from] ReadRelaError),
}

#[derive(thiserror::Error, Debug)]
pub enum RelocationError {
    #[error("unimplemented relocation: {0:?}")]
    UnimplementedRelocation(RelocationType),
    #[allow(dead_code)]
    #[error("unknown symbol number: {0}")]
    UnknownSymbolNumber(u32),
    #[error("undefined symbol: {0}")]
    UndefinedSymbol(String),
}

pub enum GetResult {
    Cached(usize),
    Fresh(usize),
}

impl GetResult {
    fn fresh(self) -> Option<usize> {
        if let Self::Fresh(index) = self {
            Some(index)
        } else {
            None
        }
    }
}
