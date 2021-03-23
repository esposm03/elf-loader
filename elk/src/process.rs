use std::{
    ops::Range,
    cmp::{max, min},
    collections::HashMap,
};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    os::unix::io::AsRawFd,
};
use std::mem;

use enumflags2::BitFlags;
use mmap::{MapOption, MemoryMap};
use custom_debug_derive::Debug as CustomDebug;

use delf::{
    Addr,
    File,
    Sym,
    components::{
        rela::{KnownRelType, RelType},
        segment::{DynamicTag, SegmentFlag, SegmentType}
    }
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
}

impl Process {
    /// Create a new, empty [`Process`]
    pub fn new() -> Self {
        Self {
            objects: vec![],
            search_path: vec!["/usr/lib".into()],
            objects_by_path: HashMap::new(),
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

        let mut input = vec![];
        let mut fs_file: _ = fs::File::open(&path).map_err(|e| LoadError::IO(path.clone(), e))?;
        fs_file
            .read_to_end(&mut input)
            .map_err(|e| LoadError::IO(path.clone(), e))?;

        println!("Loading {:?}", path);
        let file = File::parse_or_print_error(&input)
            .ok_or_else(|| LoadError::ParseError(path.clone()))?;

        let load_segments = || {
            file.program_headers
                .iter()
                .filter(|&ph| ph.r#type == SegmentType::Load)
        };

        let origin = path
            .parent()
            .ok_or_else(|| LoadError::InvalidPath(path.clone()))?
            .to_str()
            .ok_or_else(|| LoadError::InvalidPath(path.clone()))?;

        // Add `DT_RUNPATH` members to the search path
        file.dynamic_entry_strings(DynamicTag::Runpath)
            .map(|path| path.replace("$ORIGIN", &origin))
            .map(|path| path.split(":").map(|i| i.to_string()).collect::<Vec<_>>())
            .flatten()
            .filter(|i| !i.contains("/nix/store"))
            .map(PathBuf::from)
            .for_each(|rpath| self.search_path.push(rpath));

        let mem_range = load_segments()
            .map(|ph| ph.mem_range())
            .fold(None, |acc, range| match acc {
                None => Some(range),
                Some(acc) => Some(convex_hull(acc, range)),
            })
            .ok_or(LoadError::NoLoadSegments)?;

        let mem_size: usize = (mem_range.end - mem_range.start).into();
        let mem_map = MemoryMap::new(mem_size, &[])?;
        let base = Addr(mem_map.data() as _);
        mem::forget(mem_map);

        let segments = load_segments()
            .filter_map(|ph| {
                if ph.memsz.0 > 0 {
                    let vaddr = delf::Addr(ph.vaddr.0 & !0xFFF);
                    let padding: Addr = ph.vaddr - vaddr;
                    let offset: Addr = ph.offset - padding;
                    let memsz: Addr = ph.memsz + padding;
                    let map_res = MemoryMap::new(
                        memsz.into(),
                        &[
                            MapOption::MapFd(fs_file.as_raw_fd()),
                            MapOption::MapOffset(offset.into()),
                            MapOption::MapAddr(unsafe { (base + vaddr).as_ptr() }),
                            MapOption::MapReadable,
                            MapOption::MapWritable,
                        ],
                    );

                    Some(map_res.map(|map| Segment {
                        map,
                        padding,
                        flags: ph.flags,
                    }))
                } else {
                    None
                }
            })
            .collect::<Result<Vec<_>, _>>()?;

        let syms = file.read_syms()?;

        self.objects.push(Object {
            path: path.clone(),
            base,
            mem_range,
            file,
            syms,
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
                .map(|index| &self.objects[index].file)
                .flat_map(|file| file.dynamic_entry_strings(Needed))
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

    /// Find a symbol by name, optionally excluding an object from the search
    pub fn lookup_symbol(&self, name: &str, ignore: Option<&Object>) -> Result<Option<(&Object, &delf::Sym)>, RelocationError> {
        let candidates = self
            .objects
            .iter()
            .filter(|&obj| if let Some(ign) = ignore {
                !std::ptr::eq(obj, ign)
            } else {
                true
            });
        for obj in candidates {
            for (i, sym) in obj.syms.iter().enumerate() {
                if obj.sym_name(i as u32)? == name {
                    return Ok(Some((obj, sym)))
                }
            }
        }
        Ok(None)
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

    pub fn apply_relocations(&self) -> Result<(), RelocationError> {
        for obj in self.objects.iter().rev() {
            println!("Applying relocations for {:?}", obj.path);

            match obj.file.read_rela_entries() {
                Ok(rels) => for rel in rels {
                    println!("Found {:?}", rel);
                    match rel.r#type {
                        RelType::Known(KnownRelType::_64) => {
                            let name = obj.sym_name(rel.sym)?;

                            let (lib, sym) = self
                                .lookup_symbol(&name, None)?
                                .ok_or(RelocationError::UndefinedSymbol(name))?;
                            let offset = obj.base + rel.offset;
                            let value = sym.value + lib.base + rel.addend;

                            unsafe {
                                let ptr: *mut u64 = offset.as_mut_ptr();
                                *ptr = value.0;
                            }
                        }
                        RelType::Known(KnownRelType::Copy) => {
                            let name = obj.sym_name(rel.sym)?;
                            let (lib, sym) =
                                self.lookup_symbol(&name, Some(obj))?.ok_or_else(|| {
                                    RelocationError::UndefinedSymbol(name.clone())
                                })?;
                            unsafe {
                                let src = (sym.value + lib.base).as_ptr();
                                let dst = (rel.offset + obj.base).as_mut_ptr();
                                std::ptr::copy_nonoverlapping::<u8>(
                                    src,
                                    dst,
                                    sym.size as usize,
                                );
                            }
                        }
                        RelType::Known(t) => return Err(RelocationError::UnimplementedRelocation(t)),
                        RelType::Unknown(n) => return Err(RelocationError::UnknownRelocation(n)),
                    }
                }
                Err(e) => println!("Nevermind: {:?}", e),
            }
        }

        Ok(())
    }

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

/// Get a range that contains both `a` and `b`
pub fn convex_hull(a: Range<Addr>, b: Range<Addr>) -> Range<Addr> {
    min(a.start, b.start)..max(a.end, b.end)
}

/// Dump the memory maps of the current process
fn dump_maps(msg: &str) {
    use std::{fs, process};

    println!("======== MEMORY MAPS: {}", msg);
    fs::read_to_string(format!("/proc/{pid}/maps", pid = process::id()))
        .unwrap()
        .lines()
        .filter(|line| line.contains("hello-dl") || line.contains("libmsg.so"))
        .for_each(|line| println!("{}", line));
    println!("=============================");
}

#[derive(CustomDebug)]
pub struct Object {
    pub path: PathBuf,
    pub base: Addr,
    pub mem_range: Range<Addr>,

    #[debug(skip)]
    pub file: File,
    #[debug(skip)]
    pub segments: Vec<Segment>,
    #[debug(skip)]
    pub syms: Vec<Sym>,
}

impl Object {
    pub fn sym_name(&self, index: u32) -> Result<String, RelocationError> {
        self.file
            .get_string(self.syms[index as usize].name)
            .map_err(|_| RelocationError::UnknownSymbolNumber(index))
    }
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
    ReadSymsError(#[from] delf::ReadSymsError),
}

#[derive(thiserror::Error, Debug)]
pub enum RelocationError {
    #[error("unknown relocation: {0}")]
    UnknownRelocation(u32),
    #[error("unimplemented relocation: {0:?}")]
    UnimplementedRelocation(KnownRelType),
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

#[derive(CustomDebug)]
pub struct Segment {
    #[debug(skip)]
    pub map: MemoryMap,
    pub padding: Addr,
    pub flags: BitFlags<SegmentFlag>,
}
