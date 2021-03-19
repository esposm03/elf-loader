use std::{collections::HashMap, fs, path::{Path, PathBuf}};

use delf::{Addr, File, components::segment::DynamicTag};
use mmap::MemoryMap;
use custom_debug_derive::Debug as CustomDebug;

#[derive(Debug)]
pub struct Process {
    pub objects: Vec<Object>,
    pub search_path: Vec<PathBuf>,
    pub objects_by_path: HashMap<PathBuf, usize>,
}

#[allow(dead_code)]
#[allow(unused_variables)]
impl Process {
    pub fn new() -> Self {
        Self {
            objects: vec![],
            search_path: vec!["/usr/lib".into()],
            objects_by_path: HashMap::new(),
        }
    }

    pub fn load_object<T: AsRef<Path>>(&mut self, path: T) -> Result<usize, LoadError> {
        let path = path.as_ref().canonicalize()?;
        let input = fs::read(&path)?;

        println!("Loading {:?}", path);
        let file = File::parse_or_print_error(&input)
            .ok_or_else(|| LoadError::ParseError(path.clone()))?;

        let origin = path
            .parent()
            .ok_or_else(|| LoadError::InvalidPath(path.clone()))?
            .to_str()
            .ok_or_else(|| LoadError::InvalidPath(path.clone()))?;

        // Add `DT_RUNPATH` members to the search path
        file
            .dynamic_entry_strings(DynamicTag::Runpath)
            .map(|path| path.replace("$ORIGIN", &origin))
            .map(|path| path.split(":").map(|i| i.to_string()).collect::<Vec<_>>())
            .flatten()
            .filter(|i| !i.contains("/nix/store"))
            .map(PathBuf::from)
            .for_each(|rpath| self.search_path.push(rpath));

        self.objects.push(Object {
            path: path.clone(),
            base: Addr(0x400000),
            file,
            maps: vec![],
        });

        self.objects_by_path.insert(path, self.objects.len() - 1);
        Ok(self.objects.len() - 1)
    }

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

    pub fn object_path(&self, name: &str) -> Result<PathBuf, LoadError> {
        self.search_path
            .iter()
            .filter_map(|prefix| prefix.join(name).canonicalize().ok())
            .find(|path| path.exists())
            .ok_or_else(|| LoadError::NotFound(name.into()))
    }

    pub fn get_object(&mut self, name: &str) -> Result<GetResult, LoadError> {
        let path = self.object_path(name)?;
        self.objects_by_path
            .get(&path)
            .map(|&index| Ok(GetResult::Cached(index)))
            .unwrap_or_else(|| self.load_object(path).map(GetResult::Fresh))
    }

}

#[derive(CustomDebug)]
pub struct Object {
    pub path: PathBuf,
    pub base: Addr,

    #[debug(skip)]
    pub file: File,
    #[debug(skip)]
    pub maps: Vec<MemoryMap>,
}

#[derive(thiserror::Error, Debug)]
pub enum LoadError {
    #[error("ELF object not found: {0}")]
    NotFound(String),
    #[error("An invalid or unsupported path was encountered")]
    InvalidPath(PathBuf),
    #[error("I/O Error: {0}")]
    IO(#[from] std::io::Error),
    #[error("ELF object could not be parsed: {0}")]
    ParseError(PathBuf),
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
