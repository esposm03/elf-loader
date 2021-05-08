//! Parsing Elf files

pub mod components;
pub mod parse;
use components::{
    rela::Rela,
    section::{SectionHeader, SectionType},
    segment::{DynamicEntry, DynamicTag, ProgramHeader, SegmentContents, SegmentType},
    strtab::StrTab,
    sym::Sym,
};

use std::fmt;
use std::{convert::TryFrom, usize};

use derive_more::*;
use derive_try_from_primitive::TryFromPrimitive;

use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    combinator::{map, verify},
    error::context,
    multi::many_m_n,
    number::complete::{le_u16, le_u32, le_u64},
    sequence::tuple,
    Err::{Error, Failure},
    Offset,
};

/// An ELF file
#[derive(Debug)]
pub struct File {
    pub typ: ElfType,
    pub machine: Machine,
    pub entry_point: Addr,
    pub program_headers: Vec<ProgramHeader>,
    pub section_headers: Vec<SectionHeader>,
    pub full_content: Vec<u8>,

    pub shstrtab: StrTab<'static>,
    pub strtab: StrTab<'static>,
}

impl File {
    const MAGIC: &'static [u8] = &[0x7F, 0x45, 0x4C, 0x46];

    /// Parse an Elf file given some bytes
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        let full_input = i;

        // Parser taking a `u16`, but outputting it as a `usize`
        let u16_usize: _ = map(le_u16, |x| x as usize);

        let (i, _) = tuple((
            context("Magic", tag(Self::MAGIC)),
            context("Class not 64bit", tag(&[0x2])),
            context("Endianness not little", tag(&[0x1])),
            context("Version not 1", tag(&[0x1])),
            context("OS ABI not sysv/linux", alt((tag(&[0x0]), tag(&[0x3])))),
            context("Padding", take(8usize)),
        ))(i)?;

        let (i, typ) = ElfType::parse(i)?;
        let (i, machine) = Machine::parse(i)?;
        let (i, _) = context("Version (bis)", verify(le_u32, |&x| x == 1))(i)?;
        let (i, entry_point) = Addr::parse(i)?;

        // Section headers and program headers
        let (i, ph_offset) = Addr::parse(i)?;
        let (i, sh_offset) = Addr::parse(i)?;
        let (i, _flags) = le_u32(i)?;
        let (i, _hdr_size) = le_u16(i)?;
        let (i, ph_entsize) = u16_usize(i)?;
        let (i, ph_count) = u16_usize(i)?;
        let (i, sh_entsize) = u16_usize(i)?;
        let (i, sh_count) = u16_usize(i)?;
        let (i, sh_nidx) = u16_usize(i)?;

        let ph_slices = full_input[ph_offset.into()..].chunks(ph_entsize);
        let mut program_headers = Vec::new();
        for ph_slice in ph_slices.take(ph_count) {
            let (_, ph) = ProgramHeader::parse(full_input, ph_slice)?;
            program_headers.push(ph);
        }

        let sh_slices = (&full_input[sh_offset.into()..]).chunks(sh_entsize);
        let mut section_headers = Vec::new();
        for sh_slice in sh_slices.take(sh_count) {
            let (_, sh) = SectionHeader::parse(sh_slice)?;
            section_headers.push(sh);
        }

        let full_content = full_input.to_vec();

        let shstrtab = {
            let sh = &section_headers[sh_nidx];
            let data = full_content[sh.off.0 as usize..][..sh.size.0 as usize].to_vec();
            StrTab::new(data)
        };

        let strtab = {
            let sh = section_headers
                .iter()
                .find(|&sh| {
                    sh.r#type == SectionType::StrTab
                        && shstrtab.at(sh.name) == Some(".strtab".into())
                })
                .expect("Binary doesn't contain `.strtab` section");

            let data = full_content[sh.off.0 as usize..][..sh.size.0 as usize].to_vec();
            StrTab::new(data)
        };

        let res = Self {
            typ,
            machine,
            entry_point,
            program_headers,
            section_headers,
            full_content,
            shstrtab,
            strtab,
        };
        Ok((i, res))
    }

    /// Parse an Elf file, or report a (somewhat) user-friendly error
    pub fn parse_or_print_error(i: parse::Input) -> Option<Self> {
        match Self::parse(i) {
            Ok((_, file)) => Some(file),
            Err(Failure(err)) | Err(Error(err)) => {
                eprintln!("Parsing failed: ");
                for (input, err) in err.errors {
                    let offset = i.offset(input);
                    eprintln!("{:?} at position {:x}:", err, offset);
                    eprintln!("{:>08x}: {:?}", offset, HexDump(input));
                }
                None
            }
            Err(_) => panic!("unexpected nom error"),
        }
    }

    /// Return the program header whose segment contains the given address
    pub fn segment_at(&self, addr: Addr) -> Option<&ProgramHeader> {
        self.program_headers
            .iter()
            .filter(|ph| ph.typ == SegmentType::Load)
            .find(|ph| ph.mem_range().contains(&addr))
    }

    /// Take a slice of data from the given address until the end of its segment
    pub fn mem_slice_at(&self, addr: Addr) -> Option<&[u8]> {
        self.segment_at(addr)
            .map(|seg| &seg.data[(addr - seg.mem_range().start).into()..])
    }

    /// Take a slice of data from the given address until the end of its segment
    pub fn file_slice_at(&self, addr: Addr) -> Option<&[u8]> {
        self.full_content.get(addr.0 as usize..)
    }

    /// Read the `Rel` table
    pub fn read_rel(&self) -> Result<Vec<Rela>, ReadRelaError> {
        let sh = self.section_with_type(SectionType::Rel).ok_or(ReadRelaError::RelSegmentNotFound)?;

        let i = &self.full_content[sh.off.0 as usize..][..sh.size.0 as usize];

        let n: usize = i.len() / 16; // A `Rel` occupies 16 bytes
        match nom::multi::many_m_n(n, n, Rela::parse_rel)(i) {
            Ok((_, rela_entries)) => Ok(rela_entries),
            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                Err(ReadRelaError::ParsingError(format!("{:?}", err)))
            }
            _ => unreachable!(),
        }
    }

    /// Read the `Rela` table
    pub fn read_rela(&self) -> Result<Vec<Rela>, ReadRelaError> {
        let sh = self.section_with_type(SectionType::Rela).ok_or(ReadRelaError::RelaSegmentNotFound)?;

        let i = &self.full_content[sh.off.0 as usize..][..sh.size.0 as usize];

        let n: usize = i.len() / 24; // A `Rela` occupies 24 bytes
        match nom::multi::many_m_n(n, n, Rela::parse)(i) {
            Ok((_, rela_entries)) => Ok(rela_entries),
            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                Err(ReadRelaError::ParsingError(format!("{:?}", err)))
            }
            _ => unreachable!(),
        }
    }

    /// Read the relocation table
    pub fn read_rela_entries(&self) -> Result<Vec<Rela>, ReadRelaError> {
        let mut res = self.read_rel().unwrap_or(vec![]);
        res.extend(self.read_rela()?);
        Ok(res)
    }

    /// Return the first program header whose segment has the specified type
    pub fn segment_of_type(&self, typ: SegmentType) -> Option<&ProgramHeader> {
        self.program_headers.iter().find(|ph| ph.typ == typ)
    }

    /// Get the dynamic table of this ELF file
    pub fn dynamic_table(&self) -> Option<&[DynamicEntry]> {
        match self.segment_of_type(SegmentType::Dynamic) {
            Some(ProgramHeader {
                contents: SegmentContents::Dynamic(entries),
                ..
            }) => Some(entries),
            _ => None,
        }
    }

    /// Return an iterator over the addresses dynamic entries
    pub fn dynamic_entries(&self, tag: DynamicTag) -> impl Iterator<Item = Addr> + '_ {
        self.dynamic_table()
            .unwrap_or_default()
            .iter()
            .filter(move |e| e.tag == tag)
            .map(|e| e.addr)
    }

    /// Return the dynamic entry with the given type
    fn dynamic_entry(&self, tag: DynamicTag) -> Option<Addr> {
        self.dynamic_entries(tag).next()
    }

    /// Return the dynamic entry with the given type
    ///
    /// NOTE: This silently drops any string it can't read
    pub fn dynamic_entry_strings(&self, tag: DynamicTag) -> impl Iterator<Item = String> + '_ {
        self.dynamic_entries(tag)
            .filter_map(move |addr| self.strtab.at(addr))
    }

    /// Return the section starting at the given offset
    pub fn section_starting_at(&self, addr: Addr) -> Option<&SectionHeader> {
        self.section_headers.iter().find(|sh| sh.addr == addr)
    }

    pub fn section_with_type(&self, typ: SectionType) -> Option<&SectionHeader> {
        self.section_headers.iter().find(|&sh| sh.r#type == typ)
    }

    /// Return a `Vec` of the symbols defined in this file
    pub fn read_syms(&self) -> Result<Vec<Sym>, ReadSymsError> {
        use ReadSymsError::ParsingError;

        let section = self.section_with_type(SectionType::SymTab).unwrap();
        let i = self.file_slice_at(section.off).unwrap();
        let n = (section.size.0 / section.entsize.0) as usize;

        match many_m_n(n, n, Sym::parse)(i) {
            Ok((_, syms)) => Ok(syms),
            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                Err(ParsingError(format!("{:?}", err)))
            }
            // we don't use any "streaming" parsers, so.
            _ => unreachable!(),
        }
    }

    pub fn get_dynamic_entry(&self, tag: DynamicTag) -> Result<Addr, GetDynamicEntryError> {
        self.dynamic_entry(tag)
            .ok_or(GetDynamicEntryError::NotFound(tag))
    }
}

/// An error that occurred while trying to read relocations
#[derive(thiserror::Error, Debug)]
pub enum ReadRelaError {
    #[error("{0}")]
    DynamicEntryNotFound(#[from] GetDynamicEntryError),
    #[error("Object file does not contain a `SHT_RELA` section")]
    RelaSegmentNotFound,
    #[error("Object file does not contain a `SHT_REL` section")]
    RelSegmentNotFound,
    #[error("Parsing error: {0}")]
    ParsingError(String),
}

#[derive(thiserror::Error, Debug)]
pub enum GetDynamicEntryError {
    #[error("Dynamic entry {0:?} not found")]
    NotFound(DynamicTag),
}

/// An error that occurred while trying to read strings from the file
#[derive(thiserror::Error, Debug)]
pub enum GetStringError {
    #[error("StrTab dynamic entry not found")]
    StrTabNotFound,
    #[error("StrTab segment not found")]
    StrTabSegmentNotFound,
    #[error("String not found")]
    StringNotFound,
}

/// An error that occurred while trying to read symbols
#[derive(thiserror::Error, Debug)]
pub enum ReadSymsError {
    #[error("{0:?}")]
    DynamicEntryNotFound(#[from] GetDynamicEntryError),
    #[error("SymTab section not found")]
    SymTabSectionNotFound,
    #[error("SymTab segment not found")]
    SymTabSegmentNotFound,
    #[error("Parsing error: {0}")]
    ParsingError(String),
}

/// The type of an ELF file
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
pub enum ElfType {
    None = 0x0,
    Rel = 0x1,
    Exec = 0x2,
    Dyn = 0x3,
    Core = 0x4,
}

/// The machine an ELF file targets
#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
pub enum Machine {
    X86 = 0x03,
    X86_64 = 0x3E,
}

impl_parse_for_enum!(ElfType, le_u16);
impl_parse_for_enum!(Machine, le_u16);

/// An address in memory
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Add, Sub)]
pub struct Addr(pub u64);

impl Addr {
    /// Parse an address
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        map(le_u64, From::from)(i)
    }

    /// # Safety
    ///
    /// This can create dangling pointers and all sorts of eldritch
    /// errors.
    pub unsafe fn as_ptr<T>(&self) -> *const T {
        std::mem::transmute(self.0 as usize)
    }

    /// # Safety
    ///
    /// This can create dangling pointers and all sorts of eldritch
    /// errors.
    pub unsafe fn as_mut_ptr<T>(&self) -> *mut T {
        std::mem::transmute(self.0 as usize)
    }

    /// # Safety
    ///
    /// This can create invalid slices
    pub unsafe fn as_slice<T>(&self, len: usize) -> &[T] {
        std::slice::from_raw_parts(self.as_ptr(), len)
    }

    /// # Safety
    ///
    /// This can create invalid or aliased mutable slices
    pub unsafe fn as_mut_slice<T>(&mut self, len: usize) -> &mut [T] {
        std::slice::from_raw_parts_mut(self.as_mut_ptr(), len)
    }

    /// # Safety
    ///
    /// This can write anywhere
    pub unsafe fn write(&self, src: &[u8]) {
        std::ptr::copy_nonoverlapping(src.as_ptr(), self.as_mut_ptr(), src.len());
    }

    /// # Safety
    ///
    /// This can write anywhere
    pub unsafe fn set<T>(&self, src: T) {
        *self.as_mut_ptr() = src;
    }
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:016x}", self.0)
    }
}
impl fmt::Display for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}
impl Into<u64> for Addr {
    fn into(self) -> u64 {
        self.0
    }
}
impl Into<usize> for Addr {
    fn into(self) -> usize {
        self.0 as usize
    }
}
impl From<u64> for Addr {
    fn from(x: u64) -> Self {
        Self(x)
    }
}

#[cfg(test)]
mod tests {
    use super::Machine;
    use std::convert::TryFrom;

    #[test]
    fn try_enums() {
        assert_eq!(Machine::X86_64 as u16, 0x3E);
        assert_eq!(Machine::try_from(0x3E), Ok(Machine::X86_64));
        assert_eq!(Machine::try_from(0xFA), Err(0xFA));
    }

    #[test]
    fn try_bitflag() {
        use crate::components::segment::SegmentFlag;
        use enumflags2::BitFlags;

        // this is a value we could've read straight from an ELF file
        let flags_integer: u32 = 6;
        // this is how we parse it. in practice, it's less verbose,
        // because of type inference.
        let flags = BitFlags::<SegmentFlag>::from_bits(flags_integer).unwrap();
        assert_eq!(flags, SegmentFlag::Read | SegmentFlag::Write);
        assert_eq!(flags.bits(), flags_integer);

        // this does not correspond to any flags
        assert!(BitFlags::<SegmentFlag>::from_bits(1992).is_err());
    }
}

pub struct HexDump<'a>(&'a [u8]);

impl<'a> fmt::Debug for HexDump<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &x in self.0.iter().take(20) {
            write!(f, "{:02x} ", x)?;
        }
        Ok(())
    }
}
