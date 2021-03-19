//! Parsing Elf files

pub mod components;
pub mod parse;
use components::{
    rela::Rela,
    segment::{DynamicEntry, DynamicTag, ProgramHeader, SegmentContents, SegmentType},
};

use std::convert::TryFrom;
use std::fmt;

use derive_more::*;
use derive_try_from_primitive::TryFromPrimitive;

use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    combinator::{map, verify},
    error::context,
    multi::many_m_n,
    number::complete::{le_u16, le_u32, le_u64, le_u8},
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
        let (i, _sh_nidx) = u16_usize(i)?;

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

        let res = Self {
            typ,
            machine,
            entry_point,
            program_headers,
            section_headers,
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
            .filter(|ph| ph.r#type == SegmentType::Load)
            .find(|ph| ph.mem_range().contains(&addr))
    }

    /// Take a slice of data from the given address until the end of its segment
    pub fn slice_at(&self, addr: Addr) -> Option<&[u8]> {
        self.segment_at(addr)
            .map(|seg| &seg.data[(addr - seg.mem_range().start).into()..])
    }

    /// Get the string at the given offset into the string table
    pub fn get_string(&self, offset: Addr) -> Result<String, GetStringError> {
        use DynamicTag as DT;
        use GetStringError as E;

        let addr = self.dynamic_entry(DT::StrTab).ok_or(E::StrTabNotFound)?;
        let slice = self
            .slice_at(addr + offset)
            .ok_or(E::StrTabSegmentNotFound)?;
        let string_slice = slice
            .split(|&c| c == 0x00)
            .next()
            .ok_or(E::StringNotFound)?;

        Ok(String::from_utf8_lossy(string_slice).into())
    }

    /// Return the first program header whose segment has the specified type
    pub fn segment_of_type(&self, r#type: SegmentType) -> Option<&ProgramHeader> {
        self.program_headers.iter().find(|ph| ph.r#type == r#type)
    }

    /// Read the relocation table
    pub fn read_rela_entries(&self) -> Result<Vec<Rela>, ReadRelaError> {
        use DynamicTag as DT;
        use ReadRelaError as E;

        let addr = self.dynamic_entry(DT::Rela).ok_or(E::RelaNotFound)?;
        let len = self.dynamic_entry(DT::RelaSz).ok_or(E::RelaSzNotFound)?;
        let ent = self.dynamic_entry(DT::RelaEnt).ok_or(E::RelaEntNotFound)?;

        let i = self.slice_at(addr).ok_or(E::RelaSegmentNotFound)?;
        let i = &i[..len.into()];
        let n = (len.0 / ent.0) as usize;

        match many_m_n(n, n, Rela::parse)(i) {
            Ok((_, rela_entries)) => Ok(rela_entries),
            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                let e = &err.errors[0];
                let (_input, error_kind) = e;
                Err(E::ParsingError(error_kind.clone()))
            }
            // we don't use any "streaming" parsers, so `nom::Err::Incomplete` seems unlikely
            _ => unreachable!(),
        }
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
    pub fn dynamic_entry(&self, tag: DynamicTag) -> Option<Addr> {
        self.dynamic_entries(tag).next()
    }

    /// Return the dynamic entry with the given type
    ///
    /// NOTE: This silently drops any string it can't read
    pub fn dynamic_entry_strings(&self, tag: DynamicTag) -> impl Iterator<Item = String> + '_ {
        self.dynamic_entries(tag)
            .filter_map(move |addr| self.get_string(addr).ok())
    }

    /// Return the section starting at the given offset
    pub fn section_starting_at(&self, addr: Addr) -> Option<&SectionHeader> {
        self.section_headers.iter().find(|sh| sh.addr == addr)
    }

    /// Return a `Vec` of the symbols defined in this file
    pub fn read_syms(&self) -> Result<Vec<Sym>, ReadSymsError> {
        use DynamicTag as DT;
        use ReadSymsError as E;

        let addr = self.dynamic_entry(DT::SymTab).ok_or(E::SymTabNotFound)?;
        let section = self
            .section_starting_at(addr)
            .ok_or(E::SymTabSectionNotFound)?;

        let i = self.slice_at(addr).ok_or(E::SymTabSegmentNotFound)?;
        let n = (section.size.0 / section.entsize.0) as usize;

        match many_m_n(n, n, Sym::parse)(i) {
            Ok((_, syms)) => Ok(syms),
            Err(nom::Err::Failure(err)) | Err(nom::Err::Error(err)) => {
                let e = &err.errors[0];
                let (_input, error_kind) = e;
                Err(E::ParsingError(error_kind.clone()))
            }
            // we don't use any "streaming" parsers, so.
            _ => unreachable!(),
        }
    }
}

#[derive(Debug, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum SymBind {
    Local = 0,
    Global = 1,
    Weak = 2,
}

#[derive(Debug, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum SymType {
    None = 0,
    Object = 1,
    Func = 2,
    Section = 3,
}

impl SymBind {
    pub fn parse(i: parse::BitInput) -> parse::BitResult<Option<Self>> {
        use nom::bits::complete::take;
        map(take(4_usize), |i: u8| Self::try_from(i).ok())(i)
    }
}

impl SymType {
    pub fn parse(i: parse::BitInput) -> parse::BitResult<Option<Self>> {
        use nom::bits::complete::take;
        map(take(4_usize), |i: u8| Self::try_from(i).ok())(i)
    }
}

#[derive(Clone, Copy)]
pub struct SectionIndex(pub u16);

impl SectionIndex {
    pub fn is_undef(&self) -> bool {
        self.0 == 0
    }

    pub fn is_special(&self) -> bool {
        self.0 >= 0xff00
    }

    pub fn get(&self) -> Option<usize> {
        if self.is_undef() || self.is_special() {
            None
        } else {
            Some(self.0 as usize)
        }
    }
}

impl fmt::Debug for SectionIndex {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_special() {
            write!(f, "Special({:04x})", self.0)
        } else if self.is_undef() {
            write!(f, "Undef")
        } else {
            write!(f, "{}", self.0)
        }
    }
}

#[derive(Debug)]
pub struct Sym {
    pub name: Addr,
    pub bind: Option<SymBind>,
    pub r#type: Option<SymType>,
    pub shndx: SectionIndex,
    pub value: Addr,
    pub size: u64,
}

impl Sym {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        use nom::bits::bits;

        let (i, (name, (bind, r#type), _reserved, shndx, value, size)) = tuple((
            map(le_u32, |x| Addr(x as u64)),
            bits(tuple((SymBind::parse, SymType::parse))),
            le_u8,
            map(le_u16, SectionIndex),
            Addr::parse,
            le_u64,
        ))(i)?;
        let res = Self {
            name,
            bind,
            r#type,
            shndx,
            value,
            size,
        };
        Ok((i, res))
    }
}

#[derive(Debug)]
pub struct SectionHeader {
    pub name: Addr,
    pub r#type: u32,
    pub flags: u64,
    pub addr: Addr,
    pub off: Addr,
    pub size: Addr,
    pub link: u32,
    pub info: u32,
    pub addralign: Addr,
    pub entsize: Addr,
}

impl SectionHeader {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        let (i, (name, r#type, flags, addr, off, size, link, info, addralign, entsize)) =
            tuple((
                map(le_u32, |x| Addr(x as u64)),
                le_u32,
                le_u64,
                Addr::parse,
                Addr::parse,
                Addr::parse,
                le_u32,
                le_u32,
                Addr::parse,
                Addr::parse,
            ))(i)?;
        let res = Self {
            name,
            r#type,
            flags,
            addr,
            off,
            size,
            link,
            info,
            addralign,
            entsize,
        };
        Ok((i, res))
    }
}

/// An error that occurred while trying to read relocations
#[derive(thiserror::Error, Debug)]
pub enum ReadRelaError {
    #[error("Rela dynamic entry not found")]
    RelaNotFound,
    #[error("RelaSz dynamic entry not found")]
    RelaSzNotFound,
    #[error("RelaEnt dynamic entry not found")]
    RelaEntNotFound,
    #[error("RelaSeg dynamic entry not found")]
    RelaSegNotFound,
    #[error("Rela segment not found")]
    RelaSegmentNotFound,
    #[error("Parsing error")]
    ParsingError(parse::ErrorKind),
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
    #[error("SymTab dynamic entry not found")]
    SymTabNotFound,
    #[error("SymTab section not found")]
    SymTabSectionNotFound,
    #[error("SymTab segment not found")]
    SymTabSegmentNotFound,
    #[error("Parsing error")]
    ParsingError(parse::ErrorKind),
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
}

impl fmt::Debug for Addr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:08x}", self.0)
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
