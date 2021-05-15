//! Parsing Elf files

pub mod components;
pub mod errors;
pub mod parse;
use components::{
    dynamic::DynamicSection,
    rela::RelaTable,
    section::{SectionHeader, SectionType},
    segment::ProgramHeader,
    strtab::StrTab,
    sym::SymTab,
};

use std::fmt;
use std::usize;

use derive_more::*;
use derive_try_from_primitive::TryFromPrimitive;

use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    combinator::{map, verify},
    error::context,
    number::complete::{le_u16, le_u32, le_u64},
    sequence::tuple,
    Err::{Error, Failure},
    Offset,
};

/// An ELF file
#[derive(Debug, Clone)]
pub struct ParsedElf<'a> {
    pub elf_header: ElfHeader,
    pub program_headers: Vec<ProgramHeader<'a>>,
    pub section_headers: Vec<SectionHeader<'a>>,
    pub full_content: &'a [u8],
}

impl<'a> ParsedElf<'a> {
    /// Parse an Elf file given some bytes
    pub fn parse(input: parse::Input<'a>) -> parse::Result<Self> {
        let (i, (elf_header, program_headers, section_headers)) = ElfHeader::parse(input)?;

        let res = Self {
            elf_header,
            program_headers,
            section_headers,
            full_content: input,
        };
        Ok((i, res))
    }

    /// Parse an Elf file, or report a (somewhat) user-friendly error
    pub fn parse_or_print_error(i: &'a [u8]) -> Option<Self> {
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

    pub fn section_with_type(&self, typ: SectionType) -> Option<usize> {
        self.section_headers
            .iter()
            .enumerate()
            .find(|(_, sh)| sh.typ == typ)
            .map(|(i, _)| i)
    }

    pub fn strtab(&self, index: usize) -> Option<StrTab> {
        if self.section_headers[index].typ == SectionType::StrTab {
            Some(StrTab(&self.section_headers[index]))
        } else {
            None
        }
    }

    pub fn symtab(&self, index: usize) -> Option<SymTab> {
        if let SectionType::SymTab | SectionType::DynSym = self.section_headers[index].typ {
            let symtab = &self.section_headers[index];
            let strtab = self
                .strtab(self.section_headers[index].link as usize)
                .unwrap();
            Some(SymTab(symtab, strtab))
        } else {
            None
        }
    }

    pub fn rela(&self, index: usize) -> Option<RelaTable> {
        let sh = &self.section_headers[index];
        if let SectionType::Rela = sh.typ {
            Some(RelaTable(
                &self.section_headers[index],
                self.symtab(sh.link as usize)?,
            ))
        } else {
            None
        }
    }

    pub fn dynamic_section(&self) -> Option<DynamicSection> {
        self.section_headers
            .iter()
            .find(|sh| sh.typ == SectionType::Dynamic)
            .map(|sh| DynamicSection(sh, self.strtab(sh.link as usize).unwrap()))
    }
}

/// The ELF header
#[derive(Debug, Clone)]
pub struct ElfHeader {
    pub typ: ElfType,
    pub machine: Machine,
    pub entry_point: Addr,
    pub ph_offset: Addr,
    pub sh_offset: Addr,
    pub flags: u32,
    pub hdr_size: u16,
    pub ph_entsize: usize,
    pub ph_count: usize,
    pub sh_entsize: usize,
    pub sh_count: usize,
    pub sh_nidx: usize,
}

impl ElfHeader {
    const MAGIC: &'static [u8] = &[0x7F, 0x45, 0x4C, 0x46];

    pub fn parse(i: parse::Input) -> parse::Result<(Self, Vec<ProgramHeader>, Vec<SectionHeader>)> {
        let full_input = i;

        // Parser taking a `u16`, but outputting it as a `usize`
        let u16_usize = map(le_u16, |x| x as usize);

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
        let (i, flags) = le_u32(i)?;
        let (i, hdr_size) = le_u16(i)?;
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
            let (_, sh) = SectionHeader::parse(full_input, sh_slice)?;
            section_headers.push(sh);
        }

        let file_header = Self {
            typ,
            machine,
            entry_point,
            ph_offset,
            sh_offset,
            flags,
            hdr_size,
            ph_entsize,
            ph_count,
            sh_entsize,
            sh_count,
            sh_nidx,
        };
        Ok((i, (file_header, program_headers, section_headers)))
    }
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
impl From<Addr> for u64 {
    fn from(a: Addr) -> Self {
        a.0
    }
}
impl From<Addr> for usize {
    fn from(a: Addr) -> Self {
        a.0 as usize
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
