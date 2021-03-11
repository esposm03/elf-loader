pub mod components;
use components::segment::{DynamicEntry, DynamicTag, SegmentContents, SegmentType};

use std::convert::TryFrom;
use std::{fmt, ops::Range};

use derive_more::*;
use derive_try_from_primitive::TryFromPrimitive;
use enumflags2::{bitflags, BitFlags};
use nom::{
    Err::{Error, Failure},
    Offset,
};
use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    combinator::{map, verify},
    error::context,
    multi::many_m_n,
    number::complete::{le_u16, le_u32, le_u64},
    sequence::tuple,
};

pub type Input<'a> = &'a [u8];
pub type ParseResult<'a, O> = nom::IResult<Input<'a>, O, nom::error::VerboseError<Input<'a>>>;

#[macro_export]
macro_rules! impl_parse_for_enum {
    ($type: ident, $number_parser: ident) => {
        impl $type {
            pub fn parse(i: Input) -> ParseResult<Self> {
                use nom::{
                    combinator::map_res,
                    error::{context, ErrorKind},
                    number::complete::$number_parser,
                };
                let parser = map_res($number_parser, |x| {
                    Self::try_from(x).map_err(|_| ErrorKind::Alt)
                });
                context(stringify!($type), parser)(i)
            }
        }
    };
}

#[macro_export]
macro_rules! impl_parse_for_enumflags {
    ($type: ident, $number_parser: ident) => {
        impl $type {
            pub fn parse(i: Input) -> ParseResult<enumflags2::BitFlags<Self>> {
                use nom::{
                    combinator::map_res,
                    error::{context, ErrorKind},
                    number::complete::$number_parser,
                };
                let parser = map_res($number_parser, |x| {
                    enumflags2::BitFlags::<Self>::from_bits(x).map_err(|_| ErrorKind::Alt)
                });
                context(stringify!($type), parser)(i)
            }
        }
    };
}

#[derive(Debug)]
pub struct File {
    pub typ: ElfType,
    pub machine: Machine,
    pub entry_point: Addr,
    pub program_headers: Vec<ProgramHeader>,
}

impl File {
    const MAGIC: &'static [u8] = &[0x7F, 0x45, 0x4C, 0x46];

    #[allow(unused_variables)]
    pub fn parse(i: Input) -> ParseResult<Self> {
        let full_input = i;

        // Parser taking a `u16`, but outputting it as a `usize`
        let mut u16_usize: _ = map(le_u16, |x| x as usize);

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

        let res = Self {
            typ,
            machine,
            entry_point,
            program_headers,
        };
        Ok((i, res))
    }

    pub fn parse_or_print_error(i: Input) -> Option<Self> {
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
}

pub struct ProgramHeader {
    pub r#type: SegmentType,
    pub flags: BitFlags<SegmentFlag>,
    pub offset: Addr,
    pub vaddr: Addr,
    pub paddr: Addr,
    pub filesz: Addr,
    pub memsz: Addr,
    pub align: Addr,
    pub data: Vec<u8>,

    pub contents: SegmentContents,
}

impl ProgramHeader {
    pub fn file_range(&self) -> Range<Addr> {
        self.offset..self.offset + self.filesz
    }
    pub fn mem_range(&self) -> Range<Addr> {
        self.vaddr..self.vaddr + self.memsz
    }

    fn parse<'a>(full_input: Input<'a>, i: Input<'a>) -> ParseResult<'a, Self> {
        let (i, r#type) = SegmentType::parse(i)?;
        let (i, flags): _ = SegmentFlag::parse(i)?;

        let (i, offset) = Addr::parse(i)?;
        let (i, vaddr) = Addr::parse(i)?;
        let (i, paddr) = Addr::parse(i)?;
        let (i, filesz) = Addr::parse(i)?;
        let (i, memsz) = Addr::parse(i)?;
        let (i, align) = Addr::parse(i)?;

        let slice = &full_input[offset.into()..][..filesz.into()];
        let (_, contents) = match r#type {
            SegmentType::Dynamic => {
                let entry_size: usize = 16;
                let n = slice.len()/entry_size;
                map(
                    many_m_n(n, n, DynamicEntry::parse),
                    SegmentContents::Dynamic,
                )(slice)?
            }
            _ => (slice, SegmentContents::Unknown),
        };

        let res = Self {
            r#type,
            flags,
            offset,
            vaddr,
            paddr,
            filesz,
            memsz,
            align,
            data: slice.to_vec(),
            contents,
        };
        Ok((i, res))
    }
}

impl fmt::Debug for ProgramHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "file {:?} | mem {:?} | align {:?} | {} {:?}",
            self.file_range(),
            self.mem_range(),
            self.align,
            &[
                (SegmentFlag::Read, "R"),
                (SegmentFlag::Write, "W"),
                (SegmentFlag::Execute, "X")
            ]
            .iter()
            .map(|&(flag, letter)| {
                if self.flags.contains(flag) {
                    letter
                } else {
                    "."
                }
            })
            .collect::<Vec<_>>()
            .join(""),
            self.r#type,
        )
    }
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
pub enum ElfType {
    None = 0x0,
    Rel = 0x1,
    Exec = 0x2,
    Dyn = 0x3,
    Core = 0x4,
}

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
pub enum Machine {
    X86 = 0x03,
    X86_64 = 0x3E,
}


#[bitflags]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentFlag {
    Execute = 0x1,
    Write = 0x2,
    Read = 0x4,
}

impl_parse_for_enum!(ElfType, le_u16);
impl_parse_for_enum!(Machine, le_u16);
impl_parse_for_enum!(DynamicTag, le_u64);
impl_parse_for_enum!(SegmentType, le_u32);

impl_parse_for_enumflags!(SegmentFlag, le_u32);

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Add, Sub)]
pub struct Addr(pub u64);
impl Addr {
    pub fn parse(i: Input) -> ParseResult<Self> {
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
        use super::SegmentFlag;
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
