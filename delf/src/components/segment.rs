//! Utilities related to parsing of program headers

use std::{fmt, ops::Range};

use crate::{impl_parse_for_enum, impl_parse_for_enumflags, parse, Addr};
use derive_try_from_primitive::TryFromPrimitive;
use enumflags2::{bitflags, BitFlags};

use super::dynamic::DynamicEntry;

/// A program header
///
/// The program headers are parts of an ELF file useful when executing it.
/// In a file, there are generally many, each of them referring to a "segment"
/// (some data in the file and, if the segment is `Load`, in memory)
pub struct ProgramHeader<'a> {
    pub typ: SegmentType,
    pub flags: BitFlags<SegmentFlag>,
    pub offset: Addr,
    pub vaddr: Addr,
    pub paddr: Addr,
    pub filesz: Addr,
    pub memsz: Addr,
    pub align: Addr,
    pub data: Vec<u8>,

    pub contents: SegmentContents<'a>,
}

impl ProgramHeader<'_> {
    /// Get the range where segment data is located in the file
    pub fn file_range(&self) -> Range<Addr> {
        self.offset..self.offset + self.filesz
    }

    /// Get the range where segment data is located in memory, when loaded
    pub fn mem_range(&self) -> Range<Addr> {
        self.vaddr..self.vaddr + self.memsz
    }

    /// Parse the program header
    pub fn parse<'a>(full_input: parse::Input<'a>, i: parse::Input<'a>) -> parse::Result<'a, Self> {
        let (i, r#type) = SegmentType::parse(i)?;
        let (i, flags): _ = SegmentFlag::parse(i)?;

        let (i, offset) = Addr::parse(i)?;
        let (i, vaddr) = Addr::parse(i)?;
        let (i, paddr) = Addr::parse(i)?;
        let (i, filesz) = Addr::parse(i)?;
        let (i, memsz) = Addr::parse(i)?;
        let (i, align) = Addr::parse(i)?;

        let slice = &full_input[offset.into()..][..filesz.into()];
        // let (_, contents) = match r#type {
        //     SegmentType::Dynamic => map(
        //         many_till(
        //             DynamicEntry::parse,
        //             verify(DynamicEntry::parse, |e| e.tag == DynamicTag::Null),
        //         ),
        //         |(entries, _last)| SegmentContents::Dynamic(entries),
        //     )(slice)?,
        //     _ => (slice, SegmentContents::Unknown),
        // };
        let contents = SegmentContents::Unknown;

        let res = Self {
            typ: r#type,
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

impl fmt::Debug for ProgramHeader<'_> {
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
            self.typ,
        )
    }
}

/// The flags of a segment
#[bitflags]
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentFlag {
    Execute = 0x1,
    Write = 0x2,
    Read = 0x4,
}

impl_parse_for_enumflags!(SegmentFlag, le_u32);

/// The type of a segment
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, TryFromPrimitive)]
pub enum SegmentType {
    Null = 0x0,
    Load = 0x1,
    Dynamic = 0x2,
    Interp = 0x3,
    Note = 0x4,
    ShLib = 0x5,
    PHdr = 0x6,
    TLS = 0x7,
    LoOS = 0x6000_0000,
    HiOS = 0x6FFF_FFFF,
    LoProc = 0x7000_0000,
    HiProc = 0x7FFF_FFFF,
    GnuEhFrame = 0x6474_E550,
    GnuStack = 0x6474_E551,
    GnuRelRo = 0x6474_E552,
    GnuProperty = 0x6474_E553,
}

/// The contents of a segment
pub enum SegmentContents<'a> {
    /// The segment contains an array of dynamic entries
    Dynamic(Vec<DynamicEntry<'a>>),
    /// The segment contains something that is still not handled
    Unknown,
}

impl_parse_for_enum!(SegmentType, le_u32);
