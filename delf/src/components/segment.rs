use crate::{Addr, Input, ParseResult, impl_parse_for_enum};
use derive_try_from_primitive::TryFromPrimitive;
use std::convert::TryFrom;

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
pub enum SegmentContents {
    /// The segment contains an array of dynamic entries
    Dynamic(Vec<DynamicEntry>),
    /// The segment contains something that is still not handled
    Unknown,
}

/// A dynamic entry 
#[derive(Debug)]
pub struct DynamicEntry {
    pub tag: DynamicTag,
    pub addr: Addr,
}

impl DynamicEntry {
    pub fn parse(i: Input) -> ParseResult<Self> {
        let (i, tag) = DynamicTag::parse(i)?;
        let (i, addr) = Addr::parse(i)?;
        Ok((i, Self { addr, tag }))
    }
}

/// The tag of a dynamic entry
#[repr(u64)]
#[derive(Debug, TryFromPrimitive, PartialEq, Eq)]
pub enum DynamicTag {
    Null = 0,
    Needed = 1,
    PltRelSz = 2,
    PltGot = 3,
    Hash = 4,
    StrTab = 5,
    SymTab = 6,
    Rela = 7,
    RelaSz = 8,
    RelaEnt = 9,
    StrSz = 10,
    SymEnt = 11,
    Init = 12,
    Fini = 13,
    SoName = 14,
    RPath = 15,
    Symbolic = 16,
    Rel = 17,
    RelSz = 18,
    RelEnt = 19,
    PltRel = 20,
    Debug = 21,
    TextRel = 22,
    JmpRel = 23,
    BindNow = 24,
    InitArray = 25,
    FiniArray = 26,
    InitArraySz = 27,
    FiniArraySz = 28,
    Runpath = 29,
    Flags = 30,
    GnuHash = 0x6ffffef5,
    VerSym = 0x6ffffff0,
    RelaCount = 0x6ffffff9,
    Flags1 = 0x6ffffffb,
    VerDef = 0x6ffffffc,
    VerDefNum = 0x6ffffffd,
    VerNeed = 0x6ffffffe,
    VerNeedNum = 0x6fffffff,
}

#[derive(Debug)]
pub struct Rela {
    pub offset: Addr,
    pub r#type: RelType,
    pub sym: u32,
    pub addend: Addr,
}

impl Rela {
    pub fn parse(i: Input) -> ParseResult<Self> {
        use nom::{combinator::map, number::complete::le_u32, sequence::tuple};
        map(
            tuple((Addr::parse, RelType::parse, le_u32, Addr::parse)),
            |(offset, r#type, sym, addend)| Rela {
                offset,
                r#type,
                sym,
                addend,
            },
        )(i)
    }
}

#[repr(u32)]
#[derive(Debug, TryFromPrimitive, Clone, Copy, PartialEq, Eq)]
pub enum RelType {
    GlobDat = 6,
    JumpSlot = 7,
    Relative = 8,
}

impl_parse_for_enum!(RelType, le_u32);
