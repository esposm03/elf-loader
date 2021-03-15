use std::convert::TryFrom;

use derive_try_from_primitive::TryFromPrimitive;
use nom::{branch::alt, combinator::map, number::complete::le_u32, sequence::tuple};

use crate::{impl_parse_for_enum, Addr, Input, ParseResult};

#[derive(Debug)]
pub struct Rela {
    pub offset: Addr,
    pub r#type: RelType,
    pub sym: u32,
    pub addend: Addr,
}

impl Rela {
    pub fn parse(i: Input) -> ParseResult<Self> {
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
pub enum KnownRelType {
    _64 = 1,
    Copy = 5,
    GlobDat = 6,
    JumpSlot = 7,
    Relative = 8,
}
impl_parse_for_enum!(KnownRelType, le_u32);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelType {
    Known(KnownRelType),
    Unknown(u32),
}

impl RelType {
    pub fn parse(i: Input) -> ParseResult<Self> {
        alt((
            map(KnownRelType::parse, Self::Known),
            map(le_u32, Self::Unknown),
        ))(i)
    }
}
