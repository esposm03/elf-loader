//! Utilities related to parsing of relocations

use std::convert::TryFrom;

use derive_try_from_primitive::TryFromPrimitive;
use nom::{combinator::map, number::complete::le_u32, sequence::tuple};

use crate::{Addr, impl_parse_for_enum, parse};

/// A relocation
#[derive(Debug)]
pub struct Rela {
    pub offset: Addr,
    pub r#type: RelocationType,
    pub sym: u32,
    pub addend: Addr,
}

impl Rela {
    pub const SIZE: usize = 24;

    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        map(
            tuple((Addr::parse, RelocationType::parse, le_u32, Addr::parse)),
            |(offset, r#type, sym, addend)| Rela {
                offset,
                r#type,
                sym,
                addend,
            },
        )(i)
    }
}

/// A relocation
pub struct Rel {
    pub offset: Addr,
    pub r#type: RelocationType,
    pub sym: u32,
}

impl Rel {
    pub const SIZE: usize = 16;

    pub fn parse(i: parse::Input) -> parse::Result<Self> {
        map(
            tuple((Addr::parse, RelocationType::parse, le_u32)),
            |(offset, r#type, sym)| Rel {
                offset,
                r#type,
                sym,
            },
        )(i)
    }
}

/// The type of a relocation
#[repr(u32)]
#[derive(Debug, TryFromPrimitive, Clone, Copy, PartialEq, Eq)]
pub enum RelocationType {
    _64 = 1,
    Copy = 5,
    GlobDat = 6,
    JumpSlot = 7,
    Relative = 8,
    IRelative = 37,
}
impl_parse_for_enum!(RelocationType, le_u32);
