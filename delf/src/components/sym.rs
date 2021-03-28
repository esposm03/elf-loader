//! Utilities related to parsing of the symbol table

use derive_try_from_primitive::TryFromPrimitive;
use nom::{
    combinator::map,
    number::complete::{le_u16, le_u32, le_u64, le_u8},
    sequence::tuple,
};

use crate::{impl_parse_for_bitenum, parse, Addr};

use super::section::SectionIndex;

/// The bind of a symbol (local, global, weak)
#[derive(Debug, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum SymBind {
    Local = 0,
    Global = 1,
    Weak = 2,
}

/// The type of a symbol
#[derive(Debug, TryFromPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum SymType {
    None = 0,
    Object = 1,
    Func = 2,
    Section = 3,
}

impl_parse_for_bitenum!(SymBind, 4_usize);
impl_parse_for_bitenum!(SymType, 4_usize);

/// A symbol
#[derive(Clone, Debug)]
pub struct Sym {
    pub name: Addr,
    pub bind: SymBind,
    pub r#type: SymType,
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
