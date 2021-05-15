//! Utilities related to parsing of the symbol table

use std::borrow::Cow;

use derive_try_from_primitive::TryFromPrimitive;
use nom::{
    combinator::map,
    number::complete::{le_u16, le_u32, le_u64, le_u8},
    sequence::tuple,
};

use crate::{impl_parse_for_bitenum, parse, Addr};

use super::{
    section::{SectionHeader, SectionIndex},
    strtab::StrTab,
};

pub struct SymTab<'a>(pub &'a SectionHeader<'a>, pub StrTab<'a>);

impl<'a> SymTab<'a> {
    pub fn sym_index(&self, index: usize) -> Option<Sym> {
        let data = self.0.data_at(Addr((24 * index) as _))?;
        let sym = Sym::parse(&self.1, data).ok()?;
        Some(sym.1)
    }

    pub fn syms(&self) -> Vec<Sym> {
        let data = self.0.data();
        let n = data.len() / Sym::SIZE;

        let (_, res) = nom::multi::many_m_n(n, n, |i| Sym::parse(&self.1, i))(data).unwrap();

        return res;
    }
}

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
    File = 4,
    Unknown1 = 10,
}

impl_parse_for_bitenum!(SymBind, 4_usize);
impl_parse_for_bitenum!(SymType, 4_usize);

/// A symbol
#[derive(Clone, Debug)]
pub struct Sym<'a> {
    pub name: Cow<'a, str>,
    pub bind: SymBind,
    pub r#type: SymType,
    pub shndx: SectionIndex,
    pub value: Addr,
    pub size: u64,
}

impl<'a> Sym<'a> {
    pub const SIZE: usize = 24;

    pub fn parse(strtab: &'a StrTab, i: &'a [u8]) -> parse::Result<'a, Self> {
        use nom::bits::bits;

        let (i, (name, (bind, r#type), _reserved, shndx, value, size)) = tuple((
            map(le_u32, |x| Addr(x as u64)),
            bits(tuple((SymBind::parse, SymType::parse))),
            le_u8,
            map(le_u16, SectionIndex),
            Addr::parse,
            le_u64,
        ))(i)?;
        let name = strtab.at(name).unwrap();

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
