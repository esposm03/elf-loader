//! Utilities related to parsing of relocations

use derive_try_from_primitive::TryFromPrimitive;
use nom::number::complete::le_u32;

use crate::{impl_parse_for_enum, parse, Addr};

use super::{
    section::SectionHeader,
    sym::{Sym, SymTab},
};

pub struct RelaTable<'a>(pub &'a SectionHeader<'a>, pub SymTab<'a>);

impl<'a> RelaTable<'a> {
    pub fn rela_index(&'a self, index: usize) -> Option<Rela> {
        let pos = (Rela::SIZE * index) as u64;

        let data = self.0.data_at(Addr(pos))?;
        let rela = Rela::parse(data, &self.1).ok()?.1;

        Some(rela)
    }

    pub fn iter(&'a self) -> impl Iterator<Item = Rela<'a>> {
        (0..self.0.data().len() / Rela::SIZE)
            .map(|i| Rela::SIZE * i)
            .map(move |i| {
                let data = self.0.data();
                &data[i..Rela::SIZE + i]
            })
            .flat_map(move |slice| Rela::parse(slice, &self.1))
            .map(|(_, rela)| rela)
    }
}

/// A relocation
#[derive(Debug, Clone)]
pub struct Rela<'a> {
    pub offset: Addr,
    pub typ: RelocationType,
    pub sym: Sym<'a>,
    pub addend: Addr,
}

impl<'a> Rela<'a> {
    pub const SIZE: usize = 24;

    pub fn parse(i: parse::Input<'a>, symtab: &'a SymTab<'a>) -> parse::Result<'a, Self> {
        let (i, offset) = Addr::parse(i)?;
        let (i, typ) = RelocationType::parse(i)?;
        let (i, sym) = le_u32(i)?;
        let (i, addend) = Addr::parse(i)?;

        let sym = symtab
            .sym_index(sym as usize)
            .expect("Symbol index not found");
        Ok((
            i,
            Rela {
                offset,
                typ,
                sym,
                addend,
            },
        ))
    }
}

/// A relocation
#[derive(Debug)]
pub struct Rel<'a> {
    pub offset: Addr,
    pub typ: RelocationType,
    pub sym: Sym<'a>,
}

impl<'a> Rel<'a> {
    pub const SIZE: usize = 16;

    pub fn parse(i: parse::Input<'a>, symtab: &'a SymTab) -> parse::Result<'a, Self> {
        let (i, offset) = Addr::parse(i)?;
        let (i, typ) = RelocationType::parse(i)?;
        let (i, sym) = le_u32(i)?;

        let sym = symtab.sym_index(sym as usize).unwrap();

        Ok((i, Rel { offset, typ, sym }))
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
