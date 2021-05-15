//! Utilities related to parsing of section headers

use core::fmt;

use derive_try_from_primitive::TryFromPrimitive;
use nom::{
    combinator::map,
    number::complete::{le_u32, le_u64},
    sequence::tuple,
};

use crate::{impl_parse_for_enum, parse, Addr};

/// An header for a section
#[derive(Debug, Clone)]
pub struct SectionHeader<'a> {
    pub name: Addr,
    pub typ: SectionType,
    pub flags: u64,
    pub addr: Addr,
    pub off: Addr,
    pub size: Addr,
    pub link: u32,
    pub info: u32,
    pub addralign: Addr,
    pub entsize: Addr,
    pub full_input: &'a [u8],
}

impl<'a> SectionHeader<'a> {
    pub fn parse(full_input: &'a [u8], i: parse::Input<'a>) -> parse::Result<'a, Self> {
        let (i, (name, r#type, flags, addr, off, size, link, info, addralign, entsize)) =
            tuple((
                map(le_u32, |x| Addr(x as u64)),
                SectionType::parse,
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
            typ: r#type,
            flags,
            addr,
            off,
            size,
            link,
            info,
            addralign,
            entsize,
            full_input,
        };
        Ok((i, res))
    }

    pub fn data_at(&self, offset: Addr) -> Option<&'a [u8]> {
        if offset >= self.size {
            return None;
        }

        let cut_start = &self.full_input[self.off.0 as usize..];
        let cut_end = &cut_start[..self.size.0 as usize];
        Some(&cut_end[offset.0 as usize..])
    }

    pub fn data(&self) -> &'a [u8] {
        let cut_start = &self.full_input[self.off.0 as usize..];
        &cut_start[..self.size.0 as usize]
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, TryFromPrimitive)]
#[repr(u32)]
pub enum SectionType {
    Null = 0,
    ProgBits = 1,
    SymTab = 2,
    StrTab = 3,
    Rela = 4,
    Hash = 5,
    Dynamic = 6,
    Note = 7,
    NoBits = 8,
    Rel = 9,
    DynSym = 11,
    Unknown4 = 14,
    Unknown5 = 15,
    Unknown1 = 0x6fff_fff6,
    Unknown2 = 0x6fff_fffe,
    Unknown3 = 0x6fff_ffff,
}

impl_parse_for_enum!(SectionType, le_u32);
