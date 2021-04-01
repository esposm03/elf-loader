//! Utilities related to parsing of section headers

use core::convert::TryFrom;
use core::fmt;

use derive_try_from_primitive::TryFromPrimitive;
use nom::{
    combinator::map,
    number::complete::{le_u32, le_u64},
    sequence::tuple,
};

use crate::{impl_parse_for_enum, parse, Addr};

/// An header for a section
#[derive(Debug)]
pub struct SectionHeader {
    pub name: Addr,
    pub r#type: SectionType,
    pub flags: u64,
    pub addr: Addr,
    pub off: Addr,
    pub size: Addr,
    pub link: u32,
    pub info: u32,
    pub addralign: Addr,
    pub entsize: Addr,
}

impl SectionHeader {
    pub fn parse(i: parse::Input) -> parse::Result<Self> {
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
            r#type,
            flags,
            addr,
            off,
            size,
            link,
            info,
            addralign,
            entsize,
        };
        Ok((i, res))
    }
}

/// The type of a section
#[repr(u32)]
#[derive(Clone, Copy, Debug, TryFromPrimitive, PartialEq)]
pub enum SectionType {
    Null = 0x0,
    Progbits = 0x1,
    SymTab = 0x2,
    StrTab = 0x3,
    Rela = 0x4,
    Hash = 0x5,
    Dynamic = 0x6,
    Note = 0x7,
    Unknown1 = 0x70000001,
}

impl_parse_for_enum!(SectionType, le_u32);

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
