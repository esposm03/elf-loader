use std::borrow::Cow;

use crate::{impl_parse_for_enum, parse, Addr};
use derive_try_from_primitive::TryFromPrimitive;
use nom::{
    combinator::{map, verify},
    multi::many_till,
};

use super::{section::SectionHeader, strtab::StrTab};

pub struct DynamicSection<'a>(pub &'a SectionHeader<'a>, pub StrTab<'a>);

impl<'a> DynamicSection<'a> {
    pub fn entry_with_tag(&self, typ: DynamicTag) -> Option<DynamicEntry> {
        let (_, entries): (_, Vec<DynamicEntry>) = map(
            many_till(
                |i| DynamicEntry::parse(i, &self.1),
                verify(
                    |i| DynamicEntry::parse(i, &self.1),
                    |e| e.tag == DynamicTag::Null,
                ),
            ),
            |(entries, _last)| entries,
        )(self.0.data())
        .unwrap();

        entries.iter().find(|entry| entry.tag == typ).cloned()
    }
}

/// A dynamic entry
#[derive(Debug, Clone)]
pub struct DynamicEntry<'a> {
    pub addr: AddrOrString<'a>,
    pub tag: DynamicTag,
}

impl<'a> DynamicEntry<'a> {
    pub fn parse(i: &'a [u8], strtab: &'a StrTab) -> parse::Result<'a, Self> {
        let (i, tag) = DynamicTag::parse(i)?;
        let (i, addr) = Addr::parse(i)?;

        use DynamicTag::*;
        let addr = if let Some(string) = strtab.at(addr) {
            if let Needed | SoName | RPath | Runpath = tag {
                AddrOrString::String(string)
            } else {
                AddrOrString::Address(addr)
            }
        } else {
            AddrOrString::Address(addr)
        };

        Ok((i, Self { addr, tag }))
    }
}

#[derive(Clone, Debug)]
pub enum AddrOrString<'a> {
    Address(Addr),
    String(Cow<'a, str>),
}

impl AddrOrString<'_> {
    pub fn unwrap_string(&self) -> &Cow<str> {
        match self {
            Self::String(i) => i,
            Self::Address(_) => panic!("expected a string but got an address"),
        }
    }
}

/// The tag of a dynamic entry
#[repr(u64)]
#[derive(Debug, TryFromPrimitive, PartialEq, Eq, Clone, Copy)]
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

impl_parse_for_enum!(DynamicTag, le_u64);
