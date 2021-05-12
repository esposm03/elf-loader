use std::borrow::Cow;

use crate::Addr;

use super::section::SectionHeader;

/// A section whose content is to be interpreted as a symbol table
///
/// An instance can be constructed with [`crate::ParsedElf::strtab`]
#[derive(Debug)]
pub struct StrTab<'a>(pub &'a SectionHeader<'a>);

impl<'a> StrTab<'a> {
    /// Read the string at the given offset
    pub fn at(&self, offset: Addr) -> Option<Cow<str>> {
        self.0
            .data_at(offset)?
            .split(|&i| i == 0)
            .next()
            .map(|string| String::from_utf8_lossy(string))
    }
}
