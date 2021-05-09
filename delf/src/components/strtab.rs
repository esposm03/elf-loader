use std::borrow::Cow;

use crate::Addr;

#[derive(Debug)]
pub struct StrTab<'a>(Cow<'a, [u8]>);

impl<'a> StrTab<'a> {
    /// Create a new `StrTab` with owned data
    pub fn new(data: Vec<u8>) -> Self {
        StrTab(Cow::from(data))
    }

    /// Create a new `StrTab` with borrowed data
    pub fn new_borrowed(data: &'a [u8]) -> Self {
        StrTab(Cow::Borrowed(data))
    }

    /// Read the string at the given offset
    pub fn at(&self, offset: Addr) -> Option<String> {
        self.0
            .get(offset.0 as usize..)?
            .split(|&i| i == 0)
            .next()
            .map(|string| String::from_utf8_lossy(string).to_string())
    }
}
