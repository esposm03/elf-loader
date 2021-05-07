use std::borrow::Cow;

use crate::Addr;

#[derive(Debug)]
pub struct StrTab<'a>(Cow<'a, [u8]>);

impl StrTab<'_> {
    pub fn new(data: Vec<u8>) -> Self {
        StrTab(Cow::from(data))
    }

    pub fn at(&self, offset: Addr) -> Option<String> {
        self.0
            .get(offset.0 as usize..)?
            .split(|&i| i == 0)
            .next()
            .map(|string| String::from_utf8_lossy(string).to_string())
    }
}
