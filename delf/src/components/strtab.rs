use crate::Addr;

pub fn string_at(strtab: &[u8], offset: Addr) -> Option<String> {
    strtab
        .get(offset.0 as usize..)?
        .split(|&i| i == 0)
        .next()
        .map(|string| String::from_utf8_lossy(string).to_string())
}
