use crate::components::segment::DynamicTag;

/// An error that occurred while trying to read relocations
#[derive(thiserror::Error, Debug)]
pub enum ReadRelaError {
    #[error("{0}")]
    DynamicEntryNotFound(#[from] GetDynamicEntryError),
    #[error("Object file does not contain a `SHT_RELA` section")]
    RelaSegmentNotFound,
    #[error("Object file does not contain a `SHT_REL` section")]
    RelSegmentNotFound,
    #[error("Parsing error: {0}")]
    ParsingError(String),
}

#[derive(thiserror::Error, Debug)]
pub enum GetDynamicEntryError {
    #[error("Dynamic entry {0:?} not found")]
    NotFound(DynamicTag),
}

/// An error that occurred while trying to read strings from the file
#[derive(thiserror::Error, Debug)]
pub enum GetStringError {
    #[error("StrTab dynamic entry not found")]
    StrTabNotFound,
    #[error("StrTab segment not found")]
    StrTabSegmentNotFound,
    #[error("String not found")]
    StringNotFound,
}

/// An error that occurred while trying to read symbols
#[derive(thiserror::Error, Debug)]
pub enum ReadSymsError {
    #[error("{0}")]
    DynamicEntryNotFound(#[from] GetDynamicEntryError),
    #[error("SymTab section not found")]
    SymTabSectionNotFound,
    #[error("SymTab segment not found")]
    SymTabSegmentNotFound,
    #[error("Parsing error: {0}")]
    ParsingError(String),
}
