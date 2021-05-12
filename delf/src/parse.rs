//! General utilities related to parsing

use std::fmt;

/// Given an enum, implement a `parse` method for it that takes a primitive,
/// processes it with the function given as the second parameter, and returns
/// an enum
#[macro_export]
macro_rules! impl_parse_for_enum {
    ($type: ident, $number_parser: ident) => {
        impl $type {
            pub fn parse(full_input: parse::Input) -> parse::Result<Self> {
                use std::convert::TryFrom;
                use nom::number::complete::$number_parser;
                let (i, val) = $number_parser(full_input)?;
                match Self::try_from(val) {
                    Ok(val) => Ok((i, val)),
                    Err(_) => Err(nom::Err::Failure(parse::Error::from_string(
                        full_input,
                        format!("Unknown {} {} (0x{:x})", stringify!($type), val, val),
                    ))),
                }
            }
        }
    };
}

/// Given an enum, implement a `parse` method for it that takes a primitive,
/// processes it with the function given as the second parameter, and returns
/// a `BitFlags`
#[macro_export]
macro_rules! impl_parse_for_enumflags {
    ($type: ident, $number_parser: ident) => {
        impl $type {
            pub fn parse(i: parse::Input) -> parse::Result<enumflags2::BitFlags<Self>> {
                use nom::{
                    combinator::map_res,
                    error::{context, ErrorKind},
                    number::complete::$number_parser,
                };
                let parser = map_res($number_parser, |x| {
                    enumflags2::BitFlags::<Self>::from_bits(x).map_err(|_| ErrorKind::Alt)
                });
                context(stringify!($type), parser)(i)
            }
        }
    };
}

#[macro_export]
macro_rules! impl_parse_for_bitenum {
    ($type: ident, $bits: expr) => {
        impl $type {
            pub fn parse(full_input: parse::BitInput) -> parse::BitResult<Self> {
                use core::convert::TryFrom;
                use nom::bits::complete::take;

                let (i, val): (_, u8) = take($bits)(full_input)?;
                match Self::try_from(val) {
                    Ok(val) => Ok((i, val)),
                    Err(_) => Err(nom::Err::Failure($crate::parse::Error::from_string(
                        full_input,
                        format!("Unknown {} {} (0x{:x})", stringify!($type), val, val),
                    ))),
                }
            }
        }
    };
}

#[derive(Debug, Clone)]
pub enum ErrorKind {
    Nom(nom::error::ErrorKind),
    Context(&'static str),
    String(String),
}

pub struct Error<I> {
    pub errors: Vec<(I, ErrorKind)>,
}

impl<I> Error<I> {
    pub fn from_string<S: Into<String>>(input: I, s: S) -> Self {
        let errors = vec![(input, ErrorKind::String(s.into()))];
        Self { errors }
    }
}

impl fmt::Debug for Error<&[u8]> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (input, err) in &self.errors {
            writeln!(f, "{:?}:", err)?;
            writeln!(f, "input: {:?}", crate::HexDump(input))?;
        }
        Ok(())
    }
}

impl<I> nom::error::ParseError<I> for Error<I> {
    fn from_error_kind(input: I, kind: nom::error::ErrorKind) -> Self {
        let errors = vec![(input, ErrorKind::Nom(kind))];
        Self { errors }
    }

    fn append(input: I, kind: nom::error::ErrorKind, mut other: Self) -> Self {
        other.errors.push((input, ErrorKind::Nom(kind)));
        other
    }

    fn add_context(input: I, ctx: &'static str, mut other: Self) -> Self {
        other.errors.push((input, ErrorKind::Context(ctx)));
        other
    }
}

pub type Input<'a> = &'a [u8];
pub type Result<'a, O> = nom::IResult<Input<'a>, O, Error<Input<'a>>>;

pub type BitInput<'a> = (&'a [u8], usize);
pub type BitResult<'a, O> = nom::IResult<BitInput<'a>, O, Error<BitInput<'a>>>;

use nom::{ErrorConvert, Slice};
use std::ops::RangeFrom;

impl<I> ErrorConvert<Error<I>> for Error<(I, usize)>
where
    I: Slice<RangeFrom<usize>>,
{
    fn convert(self) -> Error<I> {
        let errors = self
            .errors
            .into_iter()
            .map(|((rest, offset), err)| (rest.slice(offset / 8..), err))
            .collect();
        Error { errors }
    }
}
