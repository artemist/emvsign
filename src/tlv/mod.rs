pub mod decoders;
pub mod elements;
pub mod errors;

use std::fmt::Display;

pub use self::decoders::read_tlv;
pub use self::errors::TLVDecodeError;

/// A TLV value, see EMV 4.3 Book 3 section 4.3
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TLVValue {
    Alphabetic(String),
    Alphanumeric(String),
    AlphanumericSpecial(String),
    Binary(Vec<u8>),
    // Use a string here because the leading digit of a PAN could theoretically be 0 and we don't want to mess up
    CompressedNumeric(String),
    Numeric(u128),
    Template(Vec<(u16, TLVValue)>),
}

impl Display for TLVValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.fmt(f, 0)
    }
}

impl TLVValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>, indent: usize) -> std::fmt::Result {
        write!(f, "{:width$}", "", width = indent * 4)?;
        match self {
            TLVValue::Alphabetic(s) => write!(f, "a\"{}\"", s),
            TLVValue::Alphanumeric(s) => write!(f, "an\"{}\"", s),
            TLVValue::AlphanumericSpecial(s) => write!(f, "ans\"{}\"", s),
            TLVValue::Binary(data) => {
                for b in data {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
            TLVValue::CompressedNumeric(n) => write!(f, "{}", n),
            TLVValue::Numeric(n) => write!(f, "{}", n),
            TLVValue::Template(fields) => {
                for (idx, (tag, value)) in fields.iter().enumerate() {
                    if idx != 0 {
                        write!(f, "{:width$}", "", width = indent * 4)?;
                    }
                    let tag_name = self::elements::ELEMENTS
                        .get(tag)
                        .and_then(|elem| Some(elem.name))
                        .unwrap_or("");
                    if matches!(value, TLVValue::Template(_)) {
                        write!(f, "0x{:04x} (\"{}\") => {{\n", tag, tag_name)?;
                        value.fmt(f, indent + 1)?;
                        write!(f, "}}")?;
                    } else {
                        write!(f, "0x{:04x} (\"{}\") => {},\n", tag, tag_name, value)?;
                    }
                }
                Ok(())
            }
        }
    }
}
