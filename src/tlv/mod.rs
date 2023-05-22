pub mod decoders;
pub mod elements;
pub mod errors;

use std::fmt::Display;

pub use self::decoders::read_field;
pub use self::errors::TLVDecodeError;

/// A TLV tag and value
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct TLVField {
    pub tag: u16,
    pub value: TLVValue,
}

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
    Template(Vec<TLVField>),
}

impl Display for TLVValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.fmt(f, 0)
    }
}

impl TLVValue {
    pub(self) fn fmt(&self, f: &mut std::fmt::Formatter<'_>, indent: usize) -> std::fmt::Result {
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
                for field in fields {
                    field.fmt(f, indent + 1)?;
                }
                Ok(())
            }
        }
    }

    pub fn get_path(&self, path: &[u16]) -> Option<&TLVValue> {
        let mut curr_template = self;

        'outer: for tag in path {
            match curr_template {
                TLVValue::Template(fields) => {
                    for field in fields {
                        if field.tag == *tag {
                            curr_template = &field.value;
                            continue 'outer;
                        }
                    }
                    return None;
                }
                _ => return None,
            }
        }
        return Some(curr_template)
    }
}

impl Display for TLVField {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.fmt(f, 0)
    }
}

impl TLVField {
    pub(self) fn fmt(&self, f: &mut std::fmt::Formatter<'_>, indent: usize) -> std::fmt::Result {
        write!(f, "{:width$}", "", width = indent * 4)?;
        let tag_name = self::elements::ELEMENTS
            .get(&self.tag)
            .and_then(|elem| Some(elem.name))
            .unwrap_or("");
        if matches!(self.value, TLVValue::Template(_)) {
            write!(f, "0x{:04x} (\"{}\") => {{\n", self.tag, tag_name)?;
            self.value.fmt(f, indent + 1)?;
            write!(f, "{:width$}}},\n", "", width = indent * 4)
        } else {
            write!(
                f,
                "0x{:04x} (\"{}\") => {},\n",
                self.tag, tag_name, self.value
            )
        }
    }
    pub fn get_path(&self, path: &[u16]) -> Option<&TLVValue> {
        if path.len() == 0 || self.tag != path[0] {
            None
        } else {
            self.value.get_path(&path[1..])
        }
    }
}
