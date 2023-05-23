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

    pub fn get_path(&self, path: &[u16]) -> Result<&TLVValue, TLVDecodeError> {
        let mut curr_template = self;

        let mut last_tag = 0;
        'outer: for tag in path {
            match curr_template {
                TLVValue::Template(fields) => {
                    for field in fields {
                        if field.tag == *tag {
                            curr_template = &field.value;
                            last_tag = *tag;
                            continue 'outer;
                        }
                    }
                    return Err(TLVDecodeError::NoSuchMember(*tag));
                }
                _ => return Err(TLVDecodeError::WrongType(last_tag, "Template")),
            }
        }
        return Ok(curr_template);
    }

    pub fn get_path_owned(self, path: &[u16]) -> Result<TLVValue, TLVDecodeError> {
        let mut curr_template = self;

        let mut last_tag = 0;
        'outer: for tag in path {
            match curr_template {
                TLVValue::Template(fields) => {
                    for field in fields {
                        if field.tag == *tag {
                            curr_template = field.value;
                            last_tag = *tag;
                            continue 'outer;
                        }
                    }
                    return Err(TLVDecodeError::NoSuchMember(*tag));
                }
                _ => return Err(TLVDecodeError::WrongType(last_tag, "Template")),
            }
        }
        return Ok(curr_template);
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
    pub fn get_path(&self, path: &[u16]) -> Result<&TLVValue, TLVDecodeError> {
        if path.len() == 0 {
            Err(TLVDecodeError::NoPathRequested)
        } else if self.tag != path[0] {
            Err(TLVDecodeError::NoSuchMember(path[0]))
        } else {
            self.value.get_path(&path[1..])
        }
    }

    pub fn get_path_owned(self, path: &[u16]) -> Result<TLVValue, TLVDecodeError> {
        if path.len() == 0 {
            Err(TLVDecodeError::NoPathRequested)
        } else if self.tag != path[0] {
            Err(TLVDecodeError::NoSuchMember(path[0]))
        } else {
            self.value.get_path_owned(&path[1..])
        }
    }

    pub fn get_path_binary(&self, path: &[u16]) -> Result<&[u8], TLVDecodeError> {
        match self.get_path(path)? {
            TLVValue::Binary(b) => Ok(&b),
            _ => Err(TLVDecodeError::WrongType(path[path.len() - 1], "Binary")),
        }
    }

    pub fn get_path_numeric(&self, path: &[u16]) -> Result<u128, TLVDecodeError> {
        match self.get_path(path)? {
            TLVValue::Numeric(n) => Ok(*n),
            _ => Err(TLVDecodeError::WrongType(path[path.len() - 1], "Numeric")),
        }
    }

    pub fn get_path_string(&self, path: &[u16]) -> Result<&str, TLVDecodeError> {
        match self.get_path(path)? {
            TLVValue::Alphabetic(s) => Ok(&s),
            TLVValue::Alphanumeric(s) => Ok(&s),
            TLVValue::AlphanumericSpecial(s) => Ok(&s),
            TLVValue::CompressedNumeric(s) => Ok(&s),
            _ => Err(TLVDecodeError::WrongType(path[path.len() - 1], "String")),
        }
    }
}
