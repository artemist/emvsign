use std::fmt::{Display, Write};

use super::{dol::Dol, errors::DecodeError};

/// A TLV tag and value
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Field {
    pub tag: u16,
    pub value: Value,
}

/// A TLV value, see EMV 4.3 Book 3 section 4.3
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Value {
    Alphabetic(String),
    Alphanumeric(String),
    AlphanumericSpecial(String),
    Binary(Vec<u8>),
    DigitString(Vec<u8>), // CompressedNumeric in the EMV spec
    Numeric(u128),
    Template(Vec<Field>),
    Dol(Dol),
}

impl Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.fmt(f, 0)
    }
}

impl Value {
    pub(self) fn fmt(&self, f: &mut std::fmt::Formatter<'_>, indent: usize) -> std::fmt::Result {
        match self {
            Value::Alphabetic(s) => write!(f, "a\"{}\"", s),
            Value::Alphanumeric(s) => write!(f, "an\"{}\"", s),
            Value::AlphanumericSpecial(s) => write!(f, "ans\"{}\"", s),
            Value::Binary(data) => {
                write!(f, "0x")?;
                for b in data {
                    write!(f, "{:02x}", b)?;
                }
                Ok(())
            }
            Value::DigitString(n) => {
                write!(f, "cn")?;
                for &digit in n.iter() {
                    f.write_char(char::from_digit(digit as u32, 10).unwrap())?;
                }
                Ok(())
            }
            Value::Numeric(n) => write!(f, "n{}", n),
            Value::Template(fields) => {
                for field in fields {
                    field.fmt(f, indent + 1)?;
                }
                Ok(())
            }
            Value::Dol(dol) => {
                for entry in dol.get_entries() {
                    write!(
                        f,
                        "\n{:width$}{entry}",
                        "",
                        width = (indent + 1) * 4,
                        entry = entry
                    )?;
                }
                Ok(())
            }
        }
    }

    pub fn get_template(&self) -> Option<&[Field]> {
        match self {
            Value::Template(fields) => Some(fields),
            _ => None,
        }
    }

    pub fn get_digit_string(&self) -> Option<&[u8]> {
        match self {
            Value::DigitString(digits) => Some(digits.as_slice()),
            _ => None,
        }
    }

    pub fn get_string(&self) -> Option<&str> {
        match self {
            Value::Alphabetic(s) => Some(s),
            Value::Alphanumeric(s) => Some(s),
            Value::AlphanumericSpecial(s) => Some(s),
            _ => None,
        }
    }

    pub fn get_numeric(&self) -> Option<&u128> {
        match self {
            Value::Numeric(n) => Some(n),
            _ => None,
        }
    }

    pub fn get_path(&self, path: &[u16]) -> Result<&Value, DecodeError> {
        let mut curr_template = self;

        let mut last_tag = 0;
        for tag in path {
            let Value::Template(fields) = curr_template else {
                return Err(DecodeError::WrongType(last_tag, "Template"));
            };
            let Some(field) = fields.iter().find(|field| field.tag == *tag) else {
                return Err(DecodeError::NoSuchMember(*tag));
            };
            curr_template = &field.value;
            last_tag = *tag;
        }
        Ok(curr_template)
    }

    pub fn get_path_owned(self, path: &[u16]) -> Result<Value, DecodeError> {
        let mut curr_template = self;

        let mut last_tag = 0;
        for tag in path {
            let Value::Template(fields) = curr_template else {
                return Err(DecodeError::WrongType(last_tag, "Template"));
            };
            let Some(field) = fields.into_iter().find(|field| field.tag == *tag) else {
                return Err(DecodeError::NoSuchMember(*tag));
            };
            curr_template = field.value;
            last_tag = *tag;
        }
        Ok(curr_template)
    }
}

impl Display for Field {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.fmt(f, 0)
    }
}

impl Field {
    pub(self) fn fmt(&self, f: &mut std::fmt::Formatter<'_>, indent: usize) -> std::fmt::Result {
        write!(f, "{:width$}", "", width = indent * 4)?;
        let tag_name = super::elements::ELEMENTS
            .get(&self.tag)
            .map_or("", |elem| elem.name);
        if matches!(self.value, Value::Template(_)) {
            writeln!(f, "0x{:04x} (\"{}\") => {{", self.tag, tag_name)?;
            self.value.fmt(f, indent + 1)?;
            writeln!(f, "{:width$}}},", "", width = indent * 4)
        } else {
            writeln!(
                f,
                "0x{:04x} (\"{}\") => {},",
                self.tag, tag_name, self.value
            )
        }
    }
    pub fn get_path(&self, path: &[u16]) -> Result<&Value, DecodeError> {
        match path {
            [] => Err(DecodeError::NoPathRequested),
            [tag, ..] if *tag != self.tag => Err(DecodeError::NoSuchMember(*tag)),
            [_, remaining @ ..] => self.value.get_path(remaining),
        }
    }

    pub fn get_path_owned(self, path: &[u16]) -> Result<Value, DecodeError> {
        match path {
            [] => Err(DecodeError::NoPathRequested),
            [tag, ..] if *tag != self.tag => Err(DecodeError::NoSuchMember(*tag)),
            [_, remaining @ ..] => self.value.get_path_owned(remaining),
        }
    }

    pub fn get_path_binary(&self, path: &[u16]) -> Result<&[u8], DecodeError> {
        match self.get_path(path)? {
            Value::Binary(b) => Ok(b),
            _ => Err(DecodeError::WrongType(path[path.len() - 1], "Binary")),
        }
    }

    pub fn get_path_numeric(&self, path: &[u16]) -> Result<u128, DecodeError> {
        self.get_path(path)?
            .get_numeric()
            .cloned()
            .ok_or_else(|| DecodeError::WrongType(path[path.len() - 1], "Numeric"))
    }

    pub fn get_path_string(&self, path: &[u16]) -> Result<&str, DecodeError> {
        self.get_path(path)?
            .get_string()
            .ok_or_else(|| DecodeError::WrongType(path[path.len() - 1], "String"))
    }
}
