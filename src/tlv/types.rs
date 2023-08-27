use core::fmt;
use std::{
    collections::HashMap,
    fmt::{Display, Write},
};

use super::{dol::Dol, errors::DecodeError};

/// A TLV value, see EMV 4.3 Book 3 section 4.3
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum Value {
    Alphabetic(String),
    Alphanumeric(String),
    AlphanumericSpecial(String),
    Binary(Vec<u8>),
    DigitString(Vec<u8>), // CompressedNumeric in the EMV spec
    Numeric(u128),
    Template(FieldMap), // This will break if we have duplicates or order matters
    Dol(Dol),
}

pub type FieldMap = HashMap<u16, Value>;

pub trait FieldMapExt {
    fn get_path(&self, path: &[u16]) -> Result<&Value, DecodeError>;
    fn into_path(self, path: &[u16]) -> Result<Value, DecodeError>;
    fn display(&self) -> FieldMapDisplay;
}

pub struct FieldMapDisplay<'a>(&'a FieldMap);

impl Display for FieldMapDisplay<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            write!(f, "{{}}")
        } else {
            let mut adapter = PadAdapter {
                fmt: f,
                on_newline: false,
            };
            writeln!(adapter, "{{")?;
            for (tag, value) in self.0 {
                let tag_name = super::elements::ELEMENTS.get(tag).map(|elem| elem.name);
                let tag_name = if let Some(tag_name) = tag_name {
                    format!("\"{}\"", tag_name)
                } else {
                    "<unknown tag>".to_string()
                };
                writeln!(adapter, "0x{:04x} ({}) => {},", tag, tag_name, value)?;
            }
            write!(f, "}}")
        }
    }
}

impl FieldMapExt for FieldMap {
    fn get_path(&self, path: &[u16]) -> Result<&Value, DecodeError> {
        let mut curr_map = self;

        if path.is_empty() {
            return Err(DecodeError::NoPathRequested);
        }
        for tag in &path[..path.len() - 1] {
            let Some(field) = curr_map.get(tag) else {
                return Err(DecodeError::NoSuchMember(*tag));
            };

            let Some(next_map) = field.as_template() else {
                return Err(DecodeError::WrongType(*tag, "Template"));
            };

            curr_map = next_map;
        }

        curr_map
            .get(&path[path.len() - 1])
            .ok_or(DecodeError::NoSuchMember(path[path.len() - 1]))
    }

    fn into_path(self, path: &[u16]) -> Result<Value, DecodeError> {
        let mut curr_map = self;

        if path.is_empty() {
            return Err(DecodeError::NoPathRequested);
        }
        for tag in &path[..path.len() - 1] {
            let Some(field) = curr_map.remove(tag) else {
                return Err(DecodeError::NoSuchMember(*tag));
            };

            let Some(_curr_map) = field.into_template() else {
                return Err(DecodeError::WrongType(*tag, "Template"));
            };
        }

        curr_map
            .remove(&path[path.len() - 1])
            .ok_or(DecodeError::NoSuchMember(path[path.len() - 1]))
    }

    fn display(&self) -> FieldMapDisplay {
        FieldMapDisplay(self)
    }
}

struct PadAdapter<'buf, 'fmt> {
    fmt: &'buf mut fmt::Formatter<'fmt>,
    on_newline: bool,
}

impl fmt::Write for PadAdapter<'_, '_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let mut lines = s.split('\n');
        let first = lines.next().unwrap();
        if !first.is_empty() {
            if self.on_newline {
                write!(self.fmt, "        ")?;
            }
            self.fmt.write_str(first)?;
            self.on_newline = false;
        }
        for line in lines {
            if line.is_empty() {
                writeln!(self.fmt)?;
                self.on_newline = true;
            } else {
                write!(self.fmt, "\n        {}", line)?;
                self.on_newline = false;
            }
        }
        Ok(())
    }
}

impl Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
                for &digit in n {
                    f.write_char(char::from_digit(digit as u32, 10).unwrap())?;
                }
                Ok(())
            }
            Value::Numeric(n) => write!(f, "n{}", n),
            Value::Template(fields) => FieldMapDisplay(fields).fmt(f),
            Value::Dol(dol) => {
                if dol.get_entries().is_empty() {
                    write!(f, "{{}}")
                } else {
                    let mut adapter = PadAdapter {
                        fmt: f,
                        on_newline: false,
                    };
                    writeln!(adapter, "{{")?;
                    for entry in dol.get_entries() {
                        writeln!(adapter, "{entry}",)?;
                    }
                    write!(f, "}}")
                }
            }
        }
    }
}

impl Value {
    pub fn into_alphabetic(self) -> Option<String> {
        match self {
            Value::Alphabetic(s) => Some(s),
            _ => None,
        }
    }

    pub fn into_alphanumeric(self) -> Option<String> {
        match self {
            Value::Alphanumeric(s) => Some(s),
            _ => None,
        }
    }

    pub fn into_alphanumeric_special(self) -> Option<String> {
        match self {
            Value::AlphanumericSpecial(s) => Some(s),
            _ => None,
        }
    }

    pub fn into_binary(self) -> Option<Vec<u8>> {
        match self {
            Value::Binary(b) => Some(b),
            _ => None,
        }
    }

    pub fn into_digit_string(self) -> Option<Vec<u8>> {
        match self {
            Value::DigitString(digits) => Some(digits),
            _ => None,
        }
    }

    pub fn into_numeric(self) -> Option<u128> {
        match self {
            Value::Numeric(n) => Some(n),
            _ => None,
        }
    }

    pub fn into_template(self) -> Option<FieldMap> {
        match self {
            Value::Template(fields) => Some(fields),
            _ => None,
        }
    }

    pub fn into_dol(self) -> Option<Dol> {
        match self {
            Value::Dol(d) => Some(d),
            _ => None,
        }
    }

    pub fn as_alphabetic(&self) -> Option<&str> {
        match self {
            Value::Alphabetic(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_alphanumeric(&self) -> Option<&str> {
        match self {
            Value::Alphanumeric(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_alphanumeric_special(&self) -> Option<&str> {
        match self {
            Value::AlphanumericSpecial(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_binary(&self) -> Option<&[u8]> {
        match self {
            Value::Binary(b) => Some(b.as_slice()),
            _ => None,
        }
    }

    pub fn as_digit_string(&self) -> Option<&[u8]> {
        match self {
            Value::DigitString(digits) => Some(digits.as_slice()),
            _ => None,
        }
    }

    pub fn as_numeric(&self) -> Option<&u128> {
        match self {
            Value::Numeric(n) => Some(n),
            _ => None,
        }
    }

    pub fn as_template(&self) -> Option<&FieldMap> {
        match self {
            Value::Template(fields) => Some(fields),
            _ => None,
        }
    }

    pub fn as_dol(&self) -> Option<&Dol> {
        match self {
            Value::Dol(d) => Some(d),
            _ => None,
        }
    }

    pub fn get_path(&self, path: &[u16]) -> Result<&Value, DecodeError> {
        self.as_template()
            .ok_or(DecodeError::WrongType(0, "Template"))
            .and_then(|map| map.get_path(path))
    }

    pub fn get_path_binary(&self, path: &[u16]) -> Result<&[u8], DecodeError> {
        self.get_path(path)?
            .as_binary()
            .ok_or(DecodeError::WrongType(path[path.len() - 1], "Binary"))
    }

    pub fn get_path_owned(self, path: &[u16]) -> Result<Value, DecodeError> {
        self.into_template()
            .ok_or(DecodeError::WrongType(0, "Template"))
            .and_then(|map| map.into_path(path))
    }
}
