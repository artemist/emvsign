use core::fmt;
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

struct PadAdapter<'buf, 'fmt> {
    fmt: &'buf mut fmt::Formatter<'fmt>,
    on_newline: bool,
}
// impl PadAdapter<'_, '_> {
//     fn new(f: &mut fmt::Formatter<'_>, on_newline: bool) -> Self {
//         PadAdapter { fmt: f, on_newline }
//     }
// }

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
            Value::Template(fields) => {
                if fields.is_empty() {
                    write!(f, "{{}}")
                } else {
                    let mut adapter = PadAdapter {
                        fmt: f,
                        on_newline: false,
                    };
                    writeln!(adapter, "{{")?;
                    for field in fields {
                        write!(adapter, "{}", field)?;
                    }
                    write!(f, "}}")
                }
            }
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

    pub fn get_dol(&self, tag: u16) -> Result<&Dol, DecodeError> {
        match self.get_path(&[tag])? {
            Value::Dol(d) => Ok(d),
            _ => Err(DecodeError::WrongType(tag, "Dol")),
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
        {
            let f: &mut std::fmt::Formatter<'_> = f;
            let tag_name = super::elements::ELEMENTS
                .get(&self.tag)
                .map(|elem| elem.name);
            let tag_name = if let Some(tag_name) = tag_name {
                format!("\"{}\"", tag_name)
            } else {
                "<unknown tag>".to_string()
            };
            writeln!(f, "0x{:04x} ({}) => {},", self.tag, tag_name, self.value)
        }
    }
}

impl Field {
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
