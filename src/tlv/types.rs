use std::fmt::Display;

use super::errors::DecodeError;

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
    // Use a string here because the leading digit of a PAN could theoretically be 0 and we don't want to mess up
    CompressedNumeric(String),
    Numeric(u128),
    Template(Vec<Field>),
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
            Value::CompressedNumeric(n) => write!(f, "cn{}", n),
            Value::Numeric(n) => write!(f, "n{}", n),
            Value::Template(fields) => {
                for field in fields {
                    field.fmt(f, indent + 1)?;
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

    pub fn get_string(&self) -> Option<&str> {
        match self {
            Value::Alphabetic(s) => Some(s),
            Value::Alphanumeric(s) => Some(s),
            Value::AlphanumericSpecial(s) => Some(s),
            Value::CompressedNumeric(s) => Some(s),
            _ => None,
        }
    }

    pub fn get_path(&self, path: &[u16]) -> Result<&Value, DecodeError> {
        let mut curr_template = self;

        let mut last_tag = 0;
        'outer: for tag in path {
            match curr_template {
                Value::Template(fields) => {
                    for field in fields {
                        if field.tag == *tag {
                            curr_template = &field.value;
                            last_tag = *tag;
                            continue 'outer;
                        }
                    }
                    return Err(DecodeError::NoSuchMember(*tag));
                }
                _ => return Err(DecodeError::WrongType(last_tag, "Template")),
            }
        }
        Ok(curr_template)
    }

    pub fn get_path_owned(self, path: &[u16]) -> Result<Value, DecodeError> {
        let mut curr_template = self;

        let mut last_tag = 0;
        'outer: for tag in path {
            match curr_template {
                Value::Template(fields) => {
                    for field in fields {
                        if field.tag == *tag {
                            curr_template = field.value;
                            last_tag = *tag;
                            continue 'outer;
                        }
                    }
                    return Err(DecodeError::NoSuchMember(*tag));
                }
                _ => return Err(DecodeError::WrongType(last_tag, "Template")),
            }
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
            .map(|elem| elem.name)
            .unwrap_or("");
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
        if path.is_empty() {
            Err(DecodeError::NoPathRequested)
        } else if self.tag != path[0] {
            Err(DecodeError::NoSuchMember(path[0]))
        } else {
            self.value.get_path(&path[1..])
        }
    }

    pub fn get_path_owned(self, path: &[u16]) -> Result<Value, DecodeError> {
        if path.is_empty() {
            Err(DecodeError::NoPathRequested)
        } else if self.tag != path[0] {
            Err(DecodeError::NoSuchMember(path[0]))
        } else {
            self.value.get_path_owned(&path[1..])
        }
    }

    pub fn get_path_binary(&self, path: &[u16]) -> Result<&[u8], DecodeError> {
        match self.get_path(path)? {
            Value::Binary(b) => Ok(b),
            _ => Err(DecodeError::WrongType(path[path.len() - 1], "Binary")),
        }
    }

    pub fn get_path_numeric(&self, path: &[u16]) -> Result<u128, DecodeError> {
        match self.get_path(path)? {
            Value::Numeric(n) => Ok(*n),
            _ => Err(DecodeError::WrongType(path[path.len() - 1], "Numeric")),
        }
    }

    pub fn get_path_string(&self, path: &[u16]) -> Result<&str, DecodeError> {
        match self.get_path(path)? {
            Value::Alphabetic(s) => Ok(s),
            Value::Alphanumeric(s) => Ok(s),
            Value::AlphanumericSpecial(s) => Ok(s),
            Value::CompressedNumeric(s) => Ok(s),
            _ => Err(DecodeError::WrongType(path[path.len() - 1], "String")),
        }
    }
}
