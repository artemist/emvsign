use std::error::Error;
use std::fmt::Display;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum StringType {
    Alphabetic,
    Alphanumeric,
    AlphanumericSpecial,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TLVDecodeError {
    UnsupportedChar(StringType, u8),
    TooShort(usize, usize),
    TooLong(usize, usize),
    UnknownTag(u16),
    TemplateInternal(u16, Box<TLVDecodeError>),
}

impl Display for TLVDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            TLVDecodeError::UnsupportedChar(string_type, ch) => write!(
                f,
                "Unsupported character 0x{:02x} in {:?} string",
                ch, string_type
            ),
            TLVDecodeError::TooShort(needed, got) => {
                write!(f, "Message too short, needed {}, got {}", needed, got)
            }
            TLVDecodeError::TooLong(needed, got) => {
                write!(f, "Length too long, needed {}, got {}", needed, got)
            }
            TLVDecodeError::UnknownTag(tag) => write!(f, "Found unknown tag {}", tag),
            TLVDecodeError::TemplateInternal(tag, ref err) => {
                write!(f, "Error while processing tag {}: {}", tag, err)
            }
        }
    }
}

impl Error for TLVDecodeError {}
