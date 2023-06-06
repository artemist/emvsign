use std::error::Error;
use std::fmt::Display;

#[derive(Debug, PartialEq, Eq, Copy, Clone)]
pub enum StringType {
    Alphabetic,
    Alphanumeric,
    AlphanumericSpecial,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DecodeError {
    BadBcd(u8),
    TemplateInternal(u16, Box<DecodeError>),
    LengthTooLong(usize, usize),
    MessageTooShort(usize, usize),
    UnsupportedChar(StringType, u8),
    NoPathRequested,
    WrongType(u16, &'static str),
    NoSuchMember(u16),
}

impl Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            DecodeError::BadBcd(b) => write!(f, "Bad BCD character 0x{:1x}", b),
            DecodeError::UnsupportedChar(string_type, ch) => write!(
                f,
                "Unsupported character 0x{:02x} in {:?} string",
                ch, string_type
            ),
            DecodeError::MessageTooShort(needed, got) => {
                write!(f, "Message too short, needed {}, got {}", needed, got)
            }
            DecodeError::LengthTooLong(needed, got) => {
                write!(f, "Length too long, needed {}, got {}", needed, got)
            }
            DecodeError::TemplateInternal(tag, ref err) => {
                write!(f, "Error while processing tag 0x{:04x}: {}", tag, err)
            }
            DecodeError::NoPathRequested => write!(f, "No path requested"),
            DecodeError::WrongType(tag, wanted) => {
                write!(f, "Found 0x{:04x} but it is not {}", tag, wanted)
            }
            DecodeError::NoSuchMember(tag) => {
                write!(f, "No member of template with tag 0x{:04x}", tag)
            }
        }
    }
}

impl Error for DecodeError {}
