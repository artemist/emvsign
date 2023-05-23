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
    BadBcd(u8),
    TemplateInternal(u16, Box<TLVDecodeError>),
    TooLong(usize, usize),
    TooShort(usize, usize),
    UnknownTag(u16),
    UnsupportedChar(StringType, u8),
    NoPathRequested,
    WrongType(u16, &'static str),
    NoSuchMember(u16),
}

impl Display for TLVDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            TLVDecodeError::BadBcd(b) => write!(f, "Bad BCD character 0x{:1x}", b),
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
            TLVDecodeError::UnknownTag(tag) => write!(f, "Found unknown tag 0x{:04x}", tag),
            TLVDecodeError::TemplateInternal(tag, ref err) => {
                write!(f, "Error while processing tag 0x{:04x}: {}", tag, err)
            }
            TLVDecodeError::NoPathRequested => write!(f, "No path requested"),
            TLVDecodeError::WrongType(tag, wanted) => {
                write!(f, "Found 0x{:04x} but it is not {}", tag, wanted)
            }
            TLVDecodeError::NoSuchMember(tag) => {
                write!(f, "No member of template with tag 0x{:04x}", tag)
            }
        }
    }
}

impl Error for TLVDecodeError {}
