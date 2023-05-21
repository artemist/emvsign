pub mod decoders;
pub mod elements;
pub mod errors;

pub use self::errors::TLVDecodeError;
pub use self::decoders::read_tlv;

/// A TLV value, see EMV 4.3 Book 3 section 4.3
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TLVValue {
    Alphabetic(String),
    Alphanumeric(String),
    AlphanumericSpecial(String),
    Binary(Vec<u8>),
    CompressedNumeric(u128), // PANs may be up to 19 digits long and could just fit into a u64 but let's leave some extra room
    Numeric(u128),
    Template(Vec<(u16, TLVValue)>),
}
