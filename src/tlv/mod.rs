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
    // Use a string here because the leading digit of a PAN could theoretically be 0 and we don't want to mess up
    CompressedNumeric(String), 
    Numeric(u128),
    Template(Vec<(u16, TLVValue)>),
}
