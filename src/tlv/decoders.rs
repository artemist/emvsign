use super::{TLVValue, TLVDecodeError};

pub fn binary(raw: &[u8]) -> Result<TLVValue, TLVDecodeError> {
    Ok(TLVValue::Binary(raw.to_vec()))
}
