use super::*;

#[test]
fn test_read_alphabetic() {
    assert_eq!(
        decoders::alphabetic(&b"OwO"[..]),
        Ok(Value::Alphabetic("OwO".to_string()))
    )
}

#[test]
fn test_read_alphabetic_unsupported_char() {
    assert_eq!(
        decoders::alphabetic(&b" OwO"[..]),
        Err(TLVDecodeError::UnsupportedChar(
            errors::StringType::Alphabetic,
            b' '
        ))
    )
}

#[test]
fn test_read_alphanumeric() {
    assert_eq!(
        decoders::alphanumeric(&b"OwO420"[..]),
        Ok(Value::Alphanumeric("OwO420".to_string()))
    )
}

#[test]
fn test_read_alphanumeric_unsupported_char() {
    assert_eq!(
        decoders::alphanumeric(&b"OwO_420"[..]),
        Err(TLVDecodeError::UnsupportedChar(
            errors::StringType::Alphanumeric,
            b'_'
        ))
    )
}

#[test]
fn test_read_alphanumeric_special() {
    assert_eq!(
        decoders::alphanumeric_special(&b"XxX_OwO42069_XxX"[..]),
        Ok(Value::AlphanumericSpecial("XxX_OwO42069_XxX".to_string()))
    )
}

#[test]
fn test_read_alphanumeric_special_unsupported_char() {
    assert_eq!(
        decoders::alphanumeric_special(&b"OwO_420\x7f"[..]),
        Err(TLVDecodeError::UnsupportedChar(
            errors::StringType::AlphanumericSpecial,
            b'\x7f'
        ))
    )
}
