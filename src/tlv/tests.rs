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
        Err(DecodeError::UnsupportedChar(
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
        Err(DecodeError::UnsupportedChar(
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
        Err(DecodeError::UnsupportedChar(
            errors::StringType::AlphanumericSpecial,
            b'\x7f'
        ))
    )
}

#[test]
fn test_parse_ddt() {
    assert_eq!(
        // Hnadwritten example of what a Directory Discretionary Template could be
        super::read_field(&b"\x73\x0b\x5f\x55\x02US\x42\x04\x00\x44\x03\x93"[..]).unwrap(),
        Field {
            tag: 0x73,
            value: Value::Template(vec![
                Field {
                    tag: 0x5f55,
                    value: Value::Alphabetic("US".to_string()),
                },
                Field {
                    tag: 0x42,
                    value: Value::Numeric(440393),
                }
            ])
        }
    )
}

#[test]
fn test_read_tl_empty() {
    assert_eq!(
        super::decoders::read_tl(&b"\x80\x00"[..]).unwrap(),
        (0x80, 0, 2)
    )
}

#[test]
fn test_read_tl_long_tag() {
    assert_eq!(
        super::decoders::read_tl(&b"\x7f\x99\x02\x12\x34"[..]).unwrap(),
        (0x7f99, 2, 3)
    )
}

#[test]
fn test_read_tl_ff_length() {
    assert_eq!(
        super::decoders::read_tl(&b"\x80\x81\xff"[..]).unwrap(),
        (0x80, 0xff, 3)
    )
}

#[test]
fn test_read_tl_lorge() {
    assert_eq!(
        super::decoders::read_tl(&b"\x7f\x99\x84\xff\xff\xff\xff"[..]).unwrap(),
        (0x7f99, 0xffff_ffff, 7)
    )
}
