use super::dol::Dol;
use super::elements::{ElementType, ELEMENTS};
/// Decode what EMV calls "BER-TLV"
/// This is a TLV (Tag, Length, Value) format where
///  * The tag is 1 or 2 bytes and represents the interpretation of the data, not just the type
///  * The length is at least 1 byte, though we cap it to 32 bits of data (encoded as 5 bytes)
///  * The value is some type of string, number, or binary data encoded according to EMV types
///
/// This isn't actually quite BER-TLV because BER and DER encode types in the tag and you're
/// supposed to use an ASN.1 IDL file to figure out what the fields mean
///
/// For more information read EMV 4.4 Book 3 annex B1 and then cry.
use super::{errors, DecodeError, Field, Value};

use std::str;

fn left_pad_slice<const LEN: usize>(slice: &[u8]) -> [u8; LEN] {
    let mut s = [0; LEN];
    s[LEN - slice.len()..].copy_from_slice(slice);
    s
}

/// Decode the tag and length of a TLV string. This is only useful in template,
/// as it will use this to cut down the data to the proper size.
pub fn read_tl(raw: &[u8]) -> Result<(u16, usize, usize), DecodeError> {
    if raw.is_empty() {
        // Tag + length is always at least 2 bytes
        return Err(DecodeError::MessageTooShort(2, raw.len()));
    }

    // If the bottom 5 bits are set this is supposed to be a 2 byte tag
    let tag_len = if raw[0] & 0b11111 == 0b11111 { 2 } else { 1 };

    // Length is always at least 1 byte
    if raw.len() < tag_len + 1 {
        return Err(DecodeError::MessageTooShort(tag_len + 1, raw.len()));
    }

    let (tag_bytes, length_bytes) = raw.split_at(tag_len);

    let (len, len_len) = match length_bytes {
        // Checked above
        [] => unreachable!(),
        [len_len_byte, length_bytes @ ..] if len_len_byte & 0x80 == 0x80 => {
            let num_bytes = (len_len_byte & 0x7f) as usize;
            // This is valid to encode but we could theoretically be running on a 32 bit system
            // and would be very surprised if a credit card needed to send more than 4GiB of data.
            if num_bytes > 4 {
                return Err(DecodeError::LengthTooLong(4, num_bytes));
            }

            // tag_len bytes for the tag, 1 byte for the number of length bytes, then num_bytes bytes
            // for the length. There _should_ be more bytes after but this could be 0 length if someone
            // messed up
            if length_bytes.len() < num_bytes {
                return Err(DecodeError::MessageTooShort(
                    tag_len + 1 + num_bytes,
                    raw.len(),
                ));
            }

            let len = usize::from_be_bytes(left_pad_slice(&length_bytes[..num_bytes]));
            (len, num_bytes + 1)
        }
        [length, ..] => (*length as usize, 1),
    };

    let tag = u16::from_be_bytes(left_pad_slice(tag_bytes));
    Ok((tag, len, tag_len + len_len))
}

fn decode_with_type(typ: ElementType, raw: &[u8]) -> Result<Value, DecodeError> {
    match typ {
        ElementType::Alphabetic => alphabetic(raw).map(Value::Alphabetic),
        ElementType::Alphanumeric => alphanumeric(raw).map(Value::Alphanumeric),
        ElementType::AlphanumericSpecial => {
            alphanumeric_special(raw).map(Value::AlphanumericSpecial)
        }
        ElementType::Binary => binary(raw).map(Value::Binary),
        ElementType::DigitString => compressed_numeric(raw).map(Value::DigitString),
        ElementType::Numeric => numeric(raw).map(Value::Numeric),
        ElementType::Template => template(raw).map(Value::Template),
        ElementType::Dol => dol(raw).map(Value::Dol),
    }
}

fn read_tlv(raw: &[u8]) -> Result<(u16, usize, Value), DecodeError> {
    let (tag, len, tl_len) = read_tl(raw)?;
    let typ = ELEMENTS
        .get(&tag)
        .map(|&elem| elem.typ)
        .unwrap_or(ElementType::Binary);
    let value = decode_with_type(typ, &raw[tl_len..][..len])
        .map_err(|err| DecodeError::TemplateInternal(tag, Box::new(err)))?;
    Ok((tag, tl_len + len, value))
}

pub fn read_field(raw: &[u8]) -> Result<Field, DecodeError> {
    let (tag, _, value) = read_tlv(raw)?;
    Ok(Field { tag, value })
}

fn restricted_charset(
    raw: &[u8],
    predicate: impl Fn(&u8) -> bool,
    string_type: crate::tlv::errors::StringType,
) -> Result<String, DecodeError> {
    if let Some(&bad_char) = raw.iter().find(|&b| !predicate(b)) {
        Err(DecodeError::UnsupportedChar(string_type, bad_char))
    } else {
        Ok(str::from_utf8(raw).unwrap().to_owned())
    }
}

pub fn alphabetic(raw: &[u8]) -> Result<String, DecodeError> {
    restricted_charset(raw, u8::is_ascii_alphabetic, errors::StringType::Alphabetic)
}

pub fn alphanumeric(raw: &[u8]) -> Result<String, DecodeError> {
    restricted_charset(
        raw,
        u8::is_ascii_alphanumeric,
        errors::StringType::Alphanumeric,
    )
}

pub fn alphanumeric_special(raw: &[u8]) -> Result<String, DecodeError> {
    let mut s = String::with_capacity(raw.len());
    for &b in raw {
        // I don't even care anymore.
        // The specification states that this must be under 0x7f... unless it is the
        // Application Preferred Name and the card includes an Issuer Code Table Index
        // value somewhere, which specifies which ISO 8859 codepage (e.g. latin-1) to use.
        // This doesn't even apply to the user name.
        // I expected more from France, and I barely expect anything from France.
        // The amount of state required to propery convert that to Unicode would be terrible
        // so I won't do it unless someone sends me a card that does so.
        if b < 0x20 || b == 0x7f {
            return Err(DecodeError::UnsupportedChar(
                crate::tlv::errors::StringType::AlphanumericSpecial,
                b,
            ));
        }
        s.push(b as char);
    }
    Ok(s)
}

pub fn binary(raw: &[u8]) -> Result<Vec<u8>, DecodeError> {
    Ok(raw.to_vec())
}

pub fn compressed_numeric(raw: &[u8]) -> Result<Vec<u8>, DecodeError> {
    if raw.len() > 10 {
        return Err(DecodeError::LengthTooLong(10, raw.len()));
    }

    let mut s = Vec::with_capacity(raw.len() * 2);

    for digit in raw
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .take_while(|&digit| digit != 0x0f)
    {
        if digit < 10 {
            s.push(digit);
        } else {
            return Err(DecodeError::BadBcd(digit));
        }
    }

    Ok(s)
}

pub fn numeric(raw: &[u8]) -> Result<u128, DecodeError> {
    Ok(raw
        .iter()
        .flat_map(|byte| [byte >> 4, byte & 0x0f])
        .try_fold(0, |acc, digit| {
            if digit <= 9 {
                Ok(acc * 10 + digit as u128) //TODO handle overflow
            } else {
                Err(DecodeError::BadBcd(digit))
            }
        })?)
}

pub fn template(mut raw: &[u8]) -> Result<Vec<Field>, DecodeError> {
    let mut fields = Vec::new();
    while !raw.is_empty() {
        let (tag, len, value) = read_tlv(raw)?;
        raw = &raw[len..];
        fields.push(Field { tag, value });
    }
    Ok(fields)
}

pub fn dol(raw: &[u8]) -> Result<Dol, DecodeError> {
    Dol::try_from(raw)
}
