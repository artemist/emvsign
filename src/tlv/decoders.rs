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

use super::{TLVValue, TLVDecodeError};
use super::elements::ELEMENTS;

/// Decode the tag and length of a TLV string. This is only useful in template,
/// as it will use this to cut down the data to the proper size.
fn read_tl(raw: &[u8]) -> Result<(u16, usize, usize), TLVDecodeError> {
    // Tag + length is always at least 2 bytes
    if raw.len() < 2 {
        return Err(TLVDecodeError::TooShort(2, raw.len()));
    }

    // If the bottom 5 bits are set this is supposed to be a 2 byte tag
    let (tag, tag_len) = if raw[0] & 0x1f == 0x1f {
        (u16::from_be_bytes(raw[..2].try_into().unwrap()), 2)
    } else {
        (raw[0] as u16, 1)
    };

    // Length is always at least 1 byte
    if raw.len() < tag_len + 1 {
        return Err(TLVDecodeError::TooShort(3, raw.len()));
    }

    // If the high bit of the first byte is set then it encodes how many bytes follow
    let (len, len_len) = if raw[tag_len] & 0x80 == 0x80 {
        let num_bytes = (raw[tag_len] & 0x7f) as usize;
        // This is valid to encode but we could theoretically be running on a 32 bit system
        // and would be very surprised if a credit card needed to send more than 4GiB of data.
        if num_bytes > 4 {
            return Err(TLVDecodeError::TooLong(4, num_bytes));
        }

        // tag_len bytes for the tag, 1 byte for the number of length bytes, then num_bytes bytes
        // for the length. There _should_ be more bytes after but this could be 0 length if someone
        // messed up
        if raw.len() < tag_len + 1 + num_bytes {
            return Err(TLVDecodeError::TooShort(tag_len + 1 + num_bytes, raw.len()));
        }

        let mut len = 0usize;
        for b in &raw[tag_len+1..tag_len+1+num_bytes] {
            len = (len << 8) | (*b as usize);
        }
        (len, num_bytes + 1)
    } else {
        (raw[tag_len] as usize, 1)
    };

    Ok((tag, len, tag_len + len_len))
}


pub fn read_tlv(raw: &[u8]) -> Result<(u16, usize, TLVValue), TLVDecodeError> {
    let (tag, len, tl_len) = read_tl(raw)?;
    if let Some(ref data_element) = ELEMENTS.get(&tag) {
        match (data_element.decoder)(&raw[tl_len..]) {
            Ok(value) => Ok((tag, tl_len + len, value)),
            Err(err) => Err(TLVDecodeError::TemplateInternal(tag, Box::new(err)))
        }
    } else {
        Err(TLVDecodeError::UnknownTag(tag))
    }
}



pub(super) fn alphabetic(raw: &[u8]) -> Result<TLVValue, TLVDecodeError> {
    unimplemented!()
}

pub(super) fn alphanumeric(raw: &[u8]) -> Result<TLVValue, TLVDecodeError> {
    unimplemented!()
}

pub(super) fn alphanumeric_special(raw: &[u8]) -> Result<TLVValue, TLVDecodeError> {
    unimplemented!()
}

pub(super) fn binary(raw: &[u8]) -> Result<TLVValue, TLVDecodeError> {
    Ok(TLVValue::Binary(raw.to_vec()))
}

pub(super) fn compressed_numeric(raw: &[u8]) -> Result<TLVValue, TLVDecodeError> {
    unimplemented!()
}

pub(super) fn numeric(raw: &[u8]) -> Result<TLVValue, TLVDecodeError> {
    unimplemented!()
}

pub(super) fn template(raw: &[u8]) -> Result<TLVValue, TLVDecodeError> {
    // This template could be empty, so no need to error
    if raw.len() == 0 {
        return Ok(TLVValue::Template(Vec::new()));
    }

    let mut offset = 0;
    let mut fields = Vec::new();
    while offset < raw.len() {
        let (tag, len, value) = read_tlv(&raw[offset..])?;
        offset += len;
        fields.push((tag, value));
    }
    Ok(TLVValue::Template(fields))
}
