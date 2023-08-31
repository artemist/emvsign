use chrono::NaiveDate;
use crypto_bigint::modular::runtime_mod::DynResidue;
use crypto_bigint::modular::runtime_mod::DynResidueParams;
use crypto_bigint::prelude::*;
use crypto_bigint::U2048;

use log::debug;
use sha1::Digest;
use sha1::Sha1;

use crate::tlv::decoders::compressed_numeric;
use crate::tlv::decoders::numeric;
use crate::tlv::FieldMap;
use crate::tlv::Value;
use crate::util::left_pad_slice;

use super::{KeyId, VerifyError, CA_KEYS};

fn certificate_to_bigint(certificate: &[u8]) -> Result<U2048, VerifyError> {
    if certificate.len() > 248 {
        return Err(VerifyError::CertificateTooLarge(certificate.len()));
    }

    let mut arr = [0u8; 256];
    arr[256 - certificate.len()..].copy_from_slice(certificate);

    Ok(U2048::from_be_slice(&arr))
}

fn date_ym(mmyy: &[u8]) -> Result<NaiveDate, VerifyError> {
    let mut year = 2000 + numeric(&mmyy[1..2]).map_err(|_| VerifyError::InvalidData)?;
    let mut month = numeric(&mmyy[0..1]).map_err(|_| VerifyError::InvalidData)?;
    if month == 12 {
        year += 1;
        month = 1;
    }
    NaiveDate::from_ymd_opt(year as i32, month as u32, 1)
        .and_then(|date| date.pred_opt())
        .ok_or(VerifyError::InvalidData)
}

fn parse_certificate(
    is_icc: bool,
    parent_modulus: U2048,
    parent_exponent: u32,
    options: &FieldMap,
    extra_signed_data: &[u8],
) -> Result<(Vec<u8>, NaiveDate, [u8; 3], u32, U2048), VerifyError> {
    let (child_certificate_tag, child_exponent_tag, child_remainder_tag) = if !is_icc {
        (0x90, 0x9f32, 0x92)
    } else {
        (0x9f46, 0x9f47, 0x9f48)
    };
    let child_certificate_slice = options
        .get(&child_certificate_tag)
        .and_then(Value::as_binary)
        .ok_or(VerifyError::MissingTag(child_certificate_tag))?;
    let child_exponent_slice = options
        .get(&child_exponent_tag)
        .and_then(Value::as_binary)
        .ok_or(VerifyError::MissingTag(child_exponent_tag))?;
    let child_remainder = options
        .get(&child_remainder_tag)
        .and_then(Value::as_binary)
        .unwrap_or_default();
    let pan = options
        .get(&0x5a)
        .and_then(Value::as_digit_string)
        .ok_or(VerifyError::MissingTag(0x5a))?;

    // For the issuer public key we just have the IIN (start of the PAN)
    let pan_len = if is_icc { 10 } else { 4 };

    // Step 1: Make sure the parent modulus is the same length as the encrypted child certificate
    // This will also be the length of the recovered data
    let recovered_len = (parent_modulus.bits_vartime() + 7) / 8;
    if recovered_len != child_certificate_slice.len() {
        return Err(VerifyError::CertificateLengthMismatch {
            mod_size: recovered_len,
            cert_size: child_certificate_slice.len(),
        });
    }

    // Step 2: recover the certificate
    let child_certificate = certificate_to_bigint(child_certificate_slice)?;

    // A very annoying way of doing (issuer_certificate ** exponent) % modulus
    // See EMV Book 2 Annex B2.1
    let recovered_arr = DynResidue::new(&child_certificate, DynResidueParams::new(&parent_modulus))
        .pow_bounded_exp(&U2048::from_u32(parent_exponent), 32)
        .retrieve()
        .to_be_bytes();

    let recovered = &recovered_arr[256 - recovered_len..];

    debug!("Recovered {}", hex::encode(recovered));

    // Steps 3-4, 11: Make sure we understand the cert type
    if !is_icc
        && (recovered[0] != 0x6a
            || recovered[1] != 0x02
            || recovered[11] != 0x01
            || recovered[12] != 0x01)
        || is_icc
            && (recovered[0] != 0x6a
                || recovered[1] != 0x04
                || recovered[17] != 0x01
                || recovered[18] != 0x01)
    {
        return Err(VerifyError::InvalidSignature);
    }

    // Steps 5-7: Check the hash
    let mut hasher = Sha1::new();
    hasher.update(&recovered[1..recovered_len - 21]);
    hasher.update(child_remainder);
    hasher.update(child_exponent_slice);
    hasher.update(extra_signed_data);
    // If is_icc is true then we're doing CDA/DDA, in which case only 0x82 (AIP) is allowed
    // If this isn't true then we'll have an invalid signature anyway, so just assume that it's only 0x82
    if is_icc && options.contains_key(&0x9f4a) {
        hasher.update(
            options
                .get(&0x82)
                .and_then(Value::as_binary)
                .unwrap_or_default(),
        )
    }
    if hasher.finalize()[..] != recovered[recovered_len - 21..recovered_len - 1] {
        return Err(VerifyError::InvalidSignature);
    }

    // Step 8: Check if PAN matches
    let cert_pan =
        compressed_numeric(&recovered[2..2 + pan_len]).map_err(|_| VerifyError::UnmatchedPAN)?;
    if is_icc && cert_pan != pan || !is_icc && !pan.starts_with(&cert_pan) {
        return Err(VerifyError::UnmatchedPAN);
    }

    // Step 9: Check expiry date
    // Don't do this, this program should probably be run on expired cards anyway

    // Step 10: Check CRLs
    // I don't want to and have no idea where to get one anyway

    // Step 11: Format everything and return
    let child_modulus_len = usize::from(recovered[9 + pan_len]);

    let child_modulus_len = if child_modulus_len <= recovered_len - 32 - pan_len {
        certificate_to_bigint(&recovered[11 + pan_len..11 + pan_len + child_modulus_len])?
    } else {
        certificate_to_bigint(&recovered[11 + pan_len..recovered_len - 21])?
            << (child_remainder.len() * 8)
            | certificate_to_bigint(child_remainder)?
    };

    if child_exponent_slice.len() > 4 {
        return Err(VerifyError::InvalidData);
    }

    Ok((
        cert_pan,
        date_ym(&recovered[2 + pan_len..4 + pan_len])?,
        recovered[4 + pan_len..7 + pan_len].try_into().unwrap(),
        u32::from_be_bytes(left_pad_slice(child_exponent_slice)),
        child_modulus_len,
    ))
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct IssuerPublicKey {
    pub iin: Vec<u8>,
    pub expiry: NaiveDate,
    pub serial_number: [u8; 3],
    pub exponent: u32,
    pub modulus: U2048,
}

impl IssuerPublicKey {
    pub fn from_options(rid: [u8; 5], options: &FieldMap) -> Result<Self, VerifyError> {
        let index = options
            .get(&0x8f)
            .and_then(Value::as_binary)
            .and_then(|b| b.first().cloned())
            .ok_or(VerifyError::MissingTag(0x8f))?;

        let ca_key = CA_KEYS
            .get(&KeyId { rid, index })
            .ok_or(VerifyError::UnknownCAKey { rid, index })?;

        let (iin, expiry, serial_number, exponent, modulus) =
            parse_certificate(false, ca_key.modulus, ca_key.exponent, options, &[])?;

        Ok(Self {
            iin,
            expiry,
            serial_number,
            exponent,
            modulus,
        })
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct ICCPublicKey {
    pub pan: Vec<u8>,
    pub expiry: NaiveDate,
    pub serial_number: [u8; 3],
    pub exponent: u32,
    pub modulus: U2048,
}

impl ICCPublicKey {
    pub fn from_options(
        issuer_key: &IssuerPublicKey,
        sda_data: &[u8],
        options: &FieldMap,
    ) -> Result<Self, VerifyError> {
        let (pan, expiry, serial_number, exponent, modulus) = parse_certificate(
            true,
            issuer_key.modulus,
            issuer_key.exponent,
            options,
            sda_data,
        )?;

        Ok(Self {
            pan,
            expiry,
            serial_number,
            exponent,
            modulus,
        })
    }
}
