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
        let issuer_certificate_be = options
            .get(&0x90)
            .and_then(Value::as_binary)
            .ok_or(VerifyError::MissingTag(0x90))?;
        let issuer_exponent_be = options
            .get(&0x9f32)
            .and_then(Value::as_binary)
            .ok_or(VerifyError::MissingTag(0x9f32))?;
        let issuer_remainder = options
            .get(&0x92)
            .and_then(Value::as_binary)
            .unwrap_or_default();
        let pan = options
            .get(&0x5a)
            .and_then(Value::as_digit_string)
            .ok_or(VerifyError::MissingTag(0x5a))?;

        let ca_key = CA_KEYS
            .get(&KeyId { rid, index })
            .ok_or(VerifyError::UnknownCAKey { rid, index })?;

        // Step 1: Make sure N_CA (number of bytes in the CA key modulus) is the same length as the
        // encrypted issuer certificate
        let ca_modulus_len = (ca_key.modulus.bits_vartime() + 7) / 8;
        if ca_modulus_len != issuer_certificate_be.len() {
            return Err(VerifyError::CertificateLengthMismatch {
                mod_size: ca_modulus_len,
                cert_size: issuer_certificate_be.len(),
            });
        }

        // Step 2: recover the certificate
        let issuer_certificate = certificate_to_bigint(issuer_certificate_be)?;

        // A very annoying way of doing (issuer_certificate ** exponent) % modulus
        // See EMV Book 2 Annex B2.1
        let recovered_arr =
            DynResidue::new(&issuer_certificate, DynResidueParams::new(&ca_key.modulus))
                .pow_bounded_exp(&U2048::from_u32(ca_key.exponent), 32)
                .retrieve()
                .to_be_bytes();

        let recovered = &recovered_arr[256 - ca_modulus_len..];

        // Steps 3-4, 11: Make sure we understand the cert type
        if recovered[0] != 0x6a || recovered[1] != 0x02 || recovered[11] != 1 || recovered[12] != 1
        {
            return Err(VerifyError::InvalidSignature);
        }

        // Steps 5-7: Check the hash
        let mut hasher = Sha1::new();
        hasher.update(&recovered[1..ca_modulus_len - 21]);
        hasher.update(issuer_remainder);
        hasher.update(issuer_exponent_be);
        if hasher.finalize()[..] != recovered[ca_modulus_len - 21..ca_modulus_len - 1] {
            return Err(VerifyError::InvalidSignature);
        }

        // Step 8: Check if PAN matches
        let iin = compressed_numeric(&recovered[2..6]).map_err(|_| VerifyError::UnmatchedPAN)?;
        if !pan.starts_with(&iin) {
            return Err(VerifyError::UnmatchedPAN);
        }

        // Step 9: Check expiry date
        // Don't do this, this program should probably be run on expired cards anyway

        // Step 10: Check CRLs
        // I don't want to and have no idea where to get one anyway

        // Step 11: Format everything and return
        let issuer_modulus_len = usize::from(recovered[13]);

        let issuer_modulus = if issuer_modulus_len <= ca_modulus_len - 36 {
            certificate_to_bigint(&recovered[15..15 + issuer_modulus_len])?
        } else {
            certificate_to_bigint(&recovered[15..ca_modulus_len - 21])?
                << (issuer_remainder.len() * 8)
                | certificate_to_bigint(issuer_remainder)?
        };

        let mut issuer_exponent_be_arr = [0u8; 4];
        if issuer_exponent_be.len() > 4 {
            return Err(VerifyError::InvalidData);
        }
        issuer_exponent_be_arr[4 - issuer_exponent_be.len()..].copy_from_slice(issuer_exponent_be);

        Ok(Self {
            iin,
            expiry: date_ym(&recovered[6..8])?,
            serial_number: recovered[8..11].try_into().unwrap(),
            exponent: u32::from_be_bytes(issuer_exponent_be_arr),
            modulus: issuer_modulus,
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
        let icc_certificate_be = options
            .get(&0x9f46)
            .and_then(Value::as_binary)
            .ok_or(VerifyError::MissingTag(0x9f46))?;
        let icc_exponent_be = options
            .get(&0x9f47)
            .and_then(Value::as_binary)
            .ok_or(VerifyError::MissingTag(0x9f47))?;
        let icc_remainder = options
            .get(&0x9f48)
            .and_then(Value::as_binary)
            .unwrap_or_default();
        let options_pan = options
            .get(&0x5a)
            .and_then(Value::as_digit_string)
            .ok_or(VerifyError::MissingTag(0x5a))?;

        // Step 1: Make sure N_I (number of bytes in the issuer key modulus) is the same length as the
        // encrypted issuer certificate
        let issuer_modulus_len = (issuer_key.modulus.bits_vartime() + 7) / 8;
        if issuer_modulus_len != icc_certificate_be.len() {
            return Err(VerifyError::CertificateLengthMismatch {
                mod_size: issuer_modulus_len,
                cert_size: icc_certificate_be.len(),
            });
        }

        // Step 2: recover the certificate
        let icc_certificate = certificate_to_bigint(icc_certificate_be)?;

        // A very annoying way of doing (issuer_certificate ** exponent) % modulus
        // See EMV Book 2 Annex B2.1
        let recovered_arr =
            DynResidue::new(&icc_certificate, DynResidueParams::new(&issuer_key.modulus))
                .pow_bounded_exp(&U2048::from_u32(issuer_key.exponent), 32)
                .retrieve()
                .to_be_bytes();

        let recovered = &recovered_arr[256 - issuer_modulus_len..];

        debug!("{}", hex::encode(recovered));

        // Steps 3-4, 11: Make sure we understand the cert type
        if recovered[0] != 0x6a || recovered[1] != 0x04 || recovered[17] != 1 || recovered[18] != 1
        {
            return Err(VerifyError::InvalidSignature);
        }

        // Steps 5-7: Check the hash
        let mut hasher = Sha1::new();
        hasher.update(&recovered[1..issuer_modulus_len - 21]);
        hasher.update(icc_remainder);
        hasher.update(icc_exponent_be);
        hasher.update(sda_data);

        // If we called this function we're doing CDA/DDA, in which case only 0x82 (AIP) is allowed
        // We'll have an invalid signature anyway, so just assume that it's only 0x82
        if options.contains_key(&0x9f4a) {
            hasher.update(
                options
                    .get(&0x82)
                    .and_then(Value::as_binary)
                    .unwrap_or_default(),
            )
        }

        if hasher.finalize()[..] != recovered[issuer_modulus_len - 21..issuer_modulus_len - 1] {
            return Err(VerifyError::InvalidSignature);
        }

        // Step 8: Check if PAN matches
        let pan = compressed_numeric(&recovered[2..12]).map_err(|_| VerifyError::UnmatchedPAN)?;
        if pan != options_pan {
            return Err(VerifyError::UnmatchedPAN);
        }

        // Step 9: Check expiry date
        // Don't do this, this program should probably be run on expired cards anyway

        // Step 10: Check CRLs
        // I don't want to and have no idea where to get one anyway

        // Step 11: Format everything and return
        let icc_modulus_len = usize::from(recovered[19]);

        let icc_modulus = if icc_modulus_len <= issuer_modulus_len - 42 {
            certificate_to_bigint(&recovered[21..21 + icc_modulus_len])?
        } else {
            certificate_to_bigint(&recovered[21..issuer_modulus_len - 21])?
                << (icc_remainder.len() * 8)
                | certificate_to_bigint(icc_remainder)?
        };

        let mut icc_exponent_be_arr = [0u8; 4];
        if icc_exponent_be.len() > 4 {
            return Err(VerifyError::InvalidData);
        }
        icc_exponent_be_arr[4 - icc_exponent_be.len()..].copy_from_slice(icc_exponent_be);

        Ok(Self {
            pan,
            expiry: date_ym(&recovered[12..14])?,
            serial_number: recovered[14..17].try_into().unwrap(),
            exponent: u32::from_be_bytes(icc_exponent_be_arr),
            modulus: icc_modulus,
        })
    }
}
