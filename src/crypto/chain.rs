use chrono::NaiveDate;
use crypto_bigint::U2048;
use log::error;

use super::{KeyId, VerifyError, SYSTEM_KEYS};

fn certificate_to_bigint(certificate: &[u8]) -> Result<U2048, VerifyError> {
    if certificate.len() > 248 {
        return Err(VerifyError::CertificateTooLarge(certificate.len()));
    }

    let mut arr = [0u8; 256];
    (&mut arr[256 - certificate.len()..]).copy_from_slice(certificate);

    Ok(U2048::from_be_slice(&arr))
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
    pub fn from_card_data(
        rid: u64,
        index: u8,
        issuer_certificate_be: &[u8],
        issuer_exponent_be: &[u8],
        issuer_remainder: &[u8],
        pan: &[u8],
    ) -> Result<Self, VerifyError> {
        let system_key = SYSTEM_KEYS
            .get(&KeyId { rid, index })
            .ok_or_else(|| VerifyError::UnknownCAKey { rid, index })?;

        todo!()
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
