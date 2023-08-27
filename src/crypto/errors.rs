use std::{error::Error, fmt::Display};

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum VerifyError {
    UnknownCAKey { rid: u64, index: u8 },
    CertificateTooLarge(usize),
    CertificateLengthMismatch { mod_size: usize, cert_size: usize },
    InvalidSignature,
    InvalidData,
    UnmatchedPAN,
}

impl Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::UnknownCAKey { rid, index } => write!(
                f,
                "Unknown CA key with RID {:#06x} and index {:#02x}",
                rid, index
            ),
            VerifyError::CertificateTooLarge(size) => {
                write!(f, "Certificate was {} bytes, max 248", size)
            }
            VerifyError::InvalidSignature => write!(f, "Signature was invalid"),
            VerifyError::CertificateLengthMismatch {
                mod_size,
                cert_size,
            } => write!(
                f,
                "Key is {} bytes, but certificate is {} bytes",
                mod_size, cert_size
            ),
            VerifyError::UnmatchedPAN => write!(f, "PAN on card does not match certificate"),
            VerifyError::InvalidData => {
                write!(f, "Signature validated, but internal data nonsensical")
            }
        }
    }
}

impl Error for VerifyError {}
