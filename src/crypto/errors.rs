use std::{error::Error, fmt::Display};

#[derive(Debug, PartialEq, Copy, Clone)]
pub enum VerifyError {
    UnknownCAKey { rid: u64, index: u8 },
    CertificateTooLarge(usize),
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
        }
    }
}

impl Error for VerifyError {}
