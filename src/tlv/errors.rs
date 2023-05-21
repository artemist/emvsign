use std::error::Error;
use std::fmt::Display;

#[derive(Debug)]
pub enum TLVDecodeError {
    
}

impl Display for TLVDecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match *self {
            
        }
    }
}

impl Error for TLVDecodeError {}
