//! Error handling for FiSH 11

use std::error::Error;
use std::{fmt, io};

use base64;

#[derive(Debug)]
pub enum FishError {
    ConfigError(String),
    CryptoError(String),
    IoError(io::Error),
    InvalidInput(String),
    KeyNotFound(String),
    DuplicateEntry(String),
    InvalidNetworkName(String),
    MalformedEntry(String),
    InvalidKeyLength(usize),
    Base64Error(base64::DecodeError),
    NullByteInString,
    NonAsciiCharacter(char),
    // New security-specific errors
    AuthenticationFailed,
    NonceReuse,
    OversizedMessage,
    InvalidCiphertext,
    KeyExpired(String),
}

impl From<base64::DecodeError> for FishError {
    fn from(err: base64::DecodeError) -> Self {
        FishError::ConfigError(format!("Base64 decode error: {}", err))
    }
}

impl fmt::Display for FishError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            FishError::ConfigError(msg) => write!(f, "Configuration error: {}", msg),
            FishError::CryptoError(msg) => write!(f, "Cryptography error: {}", msg),
            FishError::IoError(e) => write!(f, "IO error: {}", e),
            FishError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            FishError::KeyNotFound(nick) => write!(f, "Key not found for nickname: {}", nick),
            FishError::DuplicateEntry(nick) => write!(f, "Entry '{}' already exists", nick),
            FishError::InvalidNetworkName(name) => {
                write!(f, "Invalid network name '{}' (contains forbidden characters)", name)
            }
            FishError::MalformedEntry(entry) => write!(f, "Malformed entry key: '{}'", entry),
            FishError::InvalidKeyLength(len) => {
                write!(f, "Invalid key length: {} (expected 32 bytes)", len)
            }
            FishError::AuthenticationFailed => write!(f, "Message authentication failed"),
            FishError::NonceReuse => write!(f, "Nonce reuse detected"),
            FishError::OversizedMessage => write!(f, "Message exceeds maximum allowed size"),
            FishError::InvalidCiphertext => write!(f, "Invalid ciphertext format or size"),
            FishError::KeyExpired(nick) => write!(f, "Key expired for nickname: {}", nick),
            FishError::Base64Error(e) => write!(f, "Base64 decoding error: {}", e),
            FishError::NullByteInString => write!(f, "String contains null byte"),
            FishError::NonAsciiCharacter(c) => {
                write!(f, "String contains non-ASCII character: '{}'", c)
            }
        }
    }
}

impl Error for FishError {}

impl From<std::io::Error> for FishError {
    fn from(err: std::io::Error) -> Self {
        FishError::IoError(err)
    }
}

pub type Result<T> = std::result::Result<T, FishError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_display_for_fish_errors() {
        // Tests that the Display trait is correctly implemented for FishError variants.
        assert_eq!(
            FishError::ConfigError("test message".to_string()).to_string(),
            "Configuration error: test message"
        );
        assert_eq!(
            FishError::CryptoError("crypto issue".to_string()).to_string(),
            "Cryptography error: crypto issue"
        );
        assert_eq!(
            FishError::KeyNotFound("my_nick".to_string()).to_string(),
            "Key not found for nickname: my_nick"
        );
        assert_eq!(
            FishError::DuplicateEntry("my_nick".to_string()).to_string(),
            "Entry 'my_nick' already exists"
        );
        assert_eq!(
            FishError::InvalidKeyLength(16).to_string(),
            "Invalid key length: 16 (expected 32 bytes)"
        );
        assert_eq!(FishError::AuthenticationFailed.to_string(), "Message authentication failed");
        assert_eq!(FishError::NonceReuse.to_string(), "Nonce reuse detected");
        assert_eq!(FishError::NullByteInString.to_string(), "String contains null byte");
        assert_eq!(
            FishError::NonAsciiCharacter('é').to_string(),
            "String contains non-ASCII character: 'é'"
        );
    }
}
