//! Key derivation utilities
//!
//! This module provides common functions for deriving cryptographic keys from various inputs
//! such as passwords or plain text strings.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::unified_error::{DllError, DllResult};

/// Derives a 32-byte cryptographic key from password/short key material using HKDF
pub fn derive_key_from_password(password: &str) -> DllResult<[u8; 32]> {
    // Use a salt to prevent rainbow table attacks
    let salt = b"FiSH11-DerivedKey";

    // Use the password as IKM (input key material)
    let ikm = password.as_bytes();

    // Derive a 32-byte key using HKDF-SHA256
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut output = [0u8; 32];

    hkdf.expand(b"key-expansion", &mut output).map_err(|e| DllError::InvalidInput {
        param: "password".to_string(),
        reason: format!("HKDF key derivation failed: {}", e),
    })?;

    Ok(output)
}

/// Converts plain text to a key suitable for legacy systems (4-56 bytes)
/// Uses SHA-256 hashing and truncates to a valid Blowfish key length
pub fn text_to_legacy_key(text: &str) -> Vec<u8> {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    hasher.update(text.as_bytes());
    let result = hasher.finalize();

    // Truncate to 32 bytes (256 bits) which is within the 4-56 byte range for Blowfish
    result[..32].to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_key_from_password() {
        let key = derive_key_from_password("testpassword");
        assert!(key.is_ok());
        assert_eq!(key.unwrap().len(), 32);
    }

    #[test]
    fn test_text_to_legacy_key() {
        let key = text_to_legacy_key("testpassword");
        assert_eq!(key.len(), 32); // 32 bytes is within the 4-56 byte range for Blowfish
    }

    #[test]
    fn test_different_inputs_produce_different_keys() {
        let key1 = text_to_legacy_key("password1");
        let key2 = text_to_legacy_key("password2");
        assert_ne!(key1, key2);
    }
}
