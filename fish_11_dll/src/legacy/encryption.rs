//! Legacy encryption utilities for FiSH 10 compatibility
//!
//! This module provides higher-level encryption utilities
//! that wrap the raw Blowfish implementation.

use crate::unified_error::DllError;

/// Encrypt a message using the legacy FiSH 10 format
pub fn legacy_encrypt(target: &str, message: &str) -> Result<String, DllError> {
    // Get the key for this target
    let key = super::get_legacy_key(target).ok_or_else(|| DllError::LegacyError {
        context: format!("Encrypting for '{}'", target),
        cause: "No legacy key found for this target".to_string(),
    })?;

    // Encrypt using Blowfish
    let encrypted = super::blowfish::encrypt_message(&key, message, target.as_bytes())?;

    // Add the legacy +OK prefix
    Ok(format!("+OK {}", encrypted))
}

/// Decrypt a legacy FiSH 10 message
pub fn legacy_decrypt(target: &str, encrypted_message: &str) -> Result<String, DllError> {
    // Strip the +OK prefix if present
    let mut ciphertext = encrypted_message.trim();
    if let Some(stripped) = ciphertext.strip_prefix("+OK ") {
        ciphertext = stripped;
    }

    // Get the key for this target
    let key = super::get_legacy_key(target).ok_or_else(|| DllError::LegacyError {
        context: format!("Decrypting for '{}'", target),
        cause: "No legacy key found for this target".to_string(),
    })?;

    // Decrypt using Blowfish
    super::blowfish::decrypt_message(&key, ciphertext, target.as_bytes())
}

/// Check if a message appears to be in legacy FiSH 10 format
pub fn is_legacy_message(message: &str) -> bool {
    message.trim().starts_with("+OK ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy::test_utils::setup_test_legacy_key;

    #[test]
    fn test_legacy_format_detection() {
        assert!(is_legacy_message("+OK abc123"));
        assert!(!is_legacy_message("Hello world"));
        assert!(!is_legacy_message("+FISH abc123"));
    }

    #[test]
    fn test_legacy_encryption_format() {
        setup_test_legacy_key("#test", b"testkey12345678");
        
        let result = legacy_encrypt("#test", "Hello");
        assert!(result.is_ok());
        let encrypted = result.unwrap();
        assert!(encrypted.starts_with("+OK "));
    }
}