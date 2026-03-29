//! Legacy encryption utilities for FiSH 10 compatibility
//!
//! This module provides higher-level encryption utilities
//! that wrap the raw Blowfish implementation.

use crate::unified_error::DllError;
use crate::crypto::blowfish;

/// Encryption mode for FiSH messages
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum FishEncryptionMode {
    /// ECB mode (default for FiSH 10) - marked with +OK prefix
    Ecb,
    /// CBC mode (more secure) - marked with mcps prefix
    Cbc,
}

/// Encrypt a message using the legacy FiSH 10 format
pub fn legacy_encrypt(target: &str, message: &str) -> Result<String, DllError> {
    legacy_encrypt_with_mode(target, message, FishEncryptionMode::Ecb)
}

/// Encrypt a message using specified mode
pub fn legacy_encrypt_with_mode(
    target: &str,
    message: &str,
    mode: FishEncryptionMode,
) -> Result<String, DllError> {
    // Get the key for this target
    let key = super::get_legacy_key(target).ok_or_else(|| DllError::LegacyError {
        context: format!("Encrypting for '{}'", target),
        cause: "No legacy key found for this target".to_string(),
    })?;

    match mode {
        FishEncryptionMode::Ecb => {
            // Encrypt using Blowfish ECB
            let encrypted = blowfish::encrypt_message(&key, message, target.as_bytes())?;
            // Add the legacy +OK prefix
            Ok(format!("+OK {}", encrypted))
        }
        FishEncryptionMode::Cbc => {
            // Encrypt using Blowfish CBC
            let encrypted = blowfish::encrypt_message_cbc(&key, message, target.as_bytes())?;
            // Add the legacy mcps prefix
            Ok(format!("mcps {}", encrypted))
        }
    }
}

/// Decrypt a legacy FiSH 10 message
pub fn legacy_decrypt(target: &str, encrypted_message: &str) -> Result<String, DllError> {
    let trimmed = encrypted_message.trim();

    // Detect encryption mode based on prefix
    let (ciphertext, mode) = if let Some(stripped) = trimmed.strip_prefix("+OK ") {
        (stripped, FishEncryptionMode::Ecb)
    } else if let Some(stripped) = trimmed.strip_prefix("mcps ") {
        (stripped, FishEncryptionMode::Cbc)
    } else {
        // No recognized prefix - assume ECB mode
        (trimmed, FishEncryptionMode::Ecb)
    };

    // Get the key for this target
    let key = super::get_legacy_key(target).ok_or_else(|| DllError::LegacyError {
        context: format!("Decrypting for '{}'", target),
        cause: "No legacy key found for this target".to_string(),
    })?;

    match mode {
        FishEncryptionMode::Ecb => {
            // Decrypt using Blowfish ECB
            blowfish::decrypt_message(&key, ciphertext, target.as_bytes())
        }
        FishEncryptionMode::Cbc => {
            // Decrypt using Blowfish CBC
            blowfish::decrypt_message_cbc(&key, ciphertext, target.as_bytes())
        }
    }
}

/// Check if a message appears to be in legacy FiSH 10 format
pub fn is_legacy_message(message: &str) -> bool {
    let trimmed = message.trim();
    trimmed.starts_with("+OK ") || trimmed.starts_with("mcps ")
}

/// Encrypt a topic using the legacy FiSH 10 format
pub fn legacy_encrypt_topic(target: &str, topic: &str) -> Result<String, DllError> {
    legacy_encrypt_with_mode(target, topic, FishEncryptionMode::Ecb)
}

/// Encrypt a topic using the legacy FiSH 10 format with CBC mode
pub fn legacy_encrypt_topic_cbc(target: &str, topic: &str) -> Result<String, DllError> {
    legacy_encrypt_with_mode(target, topic, FishEncryptionMode::Cbc)
}

/// Decrypt a legacy FiSH 10 topic
pub fn legacy_decrypt_topic(target: &str, encrypted_topic: &str) -> Result<String, DllError> {
    let trimmed = encrypted_topic.trim();

    // Detect encryption mode based on prefix
    let (ciphertext, mode) = if let Some(stripped) = trimmed.strip_prefix("+OK ") {
        (stripped, FishEncryptionMode::Ecb)
    } else if let Some(stripped) = trimmed.strip_prefix("mcps ") {
        (stripped, FishEncryptionMode::Cbc)
    } else {
        // No recognized prefix - assume ECB mode
        (trimmed, FishEncryptionMode::Ecb)
    };

    // Get the key for this target
    let key = super::get_legacy_key(target).ok_or_else(|| DllError::LegacyError {
        context: format!("Decrypting topic for '{}'", target),
        cause: "No legacy key found for this target".to_string(),
    })?;

    match mode {
        FishEncryptionMode::Ecb => {
            // Decrypt using Blowfish ECB

            blowfish::decrypt_message(&key, ciphertext, target.as_bytes())
        }
        FishEncryptionMode::Cbc => {
            // Decrypt using Blowfish CBC
            blowfish::decrypt_message_cbc(&key, ciphertext, target.as_bytes())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy::test_utils::setup_test_legacy_key;

    #[test]
    fn test_legacy_format_detection() {
        // ECB mode detection
        assert!(is_legacy_message("+OK abc123"));
        // CBC mode detection
        assert!(is_legacy_message("mcps abc123"));
        // Not a FiSH message
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

    #[test]
    fn test_legacy_topic_encryption() {
        setup_test_legacy_key("#test", b"testkey12345678");

        let topic = "This is a test topic";
        let result = legacy_encrypt_topic("#test", topic);
        assert!(result.is_ok());
        let encrypted = result.unwrap();
        assert!(encrypted.starts_with("+OK "));

        // Test decryption
        let decrypted_result = legacy_decrypt_topic("#test", &encrypted);
        assert!(decrypted_result.is_ok());
        let decrypted = decrypted_result.unwrap();
        assert_eq!(decrypted, topic);
    }

    #[test]
    fn test_legacy_topic_encryption_no_key() {
        // Test encryption without a key
        let result = legacy_encrypt_topic("#nonexistent", "test topic");
        assert!(result.is_err());

        // Test decryption without a key
        let result = legacy_decrypt_topic("#nonexistent", "+OK someencrypteddata");
        assert!(result.is_err());
    }

    #[test]
    fn test_legacy_cbc_encryption() {
        setup_test_legacy_key("#test", b"testkey12345678");

        let message = "This is a test message for CBC mode";
        let result = legacy_encrypt_with_mode("#test", message, FishEncryptionMode::Cbc);
        assert!(result.is_ok());
        let encrypted = result.unwrap();
        assert!(encrypted.starts_with("mcps "));

        // Test decryption
        let decrypted_result = legacy_decrypt("#test", &encrypted);
        assert!(decrypted_result.is_ok());
        let decrypted = decrypted_result.unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_legacy_cbc_topic_encryption() {
        setup_test_legacy_key("#test", b"testkey12345678");

        let topic = "This is a test topic for CBC mode";
        let result = crate::legacy::fish10_encryption::legacy_encrypt_topic_cbc("#test", topic);
        assert!(result.is_ok());
        let encrypted = result.unwrap();
        assert!(encrypted.starts_with("mcps "));

        // Test decryption
        let decrypted_result = legacy_decrypt_topic("#test", &encrypted);
        assert!(decrypted_result.is_ok());
        let decrypted = decrypted_result.unwrap();
        assert_eq!(decrypted, topic);
    }

    #[test]
    fn test_cbc_mode_detection() {
        setup_test_legacy_key("#test", b"testkey12345678");

        // Test that CBC mode is properly detected and decrypted
        let message = "CBC test message";
        let encrypted = format!("mcps {}", blowfish::encrypt_message_cbc(b"testkey12345678", message, &[]).unwrap());
        let result = legacy_decrypt("#test", &encrypted);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), message);
    }
}
