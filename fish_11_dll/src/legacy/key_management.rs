//! Legacy key management for FiSH 10 compatibility
//!
//! This module provides utilities for managing legacy Blowfish keys
//! and converting between different key formats.

use crate::unified_error::DllError;

/// Set a legacy key for a target
pub fn set_legacy_key(target: &str, key_hex: &str) -> Result<(), DllError> {
    // Decode the hex key
    let key_bytes = hex::decode(key_hex).map_err(|e| DllError::LegacyError {
        context: format!("Setting key for '{}'", target),
        cause: format!("Invalid hex key: {}", e),
    })?;

    // Validate key length
    if key_bytes.len() < 4 || key_bytes.len() > 56 {
        return Err(DllError::LegacyError {
            context: format!("Setting key for '{}'", target),
            cause: format!("Invalid key length: {} bytes (must be 4-56)", key_bytes.len()),
        });
    }

    // Store the key
    let config = super::LEGACY_CONFIG.write();
    let mut keys = config.legacy_keys.write();
    keys.insert(target.to_string(), key_bytes.clone());

    // Save to persistent storage if configured
    if let Some(ini_path) = &config.blowfish_ini_path {
        if let Err(e) = super::config::save_key_to_blowfish_ini(target, &key_bytes, ini_path) {
            log::warn!("Failed to save legacy key to blowfish.ini: {}", e);
        }
    }

    log::info!("Set legacy key for '{}'", target);
    Ok(())
}

/// Remove a legacy key for a target
pub fn remove_legacy_key(target: &str) -> Result<(), DllError> {
    let mut config = super::LEGACY_CONFIG.write();
    let mut keys = config.legacy_keys.write();
    
    if keys.remove(target).is_some() {
        log::info!("Removed legacy key for '{}'", target);
        Ok(())
    } else {
        Err(DllError::LegacyError {
            context: format!("Removing key for '{}'", target),
            cause: "Key not found".to_string(),
        })
    }
}

/// List all legacy keys
pub fn list_legacy_keys() -> Vec<String> {
    let config = super::LEGACY_CONFIG.read();
    let keys = config.legacy_keys.read();
    keys.keys().cloned().collect()
}

/// Check if a legacy key exists for a target
pub fn has_legacy_key(target: &str) -> bool {
    let config = super::LEGACY_CONFIG.read();
    let keys = config.legacy_keys.read();
    keys.contains_key(target)
}

/// Convert a password to a Blowfish key (FiSH 10 style)
pub fn password_to_key(password: &str) -> Vec<u8> {
    // FiSH 10 uses a simple approach: take the first 16 bytes of the SHA-1 hash
    use sha1::{Sha1, Digest};
    
    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();
    
    // Take first 16 bytes (128 bits) for Blowfish
    result[..16].to_vec()
}

/// Generate DH1080 key pair for FiSH 10 key exchange
pub fn generate_dh1080_keypair() -> Result<super::dh1080::DH1080KeyPair, DllError> {
    super::dh1080::generate_dh1080_keypair()
}

/// Compute shared secret using DH1080
pub fn compute_dh1080_shared_secret(
    private_key: &[u8],
    other_public_key: &str,
) -> Result<String, DllError> {
    super::dh1080::compute_dh1080_shared_secret(private_key, other_public_key)
}

/// Parse DH1080 public key
pub fn parse_dh1080_public_key(key_str: &str) -> Result<Vec<u8>, DllError> {
    super::dh1080::parse_dh1080_public_key(key_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy::test_utils::{setup_test_legacy_key, clear_test_legacy_keys};

    #[test]
    fn test_key_management() {
        clear_test_legacy_keys();
        
        // Test setting a key
        assert!(set_legacy_key("#test", "6162636465666768").is_ok());
        assert!(has_legacy_key("#test"));
        
        // Test listing keys
        let keys = list_legacy_keys();
        assert!(keys.contains("#test"));
        
        // Test removing a key
        assert!(remove_legacy_key("#test").is_ok());
        assert!(!has_legacy_key("#test"));
    }

    #[test]
    fn test_password_to_key() {
        let key = password_to_key("testpassword");
        assert_eq!(key.len(), 16); // Should be 16 bytes
    }

    #[test]
    fn test_invalid_key_length() {
        let result = set_legacy_key("#test", "6162"); // Too short
        assert!(result.is_err());
    }
}