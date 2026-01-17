//! Legacy key management for FiSH 10 compatibility
//!
//! This module provides utilities for managing legacy Blowfish keys
//! and converting between different key formats.

use crate::unified_error::DllError;
use crate::crypto::dh1080;
use std::sync::Arc;

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

    let (keys_arc, ini_path) = {
        let config = super::LEGACY_CONFIG.read();
        (Arc::clone(&config.legacy_keys), config.blowfish_ini_path.clone())
    };

    // Store the key in memory
    {
        let mut keys = keys_arc.write();
        keys.insert(target.to_string(), key_bytes.clone());
    }

    // Save to persistent storage if configured
    if let Some(path) = ini_path {
        if let Err(e) = super::fish10_config::save_key_to_blowfish_ini(target, &key_bytes, &path) {
            log::warn!("Failed to save legacy key to blowfish.ini: {}", e);
        }
    }

    log::info!("Set legacy key for '{}'", target);
    Ok(())
}

/// Remove a legacy key for a target
pub fn remove_legacy_key(target: &str) -> Result<(), DllError> {
    let (keys_arc, ini_path) = {
        let config = super::LEGACY_CONFIG.read();
        (Arc::clone(&config.legacy_keys), config.blowfish_ini_path.clone())
    };
    
    // First remove from memory
    let removed_from_memory = {
        let mut keys = keys_arc.write();
        keys.remove(target).is_some()
    };

    // Then remove from file if path is set
    if let Some(path) = &ini_path {
        if let Err(e) = super::fish10_config::remove_key_from_blowfish_ini(target, path) {
            log::warn!("LEGACY: Failed to remove key from blowfish.ini: {}", e);
        }
    }

    if removed_from_memory {
        log::info!("FiSH10: Removed legacy key for '{}'", target);
        Ok(())
    } else {
        // If not in legacy memory, check if it's in FiSH 11 store to provide a better message
        if crate::config::get_key(target, None).is_ok() || crate::config::has_channel_key(target) {
             log::info!("FiSH10: Key for '{}' not found in legacy store, but it exists in FiSH 11 store.", target);
             // We return Ok anyway because the "legacy" key is indeed "not there" (deleted or never existed)
             Ok(())
        } else {
            Err(DllError::LegacyError {
                context: format!("Removing key for '{}'", target),
                cause: "Key not found in legacy store".to_string(),
            })
        }
    }
}

/// List all legacy keys
pub fn list_legacy_keys() -> Vec<String> {
    let keys_arc = {
        let config = super::LEGACY_CONFIG.read();
        Arc::clone(&config.legacy_keys)
    };
    let keys = keys_arc.read();
    keys.keys().cloned().collect()
}

/// Check if a legacy key exists for a target
pub fn has_legacy_key(target: &str) -> bool {
    let keys_arc = {
        let config = super::LEGACY_CONFIG.read();
        Arc::clone(&config.legacy_keys)
    };
    let keys = keys_arc.read();
    keys.contains_key(target)
}

/// Convert a password to a Blowfish key (FiSH 10 style)
pub fn password_to_key(password: &str) -> Vec<u8> {
    // FiSH 10 uses a simple approach: take the first 16 bytes of the SHA-1 hash
    use sha1::{Digest, Sha1};

    let mut hasher = Sha1::new();
    hasher.update(password.as_bytes());
    let result = hasher.finalize();

    // Take first 16 bytes (128 bits) for Blowfish
    result[..16].to_vec()
}

/// Generate DH1080 key pair for FiSH 10 key exchange
pub fn generate_dh1080_keypair() -> Result<dh1080::DH1080KeyPair, DllError> {
    dh1080::generate_dh1080_keypair()
}

/// Compute shared secret using DH1080
pub fn compute_dh1080_shared_secret(
    private_key: &num_bigint::BigUint,
    other_public_key: &str,
) -> Result<String, DllError> {
    dh1080::compute_dh1080_shared_secret(private_key, other_public_key)
}

/// Parse DH1080 public key
pub fn parse_dh1080_public_key(key_str: &str) -> Result<Vec<u8>, DllError> {
    dh1080::dh1080_base64_decode(key_str)
}


pub fn get_legacy_key(target: &str) -> Option<Vec<u8>> {
    let keys_arc = {
        let config = super::LEGACY_CONFIG.read();
        std::sync::Arc::clone(&config.legacy_keys)
    };
    let keys = keys_arc.read();
    keys.get(target).cloned()
}

pub fn store_legacy_key(target: &str, key: &[u8]) -> Result<(), DllError> {
    let keys_arc = {
        let config = super::LEGACY_CONFIG.read();
        Arc::clone(&config.legacy_keys)
    };
    let mut keys = keys_arc.write();
    keys.insert(target.to_string(), key.to_vec());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy::test_utils::clear_test_legacy_keys;

    #[test]
    fn test_key_management() {
        clear_test_legacy_keys();

        // Test setting a key
        assert!(set_legacy_key("#test", "6162636465666768").is_ok());
        assert!(has_legacy_key("#test"));

        // Test listing keys
        let keys = list_legacy_keys();
        assert!(keys.contains(&"#test".to_string()));

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
