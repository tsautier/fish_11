//! Manages manually-set encrypted channel keys in the configuration.
//!
//! This module allows users to set fixed encryption keys for channels that will
//! be persisted to the configuration file in an encrypted format.

use crate::config::config_access::{with_config, with_config_mut};
use crate::config::models::EntryData;
use crate::crypto;
use crate::error::{FishError, Result};
use crate::log_debug;
use crate::unified_error::{DllError, DllResult};
use crate::utils::{base64_decode, base64_encode};
use secrecy::ExposeSecret;

/// Sets a manual channel key in the configuration after encrypting it.
///
/// This function stores a fixed channel key encrypted using a master key derived
/// from the user's X25519 keypair. The encrypted key will be persisted to the
/// configuration file and can be decrypted when needed.
///
/// # Arguments
/// * `channel_name` - The IRC channel name (must start with # or &)
/// * `key` - The 32-byte symmetric key to store
/// * `overwrite` - Whether to overwrite an existing key
///
/// # Channel Name Normalization
/// Channel names are normalized to lowercase for consistent storage.
///
/// # Validation
/// - Channel name must start with '#' or '&' (RFC 2812)
/// - Length must be 2-50 characters
/// - No invalid characters per RFC 2812
pub fn set_manual_channel_key(
    channel_name: &str,
    key: &[u8; 32],
    overwrite: bool,
) -> DllResult<()> {
    // Normalize channel name to lowercase for consistent storage
    let normalized_channel = channel_name.to_lowercase();

    // Validate channel prefix
    if !normalized_channel.starts_with('#') && !normalized_channel.starts_with('&') {
        return Err(DllError::InvalidInput {
            param: "channel_name".to_string(),
            reason: "channel_name must start with # or &".to_string(),
        });
    }

    // Validate channel name length (RFC 2812: max 50 chars, min 2 for prefix + name)
    if normalized_channel.len() < 2 || normalized_channel.len() > 50 {
        return Err(DllError::InvalidInput {
            param: "channel_name".to_string(),
            reason: format!(
                "channel_name length must be 2-50 characters, got {}",
                normalized_channel.len()
            ),
        });
    }

    // Check for invalid characters per RFC 2812 Section 2.3.1
    if normalized_channel.chars().any(|c| c.is_control() || c == ' ' || c == ',' || c == '\x07') {
        return Err(DllError::InvalidInput {
            param: "channel_name".to_string(),
            reason:
                "channel_name contains invalid characters (control chars, spaces, commas, or BEL)"
                    .to_string(),
        });
    }

    // Encrypt the key using a master key derived from the user's private key
    let encrypted_key_b64 = encrypt_channel_key_for_storage(key, &normalized_channel)?;

    with_config_mut(|config| {
        // Check if key already exists and overwriting is not allowed
        let entry_key = format!("channel_key_{}", normalized_channel);
        if !overwrite && config.entries.contains_key(&entry_key) {
            return Err(FishError::DuplicateEntry(entry_key));
        }

        let now = chrono::Local::now();
        let date_str = now.format("%Y-%m-%d %H:%M:%S").to_string();

        let entry = EntryData {
            key: Some(encrypted_key_b64),
            date: Some(date_str),
            is_exchange: Some(false), // Manual key, not from exchange
        };

        // Insert the encrypted key into the entries map, which is persisted to the INI file
        config.entries.insert(entry_key, entry);
        Ok(())
    })?;

    Ok(())
}

/// Gets a manual channel key from the configuration by decrypting it.
///
/// This function retrieves an encrypted channel key from the configuration
/// file and decrypts it using the user's master key.
///
/// # Arguments
/// * `channel_name` - The IRC channel name (case-insensitive)
///
/// # Returns
/// The decrypted 32-byte symmetric key for the channel, or an error if not found
/// or if decryption fails.
pub fn get_manual_channel_key(channel_name: &str) -> DllResult<[u8; 32]> {
    // Normalize channel name to lowercase for consistent lookup
    let normalized_channel = channel_name.to_lowercase();

    // Validate channel prefix
    if !normalized_channel.starts_with('#') && !normalized_channel.starts_with('&') {
        return Err(DllError::InvalidInput {
            param: "channel_name".to_string(),
            reason: "channel_name must start with # or &".to_string(),
        });
    }

    with_config(|config| {
        let entry_key = format!("channel_key_{}", normalized_channel);

        let entry = config.entries.get(&entry_key).ok_or_else(|| {
            FishError::KeyNotFound(format!(
                "No manual key found for channel: {}",
                normalized_channel
            ))
        })?;

        let encrypted_key_b64 = entry.key.as_ref().ok_or_else(|| {
            FishError::ConfigError(format!("No key data found for channel: {}", normalized_channel))
        })?;

        // Decrypt the key
        decrypt_channel_key_from_storage(encrypted_key_b64, &normalized_channel)
    })
    .map_err(DllError::from)
}

/// Helper function to encrypt a channel key for storage using the master key.
fn encrypt_channel_key_for_storage(key: &[u8; 32], channel_name: &str) -> Result<String> {
    // Derive a master encryption key from the user's private key
    let master_key = derive_master_storage_key()?;

    // Use the channel name as Associated Data to prevent cross-channel key usage
    let ad_str = format!("channel_key_{}", channel_name);
    let ad = ad_str.as_bytes();

    // Convert key to base64 string
    let key_b64 = base64_encode(&key[..]);

    // Log sensitive content if DEBUG flag is enabled for sensitive content
    if fish_11_core::globals::LOG_DECRYPTED_CONTENT {
        log_debug!(
            "Manual_Channel_Keys: encrypting channel key for '{}': {} bytes",
            channel_name,
            key_b64.len()
        );
    }

    // Encrypt the channel key with the master key
    let encrypted_key = crypto::encrypt_message(&master_key, &key_b64, None, Some(ad))?;

    // Log encrypted result if DEBUG flag is enabled for sensitive content
    if fish_11_core::globals::LOG_DECRYPTED_CONTENT {
        log_debug!(
            "Manual_Channel_Keys: encrypted channel key for '{}': {} bytes",
            channel_name,
            encrypted_key.len()
        );
    }

    Ok(encrypted_key)
}
/// Helper function to decrypt a channel key from storage using the master key.
fn decrypt_channel_key_from_storage(
    encrypted_key_b64: &str,
    channel_name: &str,
) -> Result<[u8; 32]> {
    // Derive the same master encryption key from the user's private key
    let master_key = derive_master_storage_key()?;

    // Use the channel name as Associated Data to prevent cross-channel key usage
    let ad_str = format!("channel_key_{}", channel_name);
    let ad = ad_str.as_bytes();

    // Log sensitive content if DEBUG flag is enabled for sensitive content
    if fish_11_core::globals::LOG_DECRYPTED_CONTENT {
        log_debug!(
            "Manual_Channel_Keys: decrypting channel key for '{}': {} bytes",
            channel_name,
            encrypted_key_b64.len()
        );
    }

    // Decrypt the base64-encoded channel key
    let decrypted_key_b64 = crypto::decrypt_message(&master_key, encrypted_key_b64, Some(ad))?;

    // Log decrypted result if DEBUG flag is enabled for sensitive content
    if fish_11_core::globals::LOG_DECRYPTED_CONTENT {
        log_debug!(
            "Manual_Channel_Keys: decrypted channel key for '{}': {} bytes",
            channel_name,
            decrypted_key_b64.len()
        );
    }

    // Now decode the base64 to get the actual key
    let key_bytes = base64_decode(&decrypted_key_b64)
        .map_err(|e| FishError::ConfigError(format!("Failed to decode base64 key: {}", e)))?;

    // Convert to 32-byte array
    if key_bytes.len() != 32 {
        return Err(FishError::ConfigError(format!(
            "Decoded key has incorrect length: expected 32, got {}",
            key_bytes.len()
        )));
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);
    Ok(key)
}

/// Derives a master key for encrypting stored channel keys.
/// The master key is derived from the user's private X25519 key to ensure
/// that only this instance of the DLL can decrypt the stored keys.
fn derive_master_storage_key() -> Result<[u8; 32]> {
    use hkdf::Hkdf;
    use sha2::Sha256;

    // Get the user's private key
    let keypair = crate::config::get_keypair()?;
    let private_bytes = keypair.private_key.expose_secret();

    // Use HKDF to derive a 32-byte key for storage purposes
    let hkdf = Hkdf::<Sha256>::new(None, private_bytes);
    let mut output = [0u8; 32];
    hkdf.expand(b"FiSH11-ChannelKeyStorage", &mut output)
        .map_err(|e| FishError::CryptoError(format!("HKDF expansion failed: {}", e)))?;

    Ok(output)
}

/// Lists all manually stored channel keys (for display purposes).
/// Returns tuples of (channel_name, date, is_manual_key).
pub fn list_manual_channel_keys() -> Result<Vec<(String, Option<String>)>> {
    with_config(|config| {
        let mut result = Vec::new();

        for (entry_key, entry) in &config.entries {
            if let Some(channel_name) = entry_key.strip_prefix("channel_key_") {
                result.push((channel_name.to_string(), entry.date.clone()));
            }
        }

        Ok(result)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_set_and_get_manual_channel_key() {
        let key = [42u8; 32];
        let channel = "#test";

        // Set the key
        let result = set_manual_channel_key(channel, &key, true);
        assert!(result.is_ok());

        // Get the key back
        let retrieved_key = get_manual_channel_key(channel).unwrap();
        assert_eq!(key, retrieved_key);

        // Cleanup
        // Note: We don't have a direct delete function, but we can overwrite with a new one
    }

    #[test]
    fn test_manual_key_persistence() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        let channel = "#persist";

        // Set first key
        set_manual_channel_key(channel, &key1, true).unwrap();

        // Get it back
        let retrieved_key1 = get_manual_channel_key(channel).unwrap();
        assert_eq!(key1, retrieved_key1);

        // Set different key with overwrite
        set_manual_channel_key(channel, &key2, true).unwrap();

        // Get the new one back
        let retrieved_key2 = get_manual_channel_key(channel).unwrap();
        assert_eq!(key2, retrieved_key2);
    }

    #[test]
    fn test_invalid_channel_name() {
        let key = [42u8; 32];

        // Should fail with invalid channel name
        let result = set_manual_channel_key("invalid", &key, true);
        assert!(result.is_err());

        // Should fail with empty channel name
        let result = set_manual_channel_key("", &key, true);
        assert!(result.is_err());

        // Should work with valid channel name
        let result = set_manual_channel_key("#valid", &key, true);
        assert!(result.is_ok());
    }

    #[test]
    fn test_channel_name_normalization() {
        let key = [42u8; 32];

        // Set key with uppercase channel
        set_manual_channel_key("#TestChan", &key, true).unwrap();

        // Should be able to retrieve with lowercase
        let retrieved = get_manual_channel_key("#testchan").unwrap();
        assert_eq!(key, retrieved);

        // And with original casing
        let retrieved = get_manual_channel_key("#TestChan").unwrap();
        assert_eq!(key, retrieved);
    }
}
