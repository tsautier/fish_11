//! Manages channel-specific symmetric keys in the configuration.

use crate::config::config_access::{with_config, with_config_mut};
use crate::error::{FishError, Result};

/// Sets a channel key in the configuration.
///
/// # Arguments
/// * `channel_name` - The IRC channel name (must start with # or &)
/// * `key` - The 32-byte symmetric key for the channel
///
/// # Channel Name Normalization
/// Channel names are normalized to lowercase before storage to ensure consistent
/// lookups regardless of case (IRC channels are case-insensitive per RFC 2812).
///
/// # Validation
/// - Channel name must start with '#' or '&' (RFC 2812)
/// - Length must be 2-50 characters
/// - No invalid characters (control chars, spaces, commas, BEL)
pub fn set_channel_key(channel_name: &str, key: &[u8; 32]) -> Result<()> {
    // Normalize channel name to lowercase for consistent storage
    let normalized = channel_name.to_lowercase();

    // Validate channel prefix
    if !normalized.starts_with('#') && !normalized.starts_with('&') {
        return Err(FishError::InvalidInput("channel_name must start with # or &".to_string()));
    }

    // Validate channel name length (RFC 2812: max 50 chars, min 2 for prefix + name)
    if normalized.len() < 2 || normalized.len() > 50 {
        return Err(FishError::InvalidInput(format!(
            "channel_name length must be 2-50 characters, got {}",
            normalized.len()
        )));
    }

    // Check for invalid characters per RFC 2812 Section 2.3.1
    // Disallowed: space (0x20), comma (0x2C), BEL (0x07), and control characters
    if normalized.chars().any(|c| c.is_control() || c == ' ' || c == ',' || c == '\x07') {
        return Err(FishError::InvalidInput(
            "channel_name contains invalid characters (control chars, spaces, commas, or BEL)"
                .to_string(),
        ));
    }

    with_config_mut(|config| {
        config.channel_keys.insert(normalized, key.to_vec());
        Ok(())
    })
}

/// Gets a channel key from the configuration.
///
/// # Arguments
/// * `channel_name` - The IRC channel name (case-insensitive)
///
/// # Returns
/// The 32-byte symmetric key for the channel, or an error if not found
///
/// # Channel Name Normalization
/// Channel names are normalized to lowercase before lookup to match the storage format.
pub fn get_channel_key(channel_name: &str) -> Result<[u8; 32]> {
    // Normalize channel name to lowercase for consistent lookup
    let normalized = channel_name.to_lowercase();

    // Validate channel prefix
    if !normalized.starts_with('#') && !normalized.starts_with('&') {
        return Err(FishError::InvalidInput("channel_name must start with # or &".to_string()));
    }

    with_config(|config| {
        config
            .channel_keys
            .get(&normalized)
            .ok_or_else(|| {
                FishError::KeyNotFound(format!("No key found for channel: {}", normalized))
            })
            .and_then(|key_bytes| {
                let key_len = key_bytes.len();
                key_bytes.as_slice().try_into().map_err(|_| {
                    FishError::ConfigError(format!(
                        "Invalid key length for channel {}: expected 32 bytes, got {}",
                        normalized, key_len
                    ))
                })
            })
    })
}
