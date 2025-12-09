//! Channel key management utilities that combine manual and ratchet-based keys

use crate::config;
use crate::unified_error::DllResult;

/// Gets a channel key, checking both manual keys and ratchet-based keys
///
/// This function first tries to get a key from the manual storage, and if not found,
/// falls back to the ratchet-based key system.
pub fn get_channel_key_with_fallback(channel_name: &str) -> DllResult<[u8; 32]> {
    // First, try to get the manual key
    match config::get_manual_channel_key(channel_name) {
        Ok(key) => {
            // Found a manual key
            Ok(key)
        }
        Err(_) => {
            // Manual key not found, try the ratchet-based channel key
            match config::get_channel_key(channel_name) {
                Ok(key) => Ok(key),
                Err(e) => {
                    // Neither key found
                    Err(e.into())
                }
            }
        }
    }
}

/// Checks if either a manual or ratchet-based channel key exists for a channel
pub fn has_channel_key(channel_name: &str) -> bool {
    config::get_manual_channel_key(channel_name).is_ok()
        || config::get_channel_key(channel_name).is_ok()
}

/// Gets the type of channel key (manual or ratchet-based)
pub fn get_channel_key_type(channel_name: &str) -> DllResult<ChannelKeyType> {
    if config::get_manual_channel_key(channel_name).is_ok() {
        Ok(ChannelKeyType::Manual)
    } else if config::get_channel_key(channel_name).is_ok() {
        Ok(ChannelKeyType::RatchetBased)
    } else {
        Err(crate::unified_error::DllError::KeyNotFound(channel_name.to_string()))
    }
}

#[derive(Debug, PartialEq)]
pub enum ChannelKeyType {
    Manual,
    RatchetBased,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config;

    #[test]
    fn test_key_type_detection() {
        // Test with no key
        assert!(get_channel_key_type("#nonexistent").is_err());

        // Set a channel key and test
        let key = [1u8; 32];
        config::set_channel_key("#test", &key).unwrap();
        assert_eq!(get_channel_key_type("#test").unwrap(), ChannelKeyType::RatchetBased);

        // Cleanup: remove ratchet key and set manual key
        // We don't have a direct delete function for channel_keys, so we'll just test manual keys
    }
}
