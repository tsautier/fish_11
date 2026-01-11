//! FiSH 10 Legacy Set Key Function
//!
//! This function allows setting legacy Blowfish keys for compatibility
//! with FiSH 10 encryption.

use std::ffi::c_char;
use std::os::raw::c_int;

use crate::dll_interface::utility;
use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;
use crate::{buffer_utils, config, crypto, dll_function_identifier, log_debug, log_info, legacy};

dll_function_identifier!(FiSH10_SetKey, data, {
    // Parse input: <target> <key>
    let mut input_str = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parsed = utility::parse_input(&input_str)?;

    let target = parsed.target;
    let key_hex = parsed.message.trim();

    // Validate key length - Blowfish keys should be between 4 and 56 bytes
    let key_bytes = hex::decode(key_hex).map_err(|e| DllError::LegacyError {
        context: "Key decoding failed".to_string(),
        cause: format!("Invalid hex key: {}", e),
    })?;

    if key_bytes.len() < 4 || key_bytes.len() > 56 {
        return Err(DllError::LegacyError {
            context: format!("Invalid key length for '{}'", target),
            cause: format!("Blowfish keys must be 4-56 bytes (got {})", key_bytes.len()),
        });
    }

    log_debug!(
        "FiSH10: Setting legacy key for '{}' (length: {})",
        target,
        key_bytes.len()
    );

    // Store the key in the legacy key store
    let config = legacy::LEGACY_CONFIG.write();
    let mut keys = config.legacy_keys.write();
    keys.insert(target.to_string(), key_bytes.clone());

    // Also save to persistent storage if configured
    if let Some(ini_path) = &config.blowfish_ini_path {
        if let Err(e) = legacy::config::save_key_to_blowfish_ini(&target, &key_bytes, ini_path) {
            log::warn!("FiSH10: Failed to save key to blowfish.ini: {}", e);
        }
    }

    log_info!("FiSH10: Successfully set legacy key for '{}'", target);

    Ok(format!("Legacy key set for {}", target))
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy::test_utils::setup_test_legacy_key;

    #[test]
    fn test_fish10_set_key_valid() {
        // Test with valid hex key
        let result = fish10_set_key_impl("#test 6162636465666768"); // "abcdefgh" in hex
        assert!(result.contains("Legacy key set"));
    }

    #[test]
    fn test_fish10_set_key_invalid_length() {
        // Test with invalid key length (too short)
        let result = fish10_set_key_impl("#test 6162"); // Only 2 bytes
        assert!(result.is_err());
    }
}