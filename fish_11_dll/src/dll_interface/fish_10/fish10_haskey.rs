//! FiSH 10 Key Check Function
//!
//! This function checks if a target has a legacy FiSH 10 key.

use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;
use crate::{buffer_utils, dll_function_identifier, legacy, log_debug};
use std::ffi::c_char;
use std::os::raw::c_int;

// Check if a target has a legacy FiSH 10 key
// Input: <target>
// Returns: "1" if key exists, "0" if not
dll_function_identifier!(FiSH10_HasKey, data, {
    let input_str = unsafe { buffer_utils::parse_buffer_input(data)? };
    let target = crate::utils::normalize_target_lowercase(&input_str);

    if target.is_empty() {
        return Err(DllError::MissingParameter("target".to_string()));
    }

    // Check if this target has a legacy key
    let has_key = legacy::is_legacy_target(&target);

    #[cfg(debug_assertions)]
    log_debug!("FiSH10_HasKey: target '{}' has legacy key: {}", target, has_key);

    Ok(if has_key { "1".to_string() } else { "0".to_string() })
});

// Get legacy key info for a target
// Input: <target>
// Returns: key info string or error
dll_function_identifier!(FiSH10_GetKeyInfo, data, {
    let input_str = unsafe { buffer_utils::parse_buffer_input(data)? };
    let target = crate::utils::normalize_target_lowercase(&input_str);

    if target.is_empty() {
        return Err(DllError::MissingParameter("target".to_string()));
    }

    // Get the legacy key for this target
    if let Some(key) = legacy::get_legacy_key(&target) {
        #[cfg(debug_assertions)]
        log_debug!("FiSH10_GetKeyInfo: found legacy key for '{}' ({} bytes)", target, key.len());

        Ok(format!("Legacy Blowfish key: {} bytes", key.len()))
    } else {
        Err(DllError::KeyNotFound(target.to_string()))
    }
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy::test_utils::{clear_test_legacy_keys, setup_test_legacy_key};

    #[test]
    fn test_fish10_haskey_exists() {
        clear_test_legacy_keys();
        setup_test_legacy_key("testuser", b"testkey12345678");

        let config = legacy::LEGACY_CONFIG.read();
        let keys = config.legacy_keys.read();
        assert!(keys.contains_key("testuser"));
    }

    #[test]
    fn test_fish10_haskey_not_exists() {
        clear_test_legacy_keys();

        let config = legacy::LEGACY_CONFIG.read();
        let keys = config.legacy_keys.read();
        assert!(!keys.contains_key("nonexistent"));
    }
}
