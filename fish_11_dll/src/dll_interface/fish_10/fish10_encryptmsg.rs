//! FiSH 10 Legacy Encryption Function
//!
//! This function provides compatibility with the legacy FiSH 10 encryption
//! using Blowfish encryption.

use crate::dll_interface::utility;
use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;
use crate::{buffer_utils, dll_function_identifier, legacy, log_debug};
use std::ffi::c_char;
use std::os::raw::c_int;

fn fish10_encrypt_msg_impl(input: &str) -> Result<String, DllError> {
    // Parse input: <target> <plaintext_message>
    let parsed = utility::parse_input(input)?;

    let target = parsed.target;
    let plaintext_message = parsed.message.trim();

    // Check if this is a legacy target
    if !legacy::is_legacy_target(&target) {
        return Err(DllError::LegacyError {
            context: format!("Target '{}' not configured for legacy mode", target),
            cause: "No legacy key found for this target".to_string(),
        });
    }

    // Get the legacy key for this target
    let config = legacy::LEGACY_CONFIG.read();
    let keys = config.legacy_keys.read();
    let key = keys.get(&target as &str).ok_or_else(|| DllError::LegacyError {
        context: format!("Missing legacy key for target '{}'", target),
        cause: "Key not found in legacy key store".to_string(),
    })?;

    #[cfg(debug_assertions)]
    log_debug!("FiSH10: Encrypting message for '{}' with legacy key", target);

    // Encrypt using legacy Blowfish algorithm
    let encrypted = legacy::blowfish::encrypt_message(key, plaintext_message, target.as_bytes())
        .map_err(|e| DllError::LegacyError {
            context: format!("Blowfish encryption failed for '{}'", target),
            cause: e.to_string(),
        })?;

    // Add the legacy +OK prefix
    let result = format!("+OK {}", encrypted);

    #[cfg(debug_assertions)]
    log_debug!("FiSH10: successfully encrypted legacy message for '{}'", target);

    Ok(result)
}

dll_function_identifier!(FiSH10_EncryptMsg, data, {
    // Parse input: <target> <plaintext_message>
    let mut input_str = unsafe { buffer_utils::parse_buffer_input(data)? };
    fish10_encrypt_msg_impl(&input_str)
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy::test_utils::setup_test_legacy_key;

    #[test]
    fn test_fish10_encrypt_basic() {
        setup_test_legacy_key("#test", b"testkey12345678");

        // Test basic encryption
        let result = fish10_encrypt_msg_impl("#test Hello World").unwrap();
        assert!(result.starts_with("+OK "));
        // Add proper assertions once blowfish implementation is complete
    }
}
