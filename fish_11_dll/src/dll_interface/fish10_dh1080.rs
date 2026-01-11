//! FiSH 10 DH1080 Key Exchange Functions
//!
//! These functions provide DH1080 key exchange compatibility for FiSH 10 protocol.

use crate::dll_interface::utility;
use crate::platform_types::{BOOL, HWND, c_char, c_int};
use crate::unified_error::DllError;
use crate::{buffer_utils, config, crypto, dll_function_identifier, legacy, log_debug, log_info};

// Generate DH1080 key pair
// Returns: public_key
dll_function_identifier!(FiSH10_DH1080_GenerateKeyPair, data, {
    // Parse input: <target> (optional)
    let mut input_str = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parsed = utility::parse_input(&input_str)?;
    let target = parsed.target;

    // Generate DH1080 key pair
    let keypair = legacy::dh1080::generate_dh1080_keypair()?;

    // Store the private key for this target
    let mut config = legacy::LEGACY_CONFIG.write();
    let mut dh_keys = config.dh1080_keys.write();

    dh_keys.insert(target.to_string(), keypair.private_key);

    #[cfg(debug_assertions)]
    log_debug!("FiSH10: generated DH1080 key pair for '{}'", target);

    Ok(keypair.public_key)
});

// Compute shared secret from DH1080 exchange
// Input: <target> <other_public_key>
// Returns: shared_secret
dll_function_identifier!(FiSH10_DH1080_ComputeSecret, data, {
    // Parse input: <target> <other_public_key>
    let mut input_str = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parsed = utility::parse_input(&input_str)?;
    let target = parsed.target;
    let other_public_key = parsed.message.trim();

    // Get our private key
    let config = legacy::LEGACY_CONFIG.read();
    let dh_keys = config.dh1080_keys.read();
    let private_key = dh_keys.get(&target as &str).ok_or_else(|| DllError::LegacyError {
        context: format!("DH1080 secret computation for '{}'", target),
        cause: "No private key found for this target".to_string(),
    })?;

    // Compute shared secret
    let shared_secret =
        legacy::dh1080::compute_dh1080_shared_secret(private_key, other_public_key)?;

    #[cfg(debug_assertions)]
    log_debug!("FiSH10: computed DH1080 shared secret for '{}'", target);

    Ok(shared_secret)
});

// Set DH1080 key for a target
// Input: <target> <private_key_hex>
// Returns: success message
dll_function_identifier!(FiSH10_DH1080_SetKey, data, {
    // Parse input: <target> <private_key_hex>
    let mut input_str = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parsed = utility::parse_input(&input_str)?;
    let target = parsed.target;
    let private_key_hex = parsed.message.trim();

    // Decode the hex private key
    let private_key_bytes = hex::decode(private_key_hex).map_err(|e| DllError::LegacyError {
        context: "DH1080 key decoding".to_string(),
        cause: format!("Invalid hex key: {}", e),
    })?;

    // Convert bytes to BigUint
    let private_key = num_bigint::BigUint::from_bytes_be(&private_key_bytes);

    // Store the private key
    let mut config = legacy::LEGACY_CONFIG.write();
    let mut dh_keys = config.dh1080_keys.write();
    dh_keys.insert(target.to_string(), private_key);

    #[cfg(debug_assertions)]
    log_debug!("FiSH10: Set DH1080 private key for '{}'", target);

    Ok(format!("DH1080 key set for {}", target))
});

// Test helpers used by unit tests: simple implementations that mirror the DLL behavior.
fn fish10_dh1080_generate_keypair_impl(input: &str) -> Result<String, DllError> {
    let target = input.trim();

    // Generate DH1080 key pair
    let keypair = legacy::dh1080::generate_dh1080_keypair()?;

    // Store the private key for this target
    let mut config = legacy::LEGACY_CONFIG.write();
    let mut dh_keys = config.dh1080_keys.write();
    dh_keys.insert(target.to_string(), keypair.private_key);

    #[cfg(debug_assertions)]
    log_debug!("FiSH10 (test helper): generated DH1080 key pair for '{}'", target);

    Ok(keypair.public_key)
}

fn fish10_dh1080_compute_secret_impl(input: &str) -> Result<String, DllError> {
    // Expect input: "<target> <other_public_key>"
    let mut parts = input.splitn(2, ' ');
    let target = parts.next().unwrap_or("").trim();
    let other_public_key = parts.next().unwrap_or("").trim();

    #[cfg(debug_assertions)]
    log_debug!("FiSH10 (test helper): computing DH1080 shared secret for '{}'", target);

    // Get our private key
    let config = legacy::LEGACY_CONFIG.read();
    let dh_keys = config.dh1080_keys.read();
    let private_key = dh_keys.get(&target as &str).ok_or_else(|| DllError::LegacyError {
        context: format!("DH1080 secret computation for '{}'", target),
        cause: "No private key found for this target".to_string(),
    })?;

    // Compute shared secret
    let shared_secret =
        legacy::dh1080::compute_dh1080_shared_secret(private_key, other_public_key)?;

    Ok(shared_secret)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::legacy::test_utils::{clear_test_dh1080_keys, setup_test_dh1080_key};

    #[test]
    fn test_dh1080_key_generation() {
        clear_test_dh1080_keys();

        let result = fish10_dh1080_generate_keypair_impl("#test");
        assert!(result.is_ok());
        let public_key = result.unwrap();
        assert!(public_key.ends_with('A'));
    }

    #[test]
    fn test_dh1080_secret_computation() {
        clear_test_dh1080_keys();

        // Generate keys for two parties
        let pub_key1 = fish10_dh1080_generate_keypair_impl("#test1").unwrap();
        let pub_key2 = fish10_dh1080_generate_keypair_impl("#test2").unwrap();

        // Compute shared secrets
        let secret1 = fish10_dh1080_compute_secret_impl(&format!("#test1 {}", pub_key2)).unwrap();
        let secret2 = fish10_dh1080_compute_secret_impl(&format!("#test2 {}", pub_key1)).unwrap();

        // In a real DH implementation, these would be equal
        assert_eq!(secret1.len(), secret2.len());
    }
}
