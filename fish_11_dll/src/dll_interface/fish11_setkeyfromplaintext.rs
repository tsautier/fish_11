// fish_11_dll/src/dll_interface/fish11_setkeyfromplaintext.rs

use std::ffi::c_char;
use std::os::raw::c_int;

use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;
use crate::utils::normalize_nick;
use crate::{buffer_utils, config, dll_function_identifier, log_debug};
use hkdf::Hkdf;
use sha2::Sha256;

dll_function_identifier!(FiSH11_SetKeyFromPlaintext, data, {
    // First parse input: <network> <target> <plaintext_key>
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.splitn(3, ' ').collect();

    if parts.len() < 3 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "expected format: <network> <target> <plaintext_key>".to_string(),
        });
    }

    let network = parts[0];
    let target_raw = parts[1];
    let plaintext_key = parts[2];

    let normalized_target = crate::utils::normalize_target(target_raw);
    let nickname = normalize_nick(normalized_target);

    if network.is_empty() {
        return Err(DllError::MissingParameter("network".to_string()));
    }
    if nickname.is_empty() {
        return Err(DllError::MissingParameter("nickname".to_string()));
    }
    if plaintext_key.is_empty() {
        return Err(DllError::MissingParameter("plaintext_key".to_string()));
    }

    // Validate minimum key length for security
    if plaintext_key.len() < 8 {
        return Err(DllError::InvalidInput {
            param: "plaintext_key".to_string(),
            reason: "plaintext key must be at least 8 characters".to_string(),
        });
    }

    log_debug!(
        "Setting key from plaintext for nickname/channel: {} on network: {} (key length: {})",
        nickname,
        network,
        plaintext_key.len()
    );

    // Derive a 32-byte key from the plaintext password using HKDF-SHA256.
    // Use network:target as salt to ensure unique keys for different contexts.
    let salt = format!("{}:{}", network, nickname);
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), plaintext_key.as_bytes());
    let mut derived_key = [0u8; 32];
    hk.expand(&[], &mut derived_key).map_err(|_| DllError::KeyDerivationFailed)?;

    log_debug!("Key derived successfully, storing...");

    // Then store the key, allowing overwrite.
    config::set_key(&nickname, &derived_key, Some(network), true)?;

    log::info!("Successfully set key from plaintext for {} on network {}", nickname, network);

    Ok("1".to_string())
});
