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
    // Accept input in two formats:
    // 1. <network> <target> <plaintext_key>
    // 2. <target> <plaintext_key> (network is determined automatically)
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.splitn(3, ' ').collect();

    let (network, target_raw, plaintext_key) = match parts.len() {
        3 => (Some(parts[0]), parts[1], parts[2]),
        2 => (None, parts[0], parts[1]),
        _ => {
            return Err(DllError::InvalidInput {
                param: "input".to_string(),
                reason: "expected format: [<network>] <target> <plaintext_key>".to_string(),
            });
        }
    };

    let normalized_target = crate::utils::normalize_target(target_raw);
    let nickname = normalize_nick(normalized_target);

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
        network.unwrap_or("auto"),
        plaintext_key.len()
    );

    // Derive a 32-byte key from the plaintext password using HKDF-SHA256.
    // Use network:target as salt to ensure unique keys for different contexts.
    let salt = format!("{}:{}", network.unwrap_or("default"), nickname);
    let hk = Hkdf::<Sha256>::new(Some(salt.as_bytes()), plaintext_key.as_bytes());
    let mut derived_key = [0u8; 32];
    hk.expand(&[], &mut derived_key).map_err(|_| DllError::KeyDerivationFailed)?;

    log_debug!("Key derived successfully, storing...");

    // Then store the key, allowing overwrite.
    config::set_key(&nickname, &derived_key, network, true, false)?;

    log::info!(
        "Successfully set key from plaintext for {} on network {}",
        nickname,
        network.unwrap_or("auto")
    );

    Ok("1".to_string())
});
