use std::ffi::c_char;
use std::os::raw::c_int;

use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::buffer_utils;
use crate::dll_function_identifier;
use crate::unified_error::DllError;
use crate::utils::normalize_nick;
use crate::{config, crypto};

dll_function_identifier!(FiSH11_ProcessPublicKey, data, {
    // Parse input: <nickname> <received_key>
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.splitn(2, ' ').collect();

    if parts.len() < 2 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "expected format: <nickname> <received_key>".to_string(),
        });
    }

    let nickname = normalize_nick(parts[0]);
    let received_pubkey_str = parts[1].trim();

    if nickname.is_empty() {
        return Err(DllError::MissingParameter("nickname".to_string()));
    }
    if received_pubkey_str.is_empty() {
        return Err(DllError::MissingParameter("received_key".to_string()));
    }

    log::info!("Processing public key for nickname: {}", nickname);

    // Extract the received public key
    let their_public_key = crypto::extract_public_key(received_pubkey_str).map_err(|e| {
        DllError::KeyInvalid { reason: format!("invalid public key format: {}", e) }
    })?;

    log::debug!("Successfully extracted public key");

    // Get our keypair
    let keypair = config::get_keypair().map_err(|_| {
        DllError::KeyNotFound(
            "local keypair (generate one first with FiSH11_ExchangeKey)".to_string(),
        )
    })?;

    log::debug!("Retrieved local keypair");

    // Compute the shared secret using Curve25519 Diffie-Hellman
    let shared_secret = crypto::compute_shared_secret(&keypair.private_key, &their_public_key)
        .map_err(|e| {
            DllError::KeyExchangeFailed(format!("failed to compute shared secret: {}", e))
        })?;

    log::debug!("Computed shared secret successfully");

    // Store the shared secret with intelligent duplicate handling:
    // - First try without overwrite (fail if key exists)
    // - If duplicate detected, update it as part of key exchange protocol
    let store_result = match config::set_key(&nickname, &shared_secret, None, false) {
        Ok(_) => Ok(()),
        Err(crate::error::FishError::DuplicateEntry(ref nick)) => {
            log::info!("Updating existing key for {} as part of key exchange", nick);
            config::set_key(&nickname, &shared_secret, None, true)
        }
        Err(e) => Err(e),
    };

    // Convert FishError to DllError for the final result
    store_result.map_err(|e| match e {
        crate::error::FishError::DuplicateEntry(nick) => DllError::KeyInvalid {
            reason: format!("key for {} already exists and couldn't be updated", nick),
        },
        _ => DllError::ConfigMalformed(format!("error storing key: {}", e)),
    })?;

    log::info!("Successfully completed key exchange with {}", nickname);

    // Return a truthy identifier value (no leading /echo) so mIRC treats this as data
    // The script checks the truthiness of $dll(..., FiSH11_ProcessPublicKey, ...)
    Ok("1".to_string())
});

dll_function_identifier!(FiSH11_TestCrypt, data, {
    // Parse input message
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };

    if input.is_empty() {
        return Err(DllError::MissingParameter("message".to_string()));
    }

    log::debug!("Testing encryption/decryption cycle with message: {}", input);

    // Generate a random 32-byte key for testing
    let key_bytes = crate::utils::generate_random_bytes(32);
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    log::debug!("Generated random test key: {:02x?}", &key[..8]); // Log first 8 bytes only

    // Encrypt the message
    let encrypted = crypto::encrypt_message(&key, &input, None).map_err(|e| {
        DllError::EncryptionFailed { context: "test encryption".to_string(), cause: e.to_string() }
    })?;

    log::debug!("Successfully encrypted message");

    // Decrypt the message to verify the cycle
    let decrypted = crypto::decrypt_message(&key, &encrypted).map_err(|e| {
        DllError::DecryptionFailed { context: "test decryption".to_string(), cause: e.to_string() }
    })?;

    log::debug!("Successfully decrypted message");

    // Verify that decryption matches original
    if decrypted != input {
        log::warn!("Decryption mismatch: expected '{}', got '{}'", input, decrypted);
        return Err(DllError::DecryptionFailed {
            context: "verification".to_string(),
            cause: "decrypted message does not match original".to_string(),
        });
    }

    // Sanitize strings for safe display (replace non-printable characters)
    fn safe_display(s: &str, max_len: usize) -> String {
        s.chars()
            .take(max_len)
            .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' })
            .collect()
    }

    let max_display_len = 100;
    let input_safe = safe_display(&input, max_display_len);
    let encrypted_safe = safe_display(&encrypted, max_display_len);
    let decrypted_safe = safe_display(&decrypted, max_display_len);

    log::info!("Encryption test completed successfully");

    Ok(format!(
        "[TestCrypt] Original: {} | Encrypted: {} | Decrypted: {}",
        input_safe, encrypted_safe, decrypted_safe
    ))
});
