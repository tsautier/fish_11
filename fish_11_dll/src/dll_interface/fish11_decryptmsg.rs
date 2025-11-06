use std::ffi::c_char;
use std::os::raw::c_int;

use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::buffer_utils;
use crate::config;
use crate::crypto;
use crate::dll_function_identifier;
use crate::unified_error::DllError;
use crate::utils::normalize_nick;

dll_function_identifier!(FiSH11_DecryptMsg, data, {
    // 1. Parse input: <target> <encrypted_message>
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.splitn(2, ' ').collect();

    if parts.len() < 2 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "expected format: <target> <encrypted_message>".to_string(),
        });
    }

    let target = parts[0];
    let mut encrypted_message = parts[1].trim();

    if target.is_empty() {
        return Err(DllError::MissingParameter("target".to_string()));
    }
    if encrypted_message.is_empty() {
        return Err(DllError::MissingParameter("encrypted_message".to_string()));
    }

    // 2. Strip the "+FiSH " prefix if present.
    if let Some(stripped) = encrypted_message.strip_prefix("+FiSH ") {
        encrypted_message = stripped;
        log::debug!("Stripped +FiSH prefix from encrypted message");
    }

    // --- Channel Decryption Logic ---
    if target.starts_with('#') || target.starts_with('&') {
        log::debug!("Decrypting for channel: {}", target);

        let encrypted_bytes = crate::utils::base64_decode(encrypted_message)?;
        if encrypted_bytes.len() < 12 {
            return Err(DllError::DecryptionFailed {
                context: "payload validation".to_string(),
                cause: "Encrypted payload too short to contain a nonce".to_string(),
            });
        }
        let nonce: [u8; 12] = encrypted_bytes[..12].try_into().unwrap();

        // 1. Anti-replay check (read-only)
        if config::check_nonce(target, &nonce)? {
            return Err(DllError::ReplayAttackDetected {
                channel: target.to_string(),
            });
        }

        // 2. Attempt decryption with ratchet state
        let decrypted = config::with_ratchet_state_mut(target, |state| {
            // Try current key first
            if let Ok(plaintext) = crypto::decrypt_message(
                &state.current_key,
                encrypted_message,
                Some(target.as_bytes()),
            ) {
                // Success with current key. Advance the ratchet.
                let next_key = crypto::advance_ratchet_key(&state.current_key, &nonce, target)?;
                state.advance(next_key);
                return Ok(Some(plaintext)); // Return plaintext to outer scope
            }

            // If current key fails, try previous keys for out-of-order messages
            for old_key in state.previous_keys.iter().rev() { // Check newest first
                if let Ok(plaintext) = crypto::decrypt_message(
                    old_key,
                    encrypted_message,
                    Some(target.as_bytes()),
                ) {
                    // Success with a previous key. DO NOT advance the ratchet.
                    log::warn!("Decrypted message for {} with a previous ratchet key (out-of-order message)", target);
                    return Ok(Some(plaintext)); // Return plaintext to outer scope
                }
            }

            Ok(None) // Indicate that decryption failed
        })?;

        if let Some(plaintext) = decrypted {
            // 3. Add nonce to cache ONLY after successful decryption
            config::add_nonce(target, nonce)?;
            log::info!("Successfully decrypted ratchet message for {}", target);
            return Ok(plaintext);
        } else {
            return Err(DllError::DecryptionFailed {
                context: format!("decrypting for channel {}", target),
                cause: "Invalid key or corrupted data (ratchet exhausted)".to_string(),
            });
        }
    }

    // --- Private Message Decryption Logic ---
    let nickname = normalize_nick(target);
    log::debug!("Decrypting for nickname: {}", nickname);

    let key_vec = config::get_key_default(&nickname)?;
    let key: &[u8; 32] = key_vec.as_slice().try_into().map_err(|_|
        DllError::InvalidInput {
            param: "key".to_string(),
            reason: format!("Key for {} must be exactly 32 bytes, got {}", nickname, key_vec.len()),
        }
    )?;

    log::debug!("Successfully retrieved decryption key");

    // Decrypt the message (no AD for private messages).
    let decrypted = crypto::decrypt_message(key, encrypted_message, None).map_err(|e| {
        DllError::DecryptionFailed {
            context: format!("decrypting for {}", nickname),
            cause: e.to_string(),
        }
    })?;

    log::info!("Successfully decrypted message for {}", nickname);

    Ok(decrypted)
});

#[cfg(test)]
mod tests {

    use crate::config;
    use crate::crypto;
    use crate::utils::normalize_nick;

    #[test]
    fn test_normalize_nick() {
        assert_eq!(normalize_nick("TestNick "), "testnick");
        assert_eq!(normalize_nick("  FiSH_User"), "fish_user");
    }

    #[test]
    fn test_decryptmsg_valid() {
        let nickname = "testuser";
        let key = [0u8; 32];
        let message = "Hello world!";
        config::set_key_default(nickname, &key, true).unwrap();
        let encrypted = crypto::encrypt_message(&key, message, Some(nickname), None).unwrap();
        let decrypted = crypto::decrypt_message(&key, &encrypted, None).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_decryptmsg_invalid_key_length() {
        let nickname = "testuser2";
        let result = config::get_key_default(nickname);
        assert!(result.is_err());
    }

    #[test]
    fn test_decryptmsg_empty_nickname() {
        let nickname = "";
        let result = normalize_nick(nickname);
        assert_eq!(result, "");
    }
}
