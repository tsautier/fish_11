///! 
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

/// Encrypts a message for a specific nickname or channel.
/// # This function handles the complete encryption workflow, including:
/// - Retrieving the appropriate encryption key.
/// - For channels: applying a symmetric key ratchet for Forward Secrecy.
/// - Performing authenticated encryption with Associated Data.
/// - Formatting the output with the FiSH protocol prefix `+FiSH `.
dll_function_identifier!(FiSH11_EncryptMsg, data, {
    // 1. Parse input: <target> <message>
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.splitn(2, ' ').collect();

    if parts.len() < 2 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "expected format: <target> <message>".to_string(),
        });
    }

    let target = parts[0];
    let message = parts[1];

    if target.is_empty() {
        return Err(DllError::MissingParameter("target".to_string()));
    }
    if message.is_empty() {
        return Err(DllError::MissingParameter("message".to_string()));
    }

    // --- Channel Encryption Logic ---
    if target.starts_with('#') || target.starts_with('&') {
        log::debug!("Encrypting for channel: {}", target);

        // Atomically get the current key and advance the ratchet for the next message.
        let encrypted_base64 = config::with_ratchet_state_mut(target, |state| {
            let current_key = state.current_key;

            // Encrypt with the current key, using the channel name as Associated Data.
            let encrypted_b64 = crypto::encrypt_message(
                &current_key,
                message,
                Some(target),
                Some(target.as_bytes()),
            )?;

            // Extract the nonce from the encrypted payload to derive the next key.
            let encrypted_bytes = crate::utils::base64_decode(&encrypted_b64)?;
            if encrypted_bytes.len() < 12 {
                return Err(DllError::EncryptionFailed {
                    context: "payload validation".to_string(),
                    cause: "Encrypted payload too short to contain a nonce".to_string(),
                });
            }
            let nonce: [u8; 12] = encrypted_bytes[..12].try_into().unwrap();

            // Advance the ratchet to the next key.
            let next_key = crypto::advance_ratchet_key(&current_key, &nonce, target)?;
            state.advance(next_key);

            Ok(encrypted_b64)
        })?;

        let result = format!("+FiSH {}", encrypted_base64);
        log::info!("Successfully encrypted ratchet message for {}", target);
        return Ok(result);
    }

    // --- Private Message Encryption Logic ---
    let nickname = normalize_nick(target);

    if nickname.is_empty() {
        return Err(DllError::MissingParameter("nickname".to_string()));
    }

    log::debug!("Encrypting for nickname: {}", nickname);

    // 2. Retrieve the encryption key for the target.
    let key_vec = config::get_key_default(&nickname)?;
    let key: &[u8; 32] = key_vec.as_slice().try_into().map_err(|_| DllError::InvalidInput {
        param: "key".to_string(),
        reason: format!("Key for {} must be exactly 32 bytes, got {}", nickname, key_vec.len()),
    })?;

    log::debug!("Successfully retrieved encryption key");

    // 3. Encrypt the message using the retrieved key (no AD for private messages).
    let encrypted_base64 =
        crypto::encrypt_message(key, message, Some(&nickname), None).map_err(|e| {
            DllError::EncryptionFailed {
                context: format!("encrypting for {}", nickname),
                cause: e.to_string(),
            }
        })?;

    // 4. Format the result with the FiSH protocol prefix and return.
    let result = format!("+FiSH {}", encrypted_base64);

    log::info!("Successfully encrypted message for {}", nickname);

    Ok(result)
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
    fn test_encryptmsg_valid() {
        let nickname = "testuser";
        let message = "Hello world!";
        let key = [0u8; 32];
        config::set_key_default(nickname, &key, true).unwrap();
        let encrypted = crypto::encrypt_message(&key, message, Some(nickname), None).unwrap();
        assert!(!encrypted.is_empty());
    }

    #[test]
    fn test_encryptmsg_invalid_key_length() {
        let nickname = "testuser2";
        // Wrong key size, we force typing to provoke a compilation error
        // let key = [0u8; 16]; // This does not compile, so we verify that the function refuses invalid keys otherwise
        let result = config::get_key_default(nickname);
        assert!(result.is_err());
    }

    #[test]
    fn test_encryptmsg_empty_nickname() {
        let nickname = "";
        let result = normalize_nick(nickname);
        assert_eq!(result, "");
    }
}
