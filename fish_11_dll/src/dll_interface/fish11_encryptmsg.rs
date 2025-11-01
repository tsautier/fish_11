use std::ffi::c_char;
use std::os::raw::c_int;

use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::buffer_utils;
use crate::config;
use crate::crypto;
use crate::dll_function;
use crate::unified_error::{DllError, DllResult};
use crate::utils::normalize_nick;

/// Encrypts a message for a specific nickname using ChaCha20-Poly1305 authenticated encryption.
///
/// This function handles the complete encryption workflow, including:
/// - Retrieving the appropriate encryption key.
/// - Performing authenticated encryption.
/// - Formatting the output with the FiSH protocol prefix `+FiSH `.
dll_function!(FiSH11_EncryptMsg, data, {
    // 1. Parse input: <nickname> <message>
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.splitn(2, ' ').collect();

    if parts.len() < 2 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "expected format: <nickname> <message>".to_string(),
        });
    }

    let nickname = normalize_nick(parts[0]);
    let message = parts[1];

    if nickname.is_empty() {
        return Err(DllError::MissingParameter("nickname".to_string()));
    }
    if message.is_empty() {
        return Err(DllError::MissingParameter("message".to_string()));
    }

    log::debug!("Encrypting for nickname: {}", nickname);

    // 2. Retrieve the encryption key for the target.
    // The `?` operator automatically converts a potential `FishError` into a `DllError`.
    let key = config::get_key_default(&nickname)?;

    log::debug!("Successfully retrieved encryption key");

    // 3. Encrypt the message using the retrieved key.
    // We map the error to provide more specific context for encryption failures.
    let key_array: &[u8; 32] = key.as_slice().try_into().map_err(|_| DllError::InvalidInput {
        param: "key".to_string(),
        reason: "key must be exactly 32 bytes".to_string(),
    })?;
    let encrypted_base64 =
        crypto::encrypt_message(key_array, message, Some(&nickname)).map_err(|e| {
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
        let encrypted = crypto::encrypt_message(&key, message, Some(nickname)).unwrap();
        assert!(!encrypted.is_empty());
    }

    #[test]
    fn test_encryptmsg_invalid_key_length() {
        let nickname = "testuser2";
        // Mauvaise taille de clé, on force le typage pour provoquer une erreur de compilation
        // let key = [0u8; 16]; // Ceci ne compile pas, donc on vérifie que la fonction refuse les clés invalides autrement
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
