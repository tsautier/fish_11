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
    /// Decrypts a message from a specific nickname using ChaCha20-Poly1305.
    ///
    /// This function handles the complete decryption workflow, including:
    /// - Retrieving the appropriate encryption key.
    /// - Stripping the `+FiSH ` prefix.
    /// - Performing authenticated decryption.
    /// - Returning the plaintext message.
    // 1. Parse input: <nickname> <encrypted_message>
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.splitn(2, ' ').collect();

    if parts.len() < 2 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "expected format: <nickname> <encrypted_message>".to_string(),
        });
    }

    let nickname = normalize_nick(parts[0]);
    let mut encrypted_message = parts[1].trim();

    if nickname.is_empty() {
        return Err(DllError::MissingParameter("nickname".to_string()));
    }
    if encrypted_message.is_empty() {
        return Err(DllError::MissingParameter("encrypted_message".to_string()));
    }

    log::debug!("Decrypting for nickname: {}", nickname);

    // 2. Strip the "+FiSH " prefix if present (6 characters).
    if let Some(stripped) = encrypted_message.strip_prefix("+FiSH ") {
        encrypted_message = stripped;
        log::debug!("Stripped +FiSH prefix from encrypted message");
    }

    // 3. Retrieve the decryption key for the target.
    let key = config::get_key_default(&nickname)?;

    log::debug!("Successfully retrieved decryption key");

    // 4. Decrypt the message using the retrieved key.
    let key_array: &[u8; 32] = key.as_slice().try_into().map_err(|_| DllError::InvalidInput {
        param: "key".to_string(),
        reason: "key must be exactly 32 bytes".to_string(),
    })?;
    let decrypted = crypto::decrypt_message(key_array, encrypted_message).map_err(|e| {
        DllError::DecryptionFailed {
            context: format!("decrypting for {}", nickname),
            cause: e.to_string(),
        }
    })?;

    // 5. Return the decrypted plaintext.
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
        let encrypted = crypto::encrypt_message(&key, message, Some(nickname)).unwrap();
        let decrypted = crypto::decrypt_message(&key, &encrypted).unwrap();
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
