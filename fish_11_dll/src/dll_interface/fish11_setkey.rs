use std::ffi::c_char;
use std::os::raw::c_int;

use base64::Engine;

use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;
use crate::utils::normalize_nick;
use crate::{buffer_utils, config, dll_function_identifier, log_debug};

dll_function_identifier!(FiSH11_SetKey, data, {
    // 1. Parse input: <network> <target> <base64_key> where target is nickname or channel
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.splitn(3, ' ').collect();

    if parts.len() < 3 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "expected format: <network> <target> <base64_key> (target = nickname or channel)".to_string(),
        });
    }

    let network = parts[0];
    let target_raw = parts[1];
    let base64_key = parts[2].trim();

    // Normalize target to strip STATUSMSG prefixes (@#chan, +#chan, etc.)
    let normalized_target = crate::utils::normalize_target(target_raw);
    let nickname = normalize_nick(normalized_target);

    if network.is_empty() {
        return Err(DllError::MissingParameter("network".to_string()));
    }
    if nickname.is_empty() {
        return Err(DllError::MissingParameter("nickname".to_string()));
    }
    if base64_key.is_empty() {
        return Err(DllError::MissingParameter("base64_key".to_string()));
    }

    log_debug!(
        "Setting key for nickname/channel: {} on network: {} (original: {})",
        nickname,
        network,
        target_raw
    );

    // 2. Decode the base64 key.
    let key_bytes = base64::engine::general_purpose::STANDARD.decode(base64_key).map_err(|e| {
        DllError::Base64DecodeFailed {
            context: "decoding nickname key".to_string(),
            cause: e.to_string(),
        }
    })?;

    // 3. Ensure it's the right length (256 bits = 32 bytes).
    if key_bytes.len() != 32 {
        return Err(DllError::InvalidKeySize { expected: 32, actual: key_bytes.len() });
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    log_debug!("Key decoded successfully, storing...");

    // 4. Store the key, allowing overwrite.
    config::set_key(&nickname, &key, Some(network), true)?;

    log::info!("Successfully set key for {} on network {}", nickname, network);

    // Return a truthy identifier value so mIRC treats this as success (no /echo)
    Ok("1".to_string())
});

#[cfg(test)]
mod tests {

    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    use crate::config;
    use crate::utils::normalize_nick;

    #[test]
    fn test_normalize_nick() {
        assert_eq!(normalize_nick("TestNick "), "testnick");
        assert_eq!(normalize_nick("  FiSH_User"), "fish_user");
    }

    #[test]
    fn test_setkey_valid() {
        let nickname = "fishuser";
        let key = [1u8; 32];

        let result = config::set_key(nickname, &key, None, true);
        assert!(result.is_ok());

        let stored = config::get_key_default(nickname).unwrap();
        assert_eq!(stored, key);
    }

    #[test]
    fn test_setkey_invalid_base64() {
        let base64_key = "invalid_base64!";
        let result = STANDARD.decode(base64_key);
        assert!(result.is_err());
    }

    #[test]
    fn test_setkey_invalid_key_size() {
        let key = [1u8; 16]; // Wrong size
        let base64_key = STANDARD.encode(&key);
        let decoded = STANDARD.decode(&base64_key).unwrap();
        assert_eq!(decoded.len(), 16);
    }

    #[test]
    fn test_setkey_empty_nickname() {
        let nickname = "";

        let result = normalize_nick(nickname);
        assert_eq!(result, "");
    }
}
