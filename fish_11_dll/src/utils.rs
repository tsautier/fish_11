use std::ffi::{CString, c_char};

use base64;
use base64::Engine;
use rand::Rng;
use rand::rngs::OsRng;

use crate::dll_interface::NICK_VALIDATOR;
use crate::error::FishError;
use crate::{buffer_utils, log_debug, log_error, log_warn};

/// Encode binary data to a base64 string using the standard Base64 alphabet with padding.
///
/// This function takes a byte slice and returns its Base64-encoded representation
/// as defined in RFC 4648. The encoding uses `+` and `/` as the 63rd and 64th characters,
/// and includes padding `=` characters as needed.
pub fn base64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Decode base64 data to binary
///
/// Converts a base64-encoded string into its original binary form.
/// Returns an error if the input is not valid base64.
pub fn base64_decode(s: &str) -> Result<Vec<u8>, crate::error::FishError> {
    base64::engine::general_purpose::STANDARD.decode(s).map_err(|e| FishError::Base64Error(e))
}

/// Generate random bytes
pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut rng = OsRng;
    let mut bytes = vec![0u8; len];
    rng.fill(&mut bytes[..]);
    bytes
}

/// Normalize a mIRC nickname (lowercase)
pub fn normalize_nick(nick: &str) -> String {
    nick.trim().to_lowercase()
}

/// Normalize a channel or target name by stripping STATUSMSG prefixes.
///
/// IRC STATUSMSG allows sending to specific user classes in a channel using prefixes:
/// - `@#channel` - ops only
/// - `+#channel` - voiced users
/// - `%#channel` - half-ops
/// - `~#channel` - owners
/// - `&#channel` - could be server-local channel OR group target (depends on STATUSMSG)
///
/// This function strips any leading status prefix to get the actual channel name.
/// For non-channel targets (private messages), returns the input unchanged.
///
/// Examples:
/// - `@#fish_11` → `#fish_11`
/// - `+#test` → `#test`
/// - `#channel` → `#channel`
/// - `bob` → `bob`
pub fn normalize_target(target: &str) -> &str {
    let trimmed = target.trim();

    // Check if it has a status prefix followed by a channel marker
    if trimmed.len() > 1 {
        let first_char = trimmed.chars().nth(0).unwrap();
        let second_char = trimmed.chars().nth(1).unwrap();

        // If first char is a status prefix and second char is a channel marker, strip prefix
        if matches!(first_char, '@' | '+' | '%' | '~' | '&') && matches!(second_char, '#' | '&') {
            return &trimmed[1..];
        }
    }

    trimmed
}

/// Basic nickname validation (no null bytes or non-ASCII chars)
fn validate_nick_basic(nick: &str) -> Result<(), crate::error::FishError> {
    // Check for null bytes
    if nick.contains('\0') {
        return Err(crate::error::FishError::NullByteInString);
    }

    // Check for non-ASCII characters
    if let Some(c) = nick.chars().find(|c| !c.is_ascii()) {
        return Err(crate::error::FishError::NonAsciiCharacter(c));
    }

    Ok(())
}

/// Validate nickname according to IRC RFC 1459
pub fn validate_nickname(
    nickname: &str,
    data: *mut c_char,
    buffer_size: usize,
    trace_id: &str,
) -> bool {
    log_debug!("FiSH11_ExchangeKey[{}]: validating nickname: '{}'", trace_id, nickname); // Check if nickname is empty
    if nickname.is_empty() {
        log_warn!("FiSH11_ExchangeKey[{}]: empty nickname provided", trace_id);
        let error_msg = CString::new("Usage: /dll fish_11.dll FiSH11_ExchangeKey <nickname>")
            .expect("Static usage string contains no null bytes");
        unsafe {
            let _ = buffer_utils::write_cstring_to_buffer(data, buffer_size, &error_msg);
        }
        return false;
    }

    // Basic validation first
    if let Err(_) = validate_nick_basic(nickname) {
        log_error!(
            "FiSH11_ExchangeKey[{}]: nickname contains invalid characters: {}",
            trace_id,
            nickname
        );
        let error_msg = CString::new("Error: nickname contains invalid characters")
            .expect("Static error string contains no null bytes");
        unsafe {
            let _ = buffer_utils::write_cstring_to_buffer(data, buffer_size, &error_msg);
        }
        return false;
    }

    // RFC 1459 compliant validation
    if !NICK_VALIDATOR.is_match(nickname) {
        log_error!(
            "FiSH11_ExchangeKey[{}]: invalid nickname format: {} (must be 1-16 chars, start with letter/special, contain only valid IRC chars)",
            trace_id,
            nickname
        );

        // Safe CString creation with fallback
        let error_msg = match CString::new(
            "Error: nickname must be 1-16 characters, start with letter/[\\]`_^{|}, contain only valid IRC characters",
        ) {
            Ok(msg) => msg,
            Err(_) => CString::new("Error: invalid nickname format")
                .expect("Fallback string contains no null bytes"),
        };

        unsafe {
            let _ = buffer_utils::write_cstring_to_buffer(data, buffer_size, &error_msg);
        }
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_nick() {
        // Tests if nickname normalization (lowercase) works correctly.
        assert_eq!(normalize_nick("TeStNiCk"), "testnick");
        assert_eq!(normalize_nick("  AnotherNick "), "anothernick");
    }

    #[test]
    fn test_base64_roundtrip() {
        // Tests if base64 encoding and decoding preserves the original data.
        let original_data = b"some secret message with &*@# symbols";
        let encoded = base64_encode(original_data);
        let decoded = base64_decode(&encoded).expect("Base64 decoding failed");
        assert_eq!(original_data, decoded.as_slice());
    }

    #[test]
    fn test_generate_random_bytes() {
        // Tests if the function generates a byte vector of the specified length.
        assert_eq!(generate_random_bytes(0).len(), 0);
        assert_eq!(generate_random_bytes(32).len(), 32);
        assert_eq!(generate_random_bytes(128).len(), 128);
    }

    #[test]
    fn test_validate_nick_basic_ok() {
        // Tests valid nicknames.
        assert!(validate_nick_basic("SimpleNick").is_ok());
        assert!(validate_nick_basic("Nick-With-Dash").is_ok());
    }

    #[test]
    fn test_validate_nick_basic_null_byte() {
        // Tests that a nickname with a null byte is rejected.
        let result = validate_nick_basic("nick\0withnull");
        assert!(matches!(result, Err(FishError::NullByteInString)));
    }

    #[test]
    fn test_validate_nick_basic_non_ascii() {
        // Tests that a nickname with non-ASCII characters is rejected.
        let result = validate_nick_basic("nické");
        assert!(matches!(result, Err(FishError::NonAsciiCharacter('é'))));
    }
}
