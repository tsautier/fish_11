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
        let error_msg =
            CString::new("/echo -ts Usage: /dll fish_11.dll FiSH11_ExchangeKey <nickname>")
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
        let error_msg = CString::new("/echo -ts Error: nickname contains invalid characters")
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
            "/echo -ts Error: nickname must be 1-16 characters, start with letter/[\\]`_^{|}, contain only valid IRC characters",
        ) {
            Ok(msg) => msg,
            Err(_) => CString::new("/echo -ts Error: invalid nickname format")
                .expect("Fallback string contains no null bytes"),
        };

        unsafe {
            let _ = buffer_utils::write_cstring_to_buffer(data, buffer_size, &error_msg);
        }
        return false;
    }
    true
}
