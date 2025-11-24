use crate::log_debug;
use crate::platform_types::{BOOL, HWND};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha256};
use std::ffi::c_char;
use std::os::raw::c_int;
use subtle::ConstantTimeEq;

use x25519_dalek::PublicKey;

use crate::dll_function_identifier;
use crate::unified_error::DllError;
use crate::utils::normalize_nick;
use crate::config::key_management::check_key_expiry;
use crate::{buffer_utils, config};

dll_function_identifier!(FiSH11_GetKeyFingerprint, data, {
    // Parse input to get the nickname
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let nickname = normalize_nick(input.trim());

    if nickname.is_empty() {
        return Err(DllError::MissingParameter("nickname".to_string()));
    }

    log::info!("Generating key fingerprint for: {}", nickname);

    // Get the key for the nickname
    let key = config::get_key_default(&nickname)?;

    log_debug!("Retrieved key, generating SHA-256 hash");

    // Generate fingerprint using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(&key);
    let hash = hasher.finalize();

    // Take first 16 bytes of the hash and encode as base64
    let fp_base64 = BASE64.encode(&hash[0..16]);

    // Format with spaces for readability (groups of 4 chars)
    let mut formatted_fp = String::with_capacity(24); // 16 chars + 3 spaces
    for (i, c) in fp_base64.chars().take(16).enumerate() {
        if i > 0 && i % 4 == 0 {
            formatted_fp.push(' ');
        }
        formatted_fp.push(c);
    }

    log::info!("Generated fingerprint for {}: {}", nickname, formatted_fp);

    // Return the fingerprint string as data (no /echo)
    Ok(format!("Key fingerprint for {}: {}", nickname, formatted_fp))
});

/// Parsed input from the DLL interface.
pub struct ParsedInput<'a> {
    pub target: &'a str,
    pub message: &'a str,
}

/// Parses the input string into target and message parts.
///
/// Expected format: `<target> <message>`
pub fn parse_input(input: &str) -> Result<ParsedInput, DllError> {
    let parts: Vec<&str> = input.splitn(2, ' ').collect();

    if parts.len() < 2 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "expected format: <target> <message>".to_string(),
        });
    }

    let target_raw = parts[0];
    let message = parts[1];

    // Normalize target to strip STATUSMSG prefixes (@#chan, +#chan, etc.)
    let target = crate::utils::normalize_target(target_raw);

    if target.is_empty() {
        return Err(DllError::MissingParameter("target".to_string()));
    }
    if message.is_empty() {
        return Err(DllError::MissingParameter("message".to_string()));
    }

    Ok(ParsedInput { target, message })
}

/// Retrieves and validates the private key for a given nickname.
pub fn get_private_key(nickname: &str) -> Result<[u8; 32], DllError> {
    // Check for key expiration before attempting to use it.
    check_key_expiry(nickname, None)?;

    let key_vec = config::get_key(nickname, None)?;
    let key: [u8; 32] = key_vec.as_slice().try_into().map_err(|_| DllError::InvalidInput {
        param: "key".to_string(),
        reason: format!("Key for {} must be exactly 32 bytes, got {}", nickname, key_vec.len()),
    })?;

    Ok(key)
}

/// Normalizes a nickname for private message operations.
pub fn normalize_private_target(target: &str) -> Result<String, DllError> {
    let nickname = normalize_nick(target);
    if nickname.is_empty() {
        return Err(DllError::MissingParameter("nickname".to_string()));
    }
    Ok(nickname)
}

/// Validates that a public key is a valid Curve25519 point
#[allow(dead_code)]
fn validate_public_key(bytes: &[u8; 32]) -> crate::error::Result<()> {
    // Check that it's not all zeros using constant-time comparison
    if bool::from(bytes.ct_eq(&[0u8; 32])) {
        return Err(crate::error::FishError::InvalidInput("Public key is all zeros".to_string()));
    }

    // Known low-order points on Curve25519 that should be rejected
    // These are points of order 1, 2, 4, and 8
    const LOW_ORDER_POINTS: [[u8; 32]; 8] = [
        // Point of order 1 (identity)
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
        // Point of order 2
        [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
        // Point of order 4 (variant 1)
        [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ],
        // Point of order 4 (variant 2)
        [
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
            0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
            0xd0, 0x9f, 0x11, 0x57,
        ],
        // Point of order 8 (variant 1)
        [
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        // Point of order 8 (variant 2)
        [
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        // Point of order 8 (variant 3)
        [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        // Point of order 8 (variant 4)
        [
            0xcd, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x80,
        ],
    ];

    // Check if the point matches any known low-order point using constant-time comparison
    for low_order_point in &LOW_ORDER_POINTS {
        if bool::from(bytes.ct_eq(low_order_point)) {
            return Err(crate::error::FishError::InvalidInput(
                "Public key is a low-order point and rejected for security".to_string(),
            ));
        }
    }

    // Attempt to construct a PublicKey - will succeed if valid format
    let _ = PublicKey::from(*bytes);

    // Return Ok if no issues
    Ok(())
}
