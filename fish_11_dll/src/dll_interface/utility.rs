use std::ffi::{CStr, CString, c_char};
use std::os::raw::c_int;
use std::ptr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use log::error;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;
use x25519_dalek::PublicKey;

use crate::dll_interface::{MIRC_COMMAND, MIRC_HALT};
use crate::{buffer_utils, config};

#[no_mangle]
#[allow(non_snake_case)]
/// Display the version information of the FiSH_11 DLL
/// Can be used to test load of the DLL into mIRC
pub extern "stdcall" fn FiSH11_GetVersion(
    _m_wnd: HWND,
    _a_wnd: HWND,
    data: *mut c_char,
    _parms: *mut c_char,
    _show: BOOL,
    _nopause: BOOL,
) -> c_int {
    // Use the main version string that includes all information
    let version_info =
        format!("/echo -ts {} - Licensed under the GPL v3.", crate::FISH_MAIN_VERSION);

    let command = match CString::new(version_info) {
        Ok(cmd) => cmd,
        Err(e) => {
            error!("FiSH_11 : error : failed to create CString: {}", e);
            return MIRC_HALT;
        }
    };
    unsafe {
        if !data.is_null() {
            crate::buffer_utils::write_cstring_to_buffer(
                data, 900, // Standard mIRC buffer size
                &command,
            )
            .unwrap_or_else(|_| {
                // Fallback if buffer write fails
                ptr::copy_nonoverlapping(
                    command.as_ptr(),
                    data,
                    command.as_bytes_with_nul().len().min(899), // Leave space for null terminator
                );
            });
            // Only log at debug level so it doesn't appear in normal logging
            log::debug!(
                "FiSH_11 : command copied to data buffer: {}",
                command.to_str().unwrap_or("FiSH_11 : error converting command to string")
            );
        } else {
            error!("FiSH_11 : data buffer pointer is null.");
            return MIRC_HALT;
        }
    }

    MIRC_COMMAND
}

/// Generates a key fingerprint for the specified nickname
///
/// This function produces a human-readable fingerprint for the encryption key associated
/// with a nickname. The fingerprint can be used to verify key authenticity through a
/// separate communications channel, helping prevent man-in-the-middle attacks.
///
/// # Arguments
/// * `data` - Pointer to mIRC's buffer containing:
///   - On input: The nickname to generate a fingerprint for
///   - On output: The fingerprint string or an error message
///
/// # Returns
/// Returns `MIRC_COMMAND` (2) to execute the echo command in mIRC
///
/// # Fingerprint Generation Process
/// 1. Retrieves the 256-bit encryption key for the specified nickname
/// 2. Hashes the key using SHA-256
/// 3. Encodes the first 16 bytes of the hash in base64
/// 4. Formats output for readability with spaces every 4 characters
#[no_mangle]
#[allow(non_snake_case)]
pub extern "stdcall" fn FiSH11_GetKeyFingerprint(
    _m_wnd: HWND,
    _a_wnd: HWND,
    data: *mut c_char,
    _parms: *mut c_char,
    _show: BOOL,
    _nopause: BOOL,
) -> c_int {
    // Read nickname from input buffer
    let nickname = unsafe {
        if data.is_null() {
            error!("Data buffer pointer is null");
            return MIRC_HALT;
        }

        match CStr::from_ptr(data).to_str() {
            Ok(s) => s.trim().to_owned(),
            Err(e) => {
                error!("Invalid ANSI input: {}", e);
                return MIRC_HALT;
            }
        }
    };
    if nickname.is_empty() {
        let error_msg = CString::new("Usage: /dll fish_11.dll FiSH11_GetKeyFingerprint <nickname>")
            .expect("Failed to create usage message");

        unsafe {
            std::ptr::copy_nonoverlapping(
                error_msg.as_ptr(),
                data,
                error_msg.as_bytes_with_nul().len(),
            );
        }

        return MIRC_COMMAND;
    } // Get the key for the nickname
    match config::get_key_default(&nickname) {
        Ok(key) => {
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
            } // Format the response message
            let result = format!("/echo -ts Key fingerprint for {}: {}", nickname, formatted_fp);

            unsafe {
                crate::buffer_utils::write_string_to_buffer(data, 900, &result).unwrap_or_else(
                    |_| {
                        // Fallback on error
                        let fallback = CString::new("/echo -ts Error generating fingerprint")
                            .expect("Failed to create fingerprint error message");
                        ptr::copy_nonoverlapping(
                            fallback.as_ptr(),
                            data,
                            fallback.as_bytes_with_nul().len().min(899),
                        );
                    },
                );
            }
        }
        Err(_) => {
            // Key not found or error occurred
            let error_msg = format!("/echo -ts No key found for {}", nickname);

            unsafe {
                buffer_utils::write_string_to_buffer(data, 900, &error_msg).unwrap_or_else(|_| {
                    // Fallback on error
                    let fallback = CString::new("/echo -ts Key lookup error")
                        .expect("Failed to create key lookup error message");
                    ptr::copy_nonoverlapping(
                        fallback.as_ptr(),
                        data,
                        fallback.as_bytes_with_nul().len().min(899),
                    );
                });
            }
        }
    }
    MIRC_COMMAND
}

/// Validates that a public key is a valid Curve25519 point
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
