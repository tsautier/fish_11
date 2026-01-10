use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;
use crate::utils::base64_decode;
use crate::{buffer_utils, config, dll_function_identifier, log_debug};
use std::ffi::{CStr, c_char};
use std::os::raw::c_int;
use std::ptr;

// Sets a manual encryption key for a channel.
//
// IMPORTANT SECURITY NOTE: The key must be a cryptographically strong 32-byte key,
// NOT a password or passphrase. This function does NOT perform key stretching.
// If you need to use a password, you must derive a proper 32-byte key using
// a key derivation function (PBKDF2, Argon2, etc.) before calling this function.
//
// Input format: <#channel> <base64_encoded_32byte_key>
//
// Example: #secret AGN2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0
//
// Returns: Success message or error
dll_function_identifier!(FiSH11_SetManualChannelKey, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.splitn(2, ' ').collect();

    if parts.len() < 2 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "Usage: <#channel> <base64_encoded_key>. Key must be a cryptographically strong 32-byte key, not a password.".to_string(),
        });
    }

    let channel_name = parts[0];
    let key_b64 = parts[1];

    // Validate channel name format
    if !channel_name.starts_with('#') && !channel_name.starts_with('&') {
        return Err(DllError::InvalidInput {
            param: "channel".to_string(),
            reason: "Channel name must start with # or &".to_string(),
        });
    }

    // Decode the base64-encoded key
    let key_bytes = base64_decode(key_b64).map_err(|e| DllError::InvalidInput {
        param: "key".to_string(),
        reason: format!("Invalid base64 format: {}", e),
    })?;

    // Validate key length (must be 32 bytes for ChaCha20-Poly1305)
    if key_bytes.len() != 32 {
        return Err(DllError::InvalidInput {
            param: "key".to_string(),
            reason: format!("Key must be 32 bytes, got {} bytes", key_bytes.len()),
        });
    }

    // Convert to fixed-size array
    let mut key_array = [0u8; 32];
    key_array.copy_from_slice(&key_bytes);

    // Set the manual channel key (this will encrypt it and store it in the config file)
    config::set_manual_channel_key(channel_name, &key_array, true)?;

    #[cfg(debug_assertions)]
    log_debug!("Successfully set manual channel key for {}", channel_name);

    Ok(format!("Manual channel key set for {}", channel_name))
});

// Public test helper function that can be used by other modules
#[allow(dead_code)]
pub fn call_set_manual_channel_key(input: &str, buffer_size: usize) -> (c_int, String) {
    let mut buffer = vec![0i8; buffer_size];

    // Copy the input into the data buffer (mIRC style: data is input/output)
    if !input.is_empty() {
        let bytes = input.as_bytes();
        let copy_len = std::cmp::min(bytes.len(), buffer.len());

        unsafe {
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer.as_mut_ptr() as *mut u8, copy_len);
        }
    }

    // Call the actual function with proper mIRC DLL signature
    let result_code = FiSH11_SetManualChannelKey(
        ptr::null_mut(),                    // mWnd
        ptr::null_mut(),                    // aWnd
        buffer.as_mut_ptr() as *mut c_char, // data
        ptr::null_mut(),                    // show
        ptr::null_mut(),                    // nopause
        ptr::null_mut(),                    // ret_buffer_size
    );

    // Extract the result string from the buffer
    let result_cstr = unsafe { CStr::from_ptr(buffer.as_ptr() as *const c_char) };
    let result_str = result_cstr.to_string_lossy().into_owned();

    (result_code, result_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dll_interface::MIRC_COMMAND;

    #[test]
    fn test_set_manual_channel_key_normal() {
        let key = [42u8; 32];
        let key_b64 = crate::utils::base64_encode(&key);
        let input = format!("#test {}", key_b64);

        let (code, msg) = call_set_manual_channel_key(&input, 256);
        assert_eq!(code, crate::dll_interface::MIRC_IDENTIFIER);
        assert!(msg.contains("Manual channel key set"));
    }

    #[test]
    fn test_set_manual_channel_key_invalid_channel() {
        let key = [42u8; 32];
        let key_b64 = crate::utils::base64_encode(&key);
        let input = format!("invalid {}", key_b64);

        let (code, msg) = call_set_manual_channel_key(&input, 256);

        assert_eq!(code, MIRC_COMMAND);
        assert!(msg.to_lowercase().contains("channel name must start with"));
    }

    #[test]
    fn test_set_manual_channel_key_invalid_key_length() {
        let short_key = [42u8; 16]; // Wrong length
        let key_b64 = crate::utils::base64_encode(&short_key);
        let input = format!("#test {}", key_b64);

        let (code, msg) = call_set_manual_channel_key(&input, 256);

        assert_eq!(code, MIRC_COMMAND);
        assert!(msg.to_lowercase().contains("key must be 32 bytes"));
    }
}
