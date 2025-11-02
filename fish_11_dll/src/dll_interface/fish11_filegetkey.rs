use std::ffi::c_char;
use std::os::raw::c_int;

use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::buffer_utils;
use crate::config;
use crate::dll_function;
use crate::unified_error::DllError;
use crate::utils::{base64_encode, normalize_nick};

dll_function!(FiSH11_FileGetKey, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };

    let nickname = normalize_nick(input.trim());
    if nickname.is_empty() {
        return Err(DllError::MissingParameter("nickname".to_string()));
    }

    log::debug!("Retrieving key for nickname: {}", nickname);

    // The `?` operator will automatically convert the error from `config::get_key_default`
    // into our `DllError` type, thanks to the `From<FishError>` implementation.
    let key = config::get_key_default(&nickname)?;

    log::debug!("Key found, encoding as base64");
    let base64_key = base64_encode(&key);

    Ok(format!("/echo -ts Key for {}: {}", nickname, base64_key))
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dll_interface::MIRC_COMMAND;
    use std::ffi::CStr;
    use std::ptr;

    fn call_getkey(input: &str, buffer_size: usize) -> (c_int, String) {
        let mut buffer = vec![0i8; buffer_size];

        // Copy the input into the data buffer (mIRC style: data is input/output)
        if !input.is_empty() {
            let bytes = input.as_bytes();
            let copy_len = std::cmp::min(bytes.len(), buffer.len());
            unsafe {
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), buffer.as_mut_ptr() as *mut u8, copy_len);
            }
        }

        // Override buffer size for this test to prevent heap corruption
        let prev_size = crate::dll_interface::override_buffer_size_for_test(buffer_size);

        let result = FiSH11_FileGetKey(
            ptr::null_mut(),
            ptr::null_mut(),
            buffer.as_mut_ptr(),
            ptr::null_mut(),
            0,
            0,
        );

        // Restore previous buffer size
        crate::dll_interface::restore_buffer_size_for_test(prev_size);

        let c_str = unsafe { CStr::from_ptr(buffer.as_ptr()) };
        (result, c_str.to_string_lossy().to_string())
    }

    #[test]
    fn test_getkey_normal() {
        // Create a test key for "alice"
        let test_key = [1u8; 32];
        config::set_key_default("alice", &test_key, true).unwrap();

        let (code, msg) = call_getkey("alice", 256);
        assert_eq!(code, MIRC_COMMAND);
        // Structured check: message should start with echo and mention alice
        assert!(msg.starts_with("/echo -ts Key for alice:"));
    }

    #[test]
    fn test_getkey_nickname_empty() {
        let (code, msg) = call_getkey("   ", 256);
        assert_eq!(code, MIRC_COMMAND);
        // Structured check: message should mention empty input or missing parameter
        assert!(msg.to_lowercase().contains("empty") || msg.to_lowercase().contains("missing"));
    }

    #[test]
    fn test_getkey_key_not_found() {
        let (code, msg) = call_getkey("unknown_nick", 256);
        assert_eq!(code, MIRC_COMMAND);
        // Structured check: message should mention no encryption key
        assert!(msg.to_lowercase().contains("no encryption key"));
    }

    #[test]
    fn test_getkey_buffer_too_small() {
        // Create a test key for a short-name user
        let test_key = [1u8; 32];
        config::set_key_default("alice", &test_key, true).unwrap();

        let (code, msg) = call_getkey("alice", 8);
        // Should still return MIRC_COMMAND, but message will be truncated
        assert_eq!(code, MIRC_COMMAND);
        // Structured check: message is truncated
        assert!(msg.len() < 20);
    }

    #[test]
    fn test_getkey_malformed_input() {
        // Test with a buffer containing null byte in the middle
        let mut buffer = vec![0i8; 256];
        // Write "a\0b" to the buffer
        buffer[0] = b'a' as i8;
        buffer[1] = 0;
        buffer[2] = b'b' as i8;

        // Override buffer size for this test to prevent heap corruption
        let prev_size = crate::dll_interface::override_buffer_size_for_test(buffer.len());

        let result = FiSH11_FileGetKey(
            ptr::null_mut(),
            ptr::null_mut(),
            buffer.as_mut_ptr(),
            ptr::null_mut(),
            0,
            0,
        );

        // Restore previous buffer size
        crate::dll_interface::restore_buffer_size_for_test(prev_size);

        let c_str = unsafe { CStr::from_ptr(buffer.as_ptr()) };
        assert_eq!(result, MIRC_COMMAND);
        // The function will read "a" and try to get the key for "a"
        // It should return an error message (key not found or similar)
        assert!(c_str.to_string_lossy().len() > 0);
    }
}
