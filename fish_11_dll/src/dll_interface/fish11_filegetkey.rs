use std::ffi::c_char;
use std::os::raw::c_int;

use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::buffer_utils;
use crate::config;
use crate::dll_function;
use crate::dll_interface::MIRC_COMMAND;
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
    use std::ffi::{CStr, CString};
    use std::ptr;

    fn call_getkey(input: &str, buffer_size: usize) -> (c_int, String) {
        let mut buffer = vec![0i8; buffer_size];

        // Override buffer size for this test to prevent heap corruption
        let prev_size = crate::dll_interface::override_buffer_size_for_test(buffer_size);

        let c_input = CString::new(input).unwrap();
        let result = FiSH11_FileGetKey(
            ptr::null_mut(),
            ptr::null_mut(),
            buffer.as_mut_ptr(),
            c_input.as_ptr() as *mut c_char,
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
        // Suppose "alice" exists in config
        let (code, msg) = call_getkey("alice", 256);
        assert_eq!(code, MIRC_COMMAND);
        assert!(msg.contains("Key for alice:"));
    }

    #[test]
    fn test_getkey_nickname_empty() {
        let (code, msg) = call_getkey("   ", 256);
        assert_eq!(code, MIRC_COMMAND);
        assert!(msg.to_lowercase().contains("missing parameter"));
    }

    #[test]
    fn test_getkey_key_not_found() {
        let (code, msg) = call_getkey("unknown_nick", 256);
        assert_eq!(code, MIRC_COMMAND);
        assert!(msg.to_lowercase().contains("no encryption key"));
    }

    #[test]
    fn test_getkey_buffer_too_small() {
        let (code, msg) = call_getkey("alice", 8);
        // Should still return MIRC_COMMAND, but message will be truncated
        assert_eq!(code, MIRC_COMMAND);
        assert!(msg.len() < 20); // Message is truncated
    }

    #[test]
    fn test_getkey_malformed_input() {
        // Input with null byte (should error)
        let bad_input = unsafe { CString::from_vec_unchecked(vec![97, 0, 98]) }; // "a\0b"
        let mut buffer = vec![0i8; 256];

        // Override buffer size for this test to prevent heap corruption
        let prev_size = crate::dll_interface::override_buffer_size_for_test(buffer.len());

        let result = FiSH11_FileGetKey(
            ptr::null_mut(),
            ptr::null_mut(),
            buffer.as_mut_ptr(),
            bad_input.as_ptr() as *mut c_char,
            0,
            0,
        );

        // Restore previous buffer size
        crate::dll_interface::restore_buffer_size_for_test(prev_size);

        let c_str = unsafe { CStr::from_ptr(buffer.as_ptr()) };
        assert_eq!(result, MIRC_COMMAND);
        assert!(c_str.to_string_lossy().to_lowercase().contains("null byte"));
    }
}
