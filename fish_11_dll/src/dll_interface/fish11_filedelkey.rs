use std::ffi::c_char;
use std::os::raw::c_int;

use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::buffer_utils;
use crate::config;
use crate::dll_function;
use crate::dll_interface::MIRC_COMMAND;
use crate::unified_error::DllError;
use crate::utils::normalize_nick;

dll_function!(FiSH11_FileDelKey, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };

    let nickname = normalize_nick(input.trim());
    if nickname.is_empty() {
        return Err(DllError::MissingParameter("nickname".to_string()));
    }

    log::info!("Key deletion requested for nickname: {}", nickname);

    // The `?` operator handles any errors during deletion.
    config::delete_key_default(&nickname)?;

    let message = format!("/echo -ts Key deleted for {}", nickname);
    log::info!("{}", message);

    Ok(message)
});

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::{CStr, CString};
    use std::ptr;

    fn call_delkey(input: &str, buffer_size: usize) -> (c_int, String) {
        let mut buffer = vec![0i8; buffer_size];
        let c_input = CString::new(input).unwrap();
        let result = FiSH11_FileDelKey(
            ptr::null_mut(),
            ptr::null_mut(),
            buffer.as_mut_ptr(),
            c_input.as_ptr() as *mut c_char,
            0,
            0,
        );

        let c_str = unsafe { CStr::from_ptr(buffer.as_ptr()) };
        (result, c_str.to_string_lossy().to_string())
    }

    #[test]
    fn test_delkey_normal() {
        // Suppose "bob" exists in config
        let (code, msg) = call_delkey("bob", 256);
        assert_eq!(code, MIRC_COMMAND);
        assert!(msg.contains("Key deleted for bob"));
    }

    #[test]
    fn test_delkey_nickname_empty() {
        let (code, msg) = call_delkey("   ", 256);
        assert_eq!(code, MIRC_COMMAND);
        assert!(msg.to_lowercase().contains("missing parameter"));
    }

    #[test]
    fn test_delkey_key_not_found() {
        let (code, msg) = call_delkey("unknown_nick", 256);
        assert_eq!(code, MIRC_COMMAND);
        assert!(msg.to_lowercase().contains("no encryption key"));
    }

    #[test]
    fn test_delkey_buffer_too_small() {
        let (code, msg) = call_delkey("bob", 8);
        assert_eq!(code, MIRC_COMMAND);
        assert!(msg.len() < 20);
    }

    #[test]
    fn test_delkey_malformed_input() {
        let bad_input = unsafe { CString::from_vec_unchecked(vec![97, 0, 98]) }; // "a\0b"
        let mut buffer = vec![0i8; 256];
        let result = FiSH11_FileDelKey(
            ptr::null_mut(),
            ptr::null_mut(),
            buffer.as_mut_ptr(),
            bad_input.as_ptr() as *mut c_char,
            0,
            0,
        );

        let c_str = unsafe { CStr::from_ptr(buffer.as_ptr()) };
        assert_eq!(result, MIRC_COMMAND);
        assert!(c_str.to_string_lossy().to_lowercase().contains("null byte"));
    }
}
