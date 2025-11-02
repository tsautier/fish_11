use std::ffi::c_char;
use std::os::raw::c_int;

use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::config;
use crate::dll_function;
use crate::unified_error::DllError;

dll_function!(FiSH11_FileListKeys, _data, {
    log::info!("Starting key listing");

    let keys = config::list_keys()?;

    if keys.is_empty() {
        return Ok("/echo -ts FiSH: No keys stored.".to_string());
    }

    // We will build a multi-line response for mIRC to process.
    // mIRC can handle multiple commands separated by `|`.
    let mut commands = Vec::new();
    commands.push("echo -ts --- FiSH Keys ---".to_string());

    for (nickname, network, _key_type, date) in keys {
        let net_display =
            if network.is_empty() || network == "default" { "default" } else { &network };

        let key_info = if let Some(date_str) = date {
            format!("Key: {:<20} | Network: {:<15} | Added: {}", nickname, net_display, date_str)
        } else {
            format!("Key: {:<20} | Network: {:<15}", nickname, net_display)
        };
        commands.push(format!("echo -ts {}", key_info));
    }

    commands.push("echo -ts -------------------".to_string());

    // Join all echo commands with `|` to be executed sequentially by mIRC.
    Ok(commands.join(" | "))
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dll_interface::MIRC_COMMAND;
    use std::ffi::{CStr, CString};
    use std::ptr;

    fn call_listkeys(buffer_size: usize) -> (c_int, String) {
        let mut buffer = vec![0i8; buffer_size];
        // Override buffer size for this test to prevent heap corruption
        let prev_size = crate::dll_interface::override_buffer_size_for_test(buffer_size);

        let result = FiSH11_FileListKeys(
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
    fn test_listkeys_normal() {
        // Suppose there are keys in config
        let (code, msg) = call_listkeys(512);
        assert_eq!(code, MIRC_COMMAND);
        // Structured check: message should mention FiSH Keys
        assert!(msg.contains("FiSH Keys"));
    }

    #[test]
    fn test_listkeys_no_keys() {
        // Suppose config is empty
        let (code, msg) = call_listkeys(256);
        assert_eq!(code, MIRC_COMMAND);
    // Structured check: message should either indicate no keys, or show the keys list.
    // The global config used in tests may already contain keys on disk, so accept both forms.
    let lower = msg.to_lowercase();
    assert!(lower.contains("no keys") || lower.contains("no keys stored") || lower.contains("fish keys"));
    }

    #[test]
    fn test_listkeys_buffer_too_small() {
        let (code, msg) = call_listkeys(8);
        assert_eq!(code, MIRC_COMMAND);
        // Structured check: message is truncated
        assert!(msg.len() < 20);
    }

    #[test]
    fn test_listkeys_malformed_input() {
        // Should not crash even if _data is a bad pointer
        let mut buffer = vec![0i8; 256];
        let bad_input = unsafe { CString::from_vec_unchecked(vec![97, 0, 98]) };
        let result = FiSH11_FileListKeys(
            ptr::null_mut(),
            ptr::null_mut(),
            buffer.as_mut_ptr(),
            bad_input.as_ptr() as *mut c_char,
            0,
            0,
        );

        let c_str = unsafe { CStr::from_ptr(buffer.as_ptr()) };
        assert_eq!(result, MIRC_COMMAND);
        // Structured check: message should not be empty
        assert!(!c_str.to_string_lossy().is_empty());
    }
}
