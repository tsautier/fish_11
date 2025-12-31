use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;
use crate::{buffer_utils, config, dll_function_identifier};
use std::ffi::c_char;
use std::os::raw::c_int;

// Checks if a ratchet channel key exists for a channel.
//
// Input format: <#channel>
//
// Returns: "1" if key exists, "0" if not exists, or error message
dll_function_identifier!(FiSH11_HasRatchetChannelKey, data, {
    let channel_name = unsafe { buffer_utils::parse_buffer_input(data)? };

    // Validate channel name format
    if !channel_name.starts_with('#') && !channel_name.starts_with('&') {
        return Err(DllError::InvalidInput {
            param: "channel".to_string(),
            reason: "Channel name must start with # or &".to_string(),
        });
    }

    // Check if ratchet key exists
    let result = config::has_ratchet_channel_key(&channel_name);

    Ok(if result { "1" } else { "0" }.to_string())
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dll_interface::MIRC_COMMAND;
    use std::ffi::CStr;
    use std::ptr;

    fn call_has_ratchet_channel_key(input: &str, buffer_size: usize) -> (c_int, String) {
        let mut buffer = vec![0i8; buffer_size];

        // Copy the input into the data buffer (mIRC style: data is input/output)
        if !input.is_empty() {
            let bytes = input.as_bytes();
            let copy_len = std::cmp::min(bytes.len(), buffer.len());
            unsafe {
                std::ptr::copy_nonoverlapping(
                    bytes.as_ptr(),
                    buffer.as_mut_ptr() as *mut u8,
                    copy_len,
                );
            }
        }

        // Override buffer size for this test to prevent heap corruption
        let prev_size = crate::dll_interface::override_buffer_size_for_test(buffer_size);

        let result = FiSH11_HasRatchetChannelKey(
            ptr::null_mut(),
            ptr::null_mut(),
            buffer.as_mut_ptr(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
        );

        // Restore previous buffer size
        crate::dll_interface::restore_buffer_size_for_test(prev_size);

        let c_str = unsafe { CStr::from_ptr(buffer.as_ptr()) };
        (result, c_str.to_string_lossy().to_string())
    }

    #[test]
    fn test_has_ratchet_channel_key_not_exists() {
        let (code, msg) = call_has_ratchet_channel_key("#nonexistent", 256);
        assert_eq!(code, crate::dll_interface::MIRC_IDENTIFIER);
        assert_eq!(msg.trim_end_matches(char::from(0)), "0");
    }

    #[test]
    fn test_has_ratchet_channel_key_invalid_channel() {
        let (code, msg) = call_has_ratchet_channel_key("invalid", 256);
        assert_eq!(code, MIRC_COMMAND);
        assert!(msg.to_lowercase().contains("channel name must start with"));
    }
}
