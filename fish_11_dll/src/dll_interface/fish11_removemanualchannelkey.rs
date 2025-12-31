use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;
use crate::{buffer_utils, config, dll_function_identifier, log_debug};
use std::ffi::c_char;
use std::os::raw::c_int;

// Removes a manual channel key for a channel.
//
// Input format: <#channel>
//
// Returns: Success message or error

dll_function_identifier!(FiSH11_RemoveManualChannelKey, data, {
    let channel_name = unsafe { buffer_utils::parse_buffer_input(data)? };
    
    // Validate channel name format
    if !channel_name.starts_with('#') && !channel_name.starts_with('&') {
        return Err(DllError::InvalidInput {
            param: "channel".to_string(),
            reason: "Channel name must start with # or &".to_string(),
        });
    }
    
    // Remove the manual channel key
    config::remove_manual_channel_key(&channel_name)?;
    
    log_debug!("Successfully removed manual channel key for {}", channel_name);
    
    Ok(format!("Manual channel key removed for {}", channel_name))
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dll_interface::MIRC_COMMAND;
    use std::ffi::CStr;
    use std::ptr;

    fn call_remove_manual_channel_key(input: &str, buffer_size: usize) -> (c_int, String) {
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

        let result = FiSH11_RemoveManualChannelKey(
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
    fn test_remove_manual_channel_key_invalid_channel() {
        let (code, msg) = call_remove_manual_channel_key("invalid", 256);
        assert_eq!(code, MIRC_COMMAND);
        assert!(msg.to_lowercase().contains("channel name must start with"));
    }

    #[test]
    fn test_remove_manual_channel_key_nonexistent() {
        let (code, msg) = call_remove_manual_channel_key("#nonexistent", 256);
        // Should succeed even if key doesn't exist (idempotent operation)
        assert_eq!(code, crate::dll_interface::MIRC_IDENTIFIER);
        assert!(msg.to_lowercase().contains("manual channel key removed"));
    }
}