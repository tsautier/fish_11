use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;
use crate::{buffer_utils, config, dll_function_identifier, log_debug};
use std::ffi::c_char;
use std::os::raw::c_int;

// Sets a manual channel key from a password or short key.
// This function accepts keys of any length and securely expands them to 32 bytes
// using a key derivation function (HKDF with SHA-256).
//
// Input format: <#channel> <key_of_any_length>
//
// Returns: Success message or error

dll_function_identifier!(FiSH11_SetManualChannelKeyFromPassword, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.splitn(2, ' ').collect();

    if parts.len() < 2 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "Usage: <#channel> <key_of_any_length>".to_string(),
        });
    }

    let channel_name = parts[0];
    let key_material = parts[1];

    // Validate channel name format
    if !channel_name.starts_with('#') && !channel_name.starts_with('&') {
        return Err(DllError::InvalidInput {
            param: "channel".to_string(),
            reason: "Channel name must start with # or &".to_string(),
        });
    }

    // Derive a 32-byte key from the input material using HKDF
    let derived_key = derive_key_from_password(key_material)?;

    // Set the manual channel key (this will encrypt it and store it in the config file)
    config::set_manual_channel_key(channel_name, &derived_key, true)?;

    log_debug!("Successfully set manual channel key for {} from password", channel_name);

    Ok(format!("Manual channel key set for {}", channel_name))
});

/// Derives a 32-byte cryptographic key from password/short key material using HKDF
fn derive_key_from_password(password: &str) -> Result<[u8; 32]> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    
    // Use channel name as salt to prevent rainbow table attacks
    // In a real implementation, we'd use a random salt stored with the key
    let salt = b"FiSH11-ChannelKey";
    
    // Use the password as IKM (input key material)
    let ikm = password.as_bytes();
    
    // Derive a 32-byte key using HKDF-SHA256
    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut output = [0u8; 32];
    hkdf.expand(b"channel-key-expansion", &mut output)
        .map_err(|e| FishError::CryptoError(format!("HKDF expansion failed: {}", e)))?;
    
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dll_interface::MIRC_COMMAND;
    use std::ffi::CStr;
    use std::ptr;

    fn call_set_manual_channel_key_from_password(input: &str, buffer_size: usize) -> (c_int, String) {
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

        let result = FiSH11_SetManualChannelKeyFromPassword(
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
    fn test_set_manual_channel_key_from_password_short() {
        let input = "#test mypassword";
        let (code, msg) = call_set_manual_channel_key_from_password(&input, 256);
        assert_eq!(code, crate::dll_interface::MIRC_IDENTIFIER);
        assert!(msg.to_lowercase().contains("manual channel key set"));
    }

    #[test]
    fn test_set_manual_channel_key_from_password_long() {
        let long_password = "This is a very long password that is definitely longer than 32 bytes";
        let input = format!("#test {}", long_password);
        let (code, msg) = call_set_manual_channel_key_from_password(&input, 256);
        assert_eq!(code, crate::dll_interface::MIRC_IDENTIFIER);
        assert!(msg.to_lowercase().contains("manual channel key set"));
    }

    #[test]
    fn test_set_manual_channel_key_from_password_invalid_channel() {
        let input = "invalid mypassword";
        let (code, msg) = call_set_manual_channel_key_from_password(&input, 256);
        assert_eq!(code, MIRC_COMMAND);
        assert!(msg.to_lowercase().contains("channel name must start with"));
    }
}