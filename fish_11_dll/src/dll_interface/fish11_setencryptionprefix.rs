use crate::config::{get_fish11_config, update_fish11_config};
use crate::dll_function_identifier;
use crate::platform_types::{BOOL, HWND, c_char, c_int};
use crate::unified_error::DllError;

// Sets the encryption prefix in the configuration.
// Input: <prefix>
dll_function_identifier!(FiSH11_SetEncryptionPrefix, data, {
    let prefix = unsafe { crate::buffer_utils::parse_buffer_input(data)? };

    if prefix.is_empty() {
        return Err(DllError::MissingParameter("prefix".to_string()));
    }

    // Get current config
    let mut config = get_fish11_config()?;

    // Update the encryption prefix
    config.encryption_prefix = prefix;

    // Save the updated config
    update_fish11_config(config)?;

    Ok("Encryption prefix set successfully".to_string())
});
