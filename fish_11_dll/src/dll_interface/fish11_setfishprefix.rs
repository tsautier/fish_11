use crate::config::{get_fish11_config, update_fish11_config};
use crate::dll_function_identifier;
use crate::platform_types::{BOOL, HWND, c_char, c_int};
use crate::unified_error::DllError;

// Sets the fish prefix flag in the configuration.
// Input: <value> where 1/true enables the fish prefix, 0/false disables it
dll_function_identifier!(FiSH11_SetFishPrefix, data, {
    let value_str = unsafe { crate::buffer_utils::parse_buffer_input(data)? };

    if value_str.is_empty() {
        return Err(DllError::MissingParameter("value".to_string()));
    }

    // Parse the value as boolean
    let fish_prefix = match value_str.to_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" => false,
        _ => {
            return Err(DllError::InvalidInput {
                param: "value".to_string(),
                reason: "expected 1/true/yes/on or 0/false/no/off".to_string(),
            });
        }
    };

    // Get current config
    let mut config = get_fish11_config()?;

    // Update the fish prefix flag
    config.fish_prefix = fish_prefix;

    // Save the updated config
    update_fish11_config(config)?;

    Ok(format!("Fish prefix set to {}", if fish_prefix { "enabled" } else { "disabled" })
        .to_string())
});
