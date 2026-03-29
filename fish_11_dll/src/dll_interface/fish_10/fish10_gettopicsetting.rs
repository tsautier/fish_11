//! FiSH 10 DLL interface for getting topic encryption setting
//!
//! This module provides the DLL interface for getting the topic encryption setting
//! for a specific network and channel.

use crate::platform_types::{BOOL, HWND, c_char, c_int};
use crate::unified_error::DllError;
use crate::{buffer_utils, dll_function_identifier};

// Get the topic encryption setting for a network/channel
// Input format: <network> <channel>
// Returns: "1" if topic encryption is enabled, "0" if disabled, or error message

dll_function_identifier!(FiSH10_GetTopicSetting, data, {
    // Parse input buffer safely
    let input_str = unsafe { buffer_utils::parse_buffer_input(data)? };

    // Parse input: network and channel
    let parts: Vec<&str> = input_str.split_whitespace().collect();

    if parts.len() < 2 {
        return Err(DllError::LegacyError {
            context: "FiSH10_GetTopicSetting".to_string(),
            cause: "Invalid input format. Expected: <network> <channel>".to_string(),
        });
    }

    let network = parts[0];
    let channel = parts[1];

    // Get the topic encryption setting
    match crate::legacy::get_encrypt_topic_setting(network, channel) {
        Ok(enabled) => {
            if enabled {
                Ok("1".to_string())
            } else {
                Ok("0".to_string())
            }
        }
        Err(e) => Err(DllError::LegacyError {
            context: "FiSH10_GetTopicSetting".to_string(),
            cause: format!("Failed to get topic setting: {}", e),
        }),
    }
});

#[cfg(test)]
mod tests {
    // Note: The FiSH10_GetTopicSetting function is a DLL export that requires
    // raw pointer arguments and cannot be easily tested directly.
    // Integration tests should be performed through the DLL interface.
}
