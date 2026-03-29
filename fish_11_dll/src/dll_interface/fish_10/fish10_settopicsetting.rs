//! FiSH 10 DLL interface for setting topic encryption setting
//!
//! This module provides the DLL interface for setting the topic encryption setting
//! for a specific network and channel.

use crate::buffer_utils;
use crate::dll_function_identifier;
use crate::platform_types::{BOOL, HWND, c_char, c_int};
use crate::unified_error::DllError;

// Set the topic encryption setting for a network/channel
// Input format: <network> <channel> <enabled>
// Where enabled is "1" to enable or "0" to disable
// Returns: "1" on success, or error message

dll_function_identifier!(FiSH10_SetTopicSetting, data, {
    // Parse input buffer safely
    let input_str = unsafe { buffer_utils::parse_buffer_input(data)? };

    // Parse input: network, channel, and enabled flag
    let parts: Vec<&str> = input_str.split_whitespace().collect();

    if parts.len() < 3 {
        return Err(DllError::LegacyError {
            context: "FiSH10_SetTopicSetting".to_string(),
            cause: "Invalid input format. Expected: <network> <channel> <enabled>".to_string(),
        });
    }

    let network = parts[0];
    let channel = parts[1];
    let enabled_str = parts[2];

    // Parse the enabled flag
    let enabled = match enabled_str {
        "1" => true,
        "0" => false,
        _ => {
            return Err(DllError::LegacyError {
                context: "FiSH10_SetTopicSetting".to_string(),
                cause: "Invalid enabled value. Expected 0 or 1".to_string(),
            });
        }
    };

    // Set the topic encryption setting
    match crate::legacy::set_encrypt_topic_setting(network, channel, enabled) {
        Ok(_) => Ok("1".to_string()),
        Err(e) => Err(DllError::LegacyError {
            context: "FiSH10_SetTopicSetting".to_string(),
            cause: format!("Failed to set topic setting: {}", e),
        }),
    }
});

#[allow(dead_code)]
fn test_set_topic_setting(input: &str) -> Result<String, DllError> {
    // Parse input: network, channel, and enabled flag
    let parts: Vec<&str> = input.split_whitespace().collect();

    if parts.len() < 3 {
        return Err(DllError::LegacyError {
            context: "FiSH10_SetTopicSetting".to_string(),
            cause: "Invalid input format. Expected: <network> <channel> <enabled>".to_string(),
        });
    }

    let network = parts[0];
    let channel = parts[1];
    let enabled_str = parts[2];

    // Parse the enabled flag
    let enabled = match enabled_str {
        "1" => true,
        "0" => false,
        _ => {
            return Err(DllError::LegacyError {
                context: "FiSH10_SetTopicSetting".to_string(),
                cause: "Invalid enabled value. Expected 0 or 1".to_string(),
            });
        }
    };

    // Set the topic encryption setting
    match crate::legacy::set_encrypt_topic_setting(network, channel, enabled) {
        Ok(_) => Ok("1".to_string()),
        Err(e) => Err(DllError::LegacyError {
            context: "FiSH10_SetTopicSetting".to_string(),
            cause: format!("Failed to set topic setting: {}", e),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Define a separate test function that mimics the behavior of the DLL function
    fn test_helper_set_topic_setting(input: &str) -> Result<String, DllError> {
        // Parse input: network, channel, and enabled flag
        let parts: Vec<&str> = input.split_whitespace().collect();

        if parts.len() < 3 {
            return Err(DllError::LegacyError {
                context: "FiSH10_SetTopicSetting".to_string(),
                cause: "Invalid input format. Expected: <network> <channel> <enabled>".to_string(),
            });
        }

        let network = parts[0];
        let channel = parts[1];
        let enabled_str = parts[2];

        // Parse the enabled flag
        let enabled = match enabled_str {
            "1" => true,
            "0" => false,
            _ => {
                return Err(DllError::LegacyError {
                    context: "FiSH10_SetTopicSetting".to_string(),
                    cause: "Invalid enabled value. Expected 0 or 1".to_string(),
                });
            }
        };

        // Set the topic encryption setting
        match crate::legacy::set_encrypt_topic_setting(network, channel, enabled) {
            Ok(_) => Ok("1".to_string()),
            Err(e) => Err(DllError::LegacyError {
                context: "FiSH10_SetTopicSetting".to_string(),
                cause: format!("Failed to set topic setting: {}", e),
            }),
        }
    }

    #[test]
    fn test_set_topic_setting() {
        // Test setting topic encryption to enabled
        let result = test_helper_set_topic_setting("testnet #testchan 1");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "1");

        // Test setting topic encryption to disabled
        let result = test_helper_set_topic_setting("testnet #testchan 0");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "1");
    }

    #[test]
    fn test_set_topic_setting_invalid_input() {
        // Test with invalid input (should return error)
        let result = test_helper_set_topic_setting("invalid");
        assert!(result.is_err());
    }

    #[test]
    fn test_set_topic_setting_invalid_enabled() {
        // Test with invalid enabled value (should return error)
        let result = test_helper_set_topic_setting("testnet #testchan 2");
        assert!(result.is_err());
    }
}
