//! Legacy message detection for FiSH 10 compatibility
//!
//! This module provides utilities for detecting and parsing
//! legacy FiSH 10 messages in IRC traffic.

use crate::unified_error::DllError;

/// FiSH 10 + mircryption message prefixes
pub const FISH10_PREFIX: &str = "+OK ";
pub const MCPS_PREFIX: &str = "mcps ";

/// Check if a message is a legacy FiSH 10 message
pub fn is_fish10_message(message: &str) -> bool {
    let trimmed = message.trim();
    trimmed.starts_with(FISH10_PREFIX) || trimmed.starts_with(MCPS_PREFIX)
}

/// Extract the encrypted payload from a FiSH 10 message
pub fn extract_fish10_payload(message: &str) -> Result<String, DllError> {
    let trimmed = message.trim();

    let (prefix_len, prefix_name) = if trimmed.starts_with(FISH10_PREFIX) {
        (FISH10_PREFIX.len(), FISH10_PREFIX)
    } else if trimmed.starts_with(MCPS_PREFIX) {
        (MCPS_PREFIX.len(), MCPS_PREFIX)
    } else {
        return Err(DllError::LegacyError {
            context: "Message detection".to_string(),
            cause: format!(
                "Message does not start with a known legacy prefix ('{}' or '{}')",
                FISH10_PREFIX, MCPS_PREFIX
            ),
        });
    };

    // Remove the prefix
    let payload = trimmed[prefix_len..].trim();

    if payload.is_empty() {
        return Err(DllError::LegacyError {
            context: "Message parsing".to_string(),
            cause: format!("Empty payload after removing prefix '{}'", prefix_name),
        });
    }

    Ok(payload.to_string())
}

/// Check if a message might be a DH1080 key exchange message
pub fn is_dh1080_message(message: &str) -> bool {
    let trimmed = message.trim();
    trimmed.starts_with("DH1080_")
}

/// Parse DH1080 message type
pub fn parse_dh1080_message_type(message: &str) -> Option<&str> {
    let trimmed = message.trim();

    if trimmed.starts_with("DH1080_") {
        // Extract the command (INIT, FINISH, etc.)
        let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
        if !parts.is_empty() {
            let command_part = parts[0];
            // Remove "DH1080_" prefix
            if command_part.len() > 7 {
                return Some(&command_part[7..]);
            }
        }
    }

    None
}

/// Extract DH1080 public key from message
pub fn extract_dh1080_public_key(message: &str) -> Option<String> {
    let trimmed = message.trim();

    if trimmed.starts_with("DH1080_") {
        let parts: Vec<&str> = trimmed.splitn(2, ' ').collect();
        if parts.len() > 1 {
            return Some(parts[1].trim().to_string());
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fish10_message_detection() {
        assert!(is_fish10_message("+OK abc123"));
        assert!(is_fish10_message("mcps abc123"));
        assert!(is_fish10_message("  +OK def456  "));
        assert!(!is_fish10_message("Hello world"));
        assert!(!is_fish10_message("+FISH abc123"));
    }

    #[test]
    fn test_fish10_payload_extraction() {
        let result = extract_fish10_payload("+OK abc123");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "abc123");

        let result = extract_fish10_payload("mcps abc123");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "abc123");

        let result = extract_fish10_payload("  +OK  def456  ");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "def456");

        let result = extract_fish10_payload("Hello world");
        assert!(result.is_err());
    }

    #[test]
    fn test_dh1080_message_detection() {
        assert!(is_dh1080_message("DH1080_INIT abc123"));
        assert!(is_dh1080_message("DH1080_FINISH def456"));
        assert!(!is_dh1080_message("+OK abc123"));
        assert!(!is_dh1080_message("Hello world"));
    }

    #[test]
    fn test_dh1080_message_parsing() {
        let result = parse_dh1080_message_type("DH1080_INIT abc123");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "INIT");

        let result = parse_dh1080_message_type("DH1080_FINISH def456");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "FINISH");

        let result = parse_dh1080_message_type("+OK abc123");
        assert!(result.is_none());
    }

    #[test]
    fn test_dh1080_key_extraction() {
        let result = extract_dh1080_public_key("DH1080_INIT abc123");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "abc123");

        let result = extract_dh1080_public_key("DH1080_FINISH def456");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), "def456");

        let result = extract_dh1080_public_key("+OK abc123");
        assert!(result.is_none());
    }
}
