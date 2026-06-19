//! Legacy FiSH 10 topic management for plaintext topics
//!
//! This module handles the storage and retrieval of plaintext topics for legacy FiSH 10 in the configuration.
//! It allows users to save topics in plaintext format and retrieve them later.

use chrono;

use crate::config::FishConfig;
use crate::error::FishError;

/// Set a plaintext topic for a channel in the legacy fish10 section
pub fn set_legacy_topic(
    config: &mut FishConfig,
    channel: &str,
    topic: &str,
) -> Result<(), FishError> {
    // Validate inputs
    if channel.is_empty() {
        return Err(FishError::InvalidInput("channel name cannot be empty".to_string()));
    }

    if topic.is_empty() {
        return Err(FishError::InvalidInput("topic cannot be empty".to_string()));
    }

    // Normalize channel name (lowercase for consistency)
    let normalized_channel = channel.to_lowercase();

    // Store the topic in the configuration under a legacy fish10 section
    // We'll use a specific prefix to distinguish these from other topics
    let key = format!("fish10_topic_{}", normalized_channel);
    config.entries.insert(
        key,
        crate::config::models::EntryData {
            key: Some(topic.to_string()),
            date: Some(chrono::Utc::now().to_rfc3339()),
            is_exchange: None, // Not an exchange key
        },
    );

    // Mark config as dirty to trigger save
    config.mark_dirty();

    Ok(())
}

/// Get a plaintext topic for a channel from the legacy fish10 section
pub fn get_legacy_topic(config: &FishConfig, channel: &str) -> Result<Option<String>, FishError> {
    // Validate input
    if channel.is_empty() {
        return Err(FishError::InvalidInput("channel name cannot be empty".to_string()));
    }

    // Normalize channel name (lowercase for consistency)
    let normalized_channel = channel.to_lowercase();

    // Retrieve the topic from the configuration
    let key = format!("fish10_topic_{}", normalized_channel);

    match config.entries.get(&key) {
        Some(entry_data) => {
            if let Some(ref topic) = entry_data.key {
                Ok(Some(topic.clone()))
            } else {
                Ok(None)
            }
        }
        None => Ok(None),
    }
}

/// Remove a plaintext topic for a channel from the legacy fish10 section
pub fn remove_legacy_topic(config: &mut FishConfig, channel: &str) -> Result<bool, FishError> {
    // Validate input
    if channel.is_empty() {
        return Err(FishError::InvalidInput("channel name cannot be empty".to_string()));
    }

    // Normalize channel name (lowercase for consistency)
    let normalized_channel = channel.to_lowercase();

    // Remove the topic from the configuration
    let key = format!("fish10_topic_{}", normalized_channel);
    let removed = config.entries.remove(&key).is_some();

    if removed {
        // Mark config as dirty to trigger save
        config.mark_dirty();
    }

    Ok(removed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FishConfig;

    #[test]
    fn test_set_and_get_legacy_topic() {
        let mut config = FishConfig::new();

        // Set a topic
        let result = set_legacy_topic(&mut config, "#test", "This is a test topic");
        assert!(result.is_ok());

        // Get the topic
        let topic = get_legacy_topic(&config, "#test").unwrap();
        assert_eq!(topic, Some("This is a test topic".to_string()));
    }

    #[test]
    fn test_remove_legacy_topic() {
        let mut config = FishConfig::new();

        // Set a topic
        set_legacy_topic(&mut config, "#test", "This is a test topic").unwrap();

        // Verify it exists
        assert!(get_legacy_topic(&config, "#test").unwrap().is_some());

        // Remove the topic
        let removed = remove_legacy_topic(&mut config, "#test").unwrap();
        assert!(removed);

        // Verify it's gone
        assert!(get_legacy_topic(&config, "#test").unwrap().is_none());
    }

    #[test]
    fn test_case_insensitive_channels() {
        let mut config = FishConfig::new();

        // Set a topic with lowercase channel
        set_legacy_topic(&mut config, "#Test", "This is a test topic").unwrap();

        // Get the topic with different case
        let topic = get_legacy_topic(&config, "#TEST").unwrap();
        assert_eq!(topic, Some("This is a test topic".to_string()));
    }

    #[test]
    fn test_empty_inputs() {
        let mut config = FishConfig::new();

        // Test empty channel
        let result = set_legacy_topic(&mut config, "", "topic");
        assert!(result.is_err());

        // Test empty topic
        let result = set_legacy_topic(&mut config, "#test", "");
        assert!(result.is_err());

        // Test empty channel for get
        let result = get_legacy_topic(&config, "");
        assert!(result.is_err());
    }
}
