//! Topic management for plaintext topics
//!
//! This module handles the storage and retrieval of plaintext topics in the configuration.
//! It allows users to save topics in plaintext format and retrieve them later.

//use std::collections::HashMap;

use crate::config::FishConfig;
use crate::error::FishError;

/// Set a plaintext topic for a channel
pub fn set_topic(config: &mut FishConfig, channel: &str, topic: &str) -> Result<(), FishError> {
    // Validate inputs
    if channel.is_empty() {
        return Err(FishError::InvalidInput("channel name cannot be empty".to_string()));
    }

    if topic.is_empty() {
        return Err(FishError::InvalidInput("topic cannot be empty".to_string()));
    }

    // Normalize channel name (lowercase for consistency)
    let normalized_channel = channel.to_lowercase();

    // Store the topic in the configuration
    config.topics.insert(normalized_channel, topic.to_string());

    // Mark config as dirty to trigger save
    config.mark_dirty();

    Ok(())
}

/// Get a plaintext topic for a channel
pub fn get_topic(config: &FishConfig, channel: &str) -> Result<Option<String>, FishError> {
    // Validate input
    if channel.is_empty() {
        return Err(FishError::InvalidInput("channel name cannot be empty".to_string()));
    }

    // Normalize channel name (lowercase for consistency)
    let normalized_channel = channel.to_lowercase();

    // Retrieve the topic from the configuration
    match config.topics.get(&normalized_channel) {
        Some(topic) => Ok(Some(topic.clone())),
        None => Ok(None),
    }
}

/// Remove a plaintext topic for a channel
pub fn remove_topic(config: &mut FishConfig, channel: &str) -> Result<bool, FishError> {
    // Validate input
    if channel.is_empty() {
        return Err(FishError::InvalidInput("channel name cannot be empty".to_string()));
    }

    // Normalize channel name (lowercase for consistency)
    let normalized_channel = channel.to_lowercase();

    // Remove the topic from the configuration
    let removed = config.topics.remove(&normalized_channel).is_some();

    if removed {
        // Mark config as dirty to trigger save
        config.mark_dirty();
    }

    Ok(removed)
}

/// List all stored topics
pub fn list_topics(config: &FishConfig) -> Result<Vec<(String, String)>, FishError> {
    let mut topics_list: Vec<(String, String)> = Vec::new();

    for (channel, topic) in &config.topics {
        topics_list.push((channel.clone(), topic.clone()));
    }

    Ok(topics_list)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::FishConfig;

    #[test]
    fn test_set_and_get_topic() {
        let mut config = FishConfig::new();

        // Set a topic
        let result = set_topic(&mut config, "#test", "This is a test topic");
        assert!(result.is_ok());

        // Get the topic
        let topic = get_topic(&config, "#test").unwrap();
        assert_eq!(topic, Some("This is a test topic".to_string()));
    }

    #[test]
    fn test_remove_topic() {
        let mut config = FishConfig::new();

        // Set a topic
        set_topic(&mut config, "#test", "This is a test topic").unwrap();

        // Verify it exists
        assert!(get_topic(&config, "#test").unwrap().is_some());

        // Remove the topic
        let removed = remove_topic(&mut config, "#test").unwrap();
        assert!(removed);

        // Verify it's gone
        assert!(get_topic(&config, "#test").unwrap().is_none());
    }

    #[test]
    fn test_case_insensitive_channels() {
        let mut config = FishConfig::new();

        // Set a topic with lowercase channel
        set_topic(&mut config, "#Test", "This is a test topic").unwrap();

        // Get the topic with different case
        let topic = get_topic(&config, "#TEST").unwrap();
        assert_eq!(topic, Some("This is a test topic".to_string()));
    }

    #[test]
    fn test_empty_inputs() {
        let mut config = FishConfig::new();

        // Test empty channel
        let result = set_topic(&mut config, "", "topic");
        assert!(result.is_err());

        // Test empty topic
        let result = set_topic(&mut config, "#test", "");
        assert!(result.is_err());

        // Test empty channel for get
        let result = get_topic(&config, "");
        assert!(result.is_err());
    }
}
