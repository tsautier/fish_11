//! Legacy FiSH 10 compatibility module
//!
//! This module provides compatibility with the legacy FiSH 10 protocol
//! using Blowfish encryption and blowfish.ini key management.


pub mod fish10_config;
pub mod fish10_encryption;
pub mod fish10_engine;
pub mod fish10_key_management;
pub mod fish10_message_detection;
pub mod fish10_integration_tests;
pub mod fish10_topics;

use crate::unified_error::DllError;
use parking_lot::RwLock;
use std::sync::Arc;
use once_cell::sync::Lazy;

/// Legacy configuration structure
#[derive(Debug, Clone)]
pub struct LegacyConfig {
    pub blowfish_ini_path: Option<String>,
    pub legacy_keys: Arc<RwLock<std::collections::HashMap<String, Vec<u8>>>>,
    pub dh1080_keys: Arc<RwLock<std::collections::HashMap<String, num_bigint::BigUint>>>,
}

impl Default for LegacyConfig {
    fn default() -> Self {
        Self {
            blowfish_ini_path: None,
            legacy_keys: Arc::new(RwLock::new(std::collections::HashMap::new())),
            dh1080_keys: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }
}



pub static LEGACY_CONFIG: Lazy<Arc<RwLock<LegacyConfig>>> =
    Lazy::new(|| Arc::new(RwLock::new(LegacyConfig::default())));

/// Initialize the legacy compatibility system
pub fn init_legacy_system() {
    log::info!("LEGACY: Initializing FiSH 10 compatibility system");

    // Load legacy configuration
    if let Err(e) = fish10_config::load_legacy_config() {
        log::warn!("LEGACY: Failed to load legacy config: {}", e);
    }

    // Initialize the FiSH 10 engine for fish_inject integration
    if let Err(e) = fish10_engine::init_fish10_engine() {
        log::warn!("LEGACY: Failed to initialize FiSH 10 engine: {}", e);
    }
}

/// Check if legacy mode is enabled for a given target
pub fn is_legacy_target(target: &str) -> bool {
    let config = LEGACY_CONFIG.read();
    let keys = config.legacy_keys.read();
    keys.contains_key(target)
}

/// Get a legacy key for a target
pub fn get_legacy_key(target: &str) -> Option<Vec<u8>> {
    let config = LEGACY_CONFIG.read();
    let keys = config.legacy_keys.read();
    keys.get(target).cloned()
}

/// Set a legacy key for a target
pub fn set_legacy_key(target: &str, key_input: &str) -> Result<(), DllError> {
    crate::legacy::fish10_key_management::set_legacy_key(target, key_input)
}

/// Get the FiSH 10 engine pointer for registration with fish_inject
pub fn get_fish10_engine_ptr() -> Option<*const fish10_engine::Fish10Engine> {
    fish10_engine::get_fish10_engine()
}

/// Get the topic encryption setting for a channel
pub fn get_encrypt_topic_setting(network: &str, channel: &str) -> Result<bool, DllError> {
    fish10_config::get_encrypt_topic_setting(network, channel)
}

/// Set the topic encryption setting for a channel
pub fn set_encrypt_topic_setting(
    network: &str,
    channel: &str,
    enabled: bool,
) -> Result<(), DllError> {
    fish10_config::set_encrypt_topic_setting(network, channel, enabled)
}

/// Set a plaintext topic for a channel in the legacy fish10 section
pub fn set_legacy_topic(channel: &str, topic: &str) -> Result<(), DllError> {
    crate::config::with_config_mut(|config| {
        fish10_topics::set_legacy_topic(config, channel, topic)
    }).map_err(DllError::from)
}

/// Get a plaintext topic for a channel from the legacy fish10 section
pub fn get_legacy_topic(channel: &str) -> Result<Option<String>, DllError> {
    crate::config::with_config(|config| {
        fish10_topics::get_legacy_topic(config, channel)
    }).map_err(DllError::from)
}

/// Remove a plaintext topic for a channel from the legacy fish10 section
pub fn remove_legacy_topic(channel: &str) -> Result<bool, DllError> {
    crate::config::with_config_mut(|config| {
        fish10_topics::remove_legacy_topic(config, channel)
    }).map_err(DllError::from)
}

#[cfg(test)]
pub mod test_utils {
    use super::*;

    /// Setup a test legacy key for testing purposes
    pub fn setup_test_legacy_key(target: &str, key: &[u8]) {
        let mut config = LEGACY_CONFIG.write();
        let mut keys = config.legacy_keys.write();
        keys.insert(target.to_string(), key.to_vec());
    }

    /// Clear all test legacy keys
    pub fn clear_test_legacy_keys() {
        let mut config = LEGACY_CONFIG.write();
        let mut keys = config.legacy_keys.write();
        keys.clear();
    }

    /// Setup a test DH1080 key for testing purposes
    pub fn setup_test_dh1080_key(target: &str, private_key: num_bigint::BigUint) {
        let mut config = LEGACY_CONFIG.write();
        let mut keys = config.dh1080_keys.write();
        keys.insert(target.to_string(), private_key);
    }

    /// Clear all test DH1080 keys
    pub fn clear_test_dh1080_keys() {
        let mut config = LEGACY_CONFIG.write();
        let mut keys = config.dh1080_keys.write();
        keys.clear();
    }
}

