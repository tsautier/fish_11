//! Legacy FiSH 10 compatibility module
//!
//! This module provides compatibility with the legacy FiSH 10 protocol
//! using Blowfish encryption and blowfish.ini key management.

pub mod blowfish;
pub mod config;
pub mod dh1080;
pub mod encryption;
pub mod fish10_engine;
pub mod key_management;
pub mod message_detection;

use parking_lot::RwLock;
use std::sync::Arc;

/// Legacy configuration structure
#[derive(Debug, Clone)]
pub struct LegacyConfig {
    pub blowfish_ini_path: Option<String>,
    pub legacy_keys: Arc<RwLock<std::collections::HashMap<String, Vec<u8>>>>,
    pub dh1080_keys: Arc<RwLock<std::collections::HashMap<String, Vec<u8>>>>,
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

/// Global legacy configuration instance
use once_cell::sync::Lazy;
pub static LEGACY_CONFIG: Lazy<Arc<RwLock<LegacyConfig>>> =
    Lazy::new(|| Arc::new(RwLock::new(LegacyConfig::default())));

/// Initialize the legacy compatibility system
pub fn init_legacy_system() {
    log::info!("LEGACY: Initializing FiSH 10 compatibility system");

    // Load legacy configuration
    if let Err(e) = config::load_legacy_config() {
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

/// Get the FiSH 10 engine pointer for registration with fish_inject
pub fn get_fish10_engine_ptr() -> Option<*const fish10_engine::Fish10Engine> {
    fish10_engine::get_fish10_engine()
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
    pub fn setup_test_dh1080_key(target: &str, private_key: Vec<u8>) {
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
