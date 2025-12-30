// Core key management module
// Provides MasterKey, ConfigKey, and LogKey functionality

pub mod config_key;
pub mod log_key;
pub mod master_key;
use once_cell::sync::Lazy;
use std::sync::Mutex;

/// Global key system state
struct KeySystemState {
    master_key: Option<MasterKey>,
    config_key: Option<ConfigKey>,
    log_key: Option<LogKey>,
}

static KEY_SYSTEM: Lazy<Mutex<KeySystemState>> =
    Lazy::new(|| Mutex::new(KeySystemState { master_key: None, config_key: None, log_key: None }));

/// Initialize the key system with a master password
pub fn initialize_key_system(password: &str, salt: &[u8]) {
    let mut state = KEY_SYSTEM.lock().unwrap();
    state.master_key = Some(MasterKey::new(password, salt));
    state.config_key = Some(ConfigKey::new_from_master(state.master_key.as_ref().unwrap()));
    state.log_key = Some(LogKey::new_from_master(state.master_key.as_ref().unwrap()));
}

/// Get the global master key (for internal use)
fn get_master_key() -> Option<MasterKey> {
    let state = KEY_SYSTEM.lock().unwrap();
    state.master_key.clone()
}

/// Lock the entire key system
pub fn lock_key_system() {
    let mut state = KEY_SYSTEM.lock().unwrap();
    if let Some(mut key) = state.master_key.take() {
        key.lock();
    }
    state.config_key = None;
    state.log_key = None;
}

/// Check if key system is unlocked
pub fn is_key_system_unlocked() -> bool {
    let state = KEY_SYSTEM.lock().unwrap();
    state.master_key.as_ref().map_or(false, |k| k.is_unlocked())
}

/// Get a config key derived from the master key
pub fn get_config_key() -> Option<ConfigKey> {
    let state = KEY_SYSTEM.lock().unwrap();
    state.config_key.clone()
}

/// Get a log key derived from the master key
pub fn get_log_key() -> Option<LogKey> {
    let state = KEY_SYSTEM.lock().unwrap();
    state.log_key.clone()
}

/// Rotate all keys in the system
pub fn rotate_all_keys() {
    let master_key = {
        let state = KEY_SYSTEM.lock().unwrap();
        state.master_key.as_ref().cloned()
    };

    if let Some(master_key) = master_key {
        let mut state = KEY_SYSTEM.lock().unwrap();
        state.config_key = Some(ConfigKey::new_from_master(&master_key));
        state.log_key = Some(LogKey::new_from_master(&master_key));
    }
}

// Public exports for the core key system
pub use config_key::ConfigKey;
pub use log_key::{LogKey, LogRotationPolicy};
pub use master_key::MasterKey;

pub use config_key::ConfigKeyGuard;
pub use log_key::LogKeyGuard;
pub use master_key::MasterKeyGuard;
