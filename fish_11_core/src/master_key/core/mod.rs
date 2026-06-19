// Core key management module
// Provides MasterKey and ConfigKey functionality

pub mod config_key;
pub mod master_key;
use once_cell::sync::Lazy;
use std::sync::Mutex;

/// Global key system state
struct KeySystemState {
    master_key: Option<MasterKey>,
    config_key: Option<ConfigKey>,
}

static KEY_SYSTEM: Lazy<Mutex<KeySystemState>> =
    Lazy::new(|| Mutex::new(KeySystemState { master_key: None, config_key: None }));

/// Initialize the key system with a master password
pub fn initialize_key_system(password: &str, salt: &[u8]) {
    let mut state = KEY_SYSTEM.lock().unwrap();
    state.master_key = Some(MasterKey::new(password, salt));
    state.config_key = Some(ConfigKey::new_from_master(state.master_key.as_ref().unwrap()));
}

/// Lock the entire key system
pub fn lock_key_system() {
    let mut state = KEY_SYSTEM.lock().unwrap();
    if let Some(mut key) = state.master_key.take() {
        key.lock();
    }
    state.config_key = None;
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

/// Rotate all keys in the system
pub fn rotate_all_keys() {
    let master_key = {
        let state = KEY_SYSTEM.lock().unwrap();
        state.master_key.as_ref().cloned()
    };

    if let Some(master_key) = master_key {
        let mut state = KEY_SYSTEM.lock().unwrap();
        state.config_key = Some(ConfigKey::new_from_master(&master_key));
    }
}

// Public exports for the core key system
pub use config_key::ConfigKey;
pub use master_key::MasterKey;

pub use config_key::ConfigKeyGuard;
pub use master_key::MasterKeyGuard;
