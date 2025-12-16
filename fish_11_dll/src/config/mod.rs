//! Configuration module for FiSH_11

use parking_lot::Mutex;
pub mod config_access;
pub mod entries;
pub mod file_storage;
pub mod key_management;
pub mod models;
pub mod networks;

pub mod channel_key_utils;
pub mod channel_keys;
pub mod manual_channel_keys;

pub mod settings;

pub mod state_management;

use std::thread;
use std::time::{Duration, Instant};

// Re-export models
pub use models::{EntryData, Fish11Section, FishConfig, StartupSection};
use once_cell::sync::Lazy;

/// Global configuration instance
/// Using parking_lot::Mutex for better performance and no poisoning
pub static CONFIG: Lazy<Mutex<FishConfig>> = Lazy::new(|| {
    #[cfg(debug_assertions)]
    log::info!("CONFIG: Initializing global configuration...");

    // Try to load config from disk, or create a new one if it doesn't exist
    match file_storage::get_config_path() {
        Ok(path) => {
            #[cfg(debug_assertions)]
            log::info!("CONFIG: Config path obtained: {}", path.display());

            match file_storage::load_config(Some(path.clone())) {
                Ok(config) => {
                    #[cfg(debug_assertions)]
                    log::info!("CONFIG: Configuration loaded successfully from {}", path.display());
                    Mutex::new(config)
                }
                Err(e) => {
                    #[cfg(debug_assertions)]
                    log::error!("CONFIG: Failed to load config from {}: {}", path.display(), e);

                    log::warn!("CONFIG: Using default configuration due to load error");
                    Mutex::new(FishConfig::new())
                }
            }
        }
        Err(e) => {
            #[cfg(debug_assertions)]
            log::error!("CONFIG: Failed to get config path: {}", e);

            log::warn!("CONFIG: Using default configuration (MIRCDIR not set)");

            #[cfg(debug_assertions)]
            log::info!("CONFIG: Creating new FishConfig...");

            let new_config = FishConfig::new();

            #[cfg(debug_assertions)]
            log::info!("CONFIG: FishConfig created successfully");

            #[cfg(debug_assertions)]
            log::info!("CONFIG: Creating Mutex wrapper...");

            let mutex = Mutex::new(new_config);

            #[cfg(debug_assertions)]
            log::info!("CONFIG: Mutex created successfully");

            #[cfg(debug_assertions)]
            log::info!("CONFIG: Returning from Lazy::new...");

            mutex
        }
    }
});

/// Force initialization of the CONFIG lazy static
/// This must be called during DLL initialization to avoid deadlocks
pub fn init_config() {
    #[cfg(debug_assertions)]
    log::info!("init_config: Forcing CONFIG initialization...");

    // Just access CONFIG to trigger Lazy initialization
    let _ = &*CONFIG;

    #[cfg(debug_assertions)]
    log::info!("init_config: CONFIG initialized successfully");
}

/// Tries to perform an operation with exponential backoff
/// This function is useful for operations that might fail due to temporary conditions
/// and should be retried after a delay.
pub fn with_retry<F, T>(
    mut operation: F,
    max_attempts: usize,
    timeout: Duration,
) -> Result<T, String>
where
    F: FnMut() -> Result<T, String>,
{
    let start = Instant::now();
    let mut attempts = 0;

    while attempts < max_attempts {
        // Check for timeout
        if start.elapsed() > timeout {
            return Err(format!("Operation timed out after {} attempts", attempts));
        }

        match operation() {
            Ok(result) => return Ok(result),
            Err(e) => {
                attempts += 1;
                if attempts >= max_attempts {
                    return Err(format!("Operation failed after {} attempts: {}", attempts, e));
                }

                // Exponential backoff with jitter
                let base_ms = 10.0;
                let max_ms = 500.0;
                let backoff_ms = (base_ms * (1.5_f64.powi(attempts as i32))).min(max_ms);
                let jitter = rand::random::<f64>() * 0.1 * backoff_ms; // 10% jitter
                let sleep_ms = (backoff_ms + jitter) as u64;

                thread::sleep(Duration::from_millis(sleep_ms));
            }
        }
    }

    Err(format!("Operation failed after {} attempts", attempts))
}

pub use config_access::{read_config, with_config, with_config_mut, write_config};
// Re-export key functions from submodules for easier access
pub use channel_key_utils::{get_channel_key_type, get_channel_key_with_fallback, has_channel_key};
pub use channel_keys::{get_channel_key, set_channel_key};
pub use entries::{
    get_channel_data, get_user_data, list_channel_entries, list_user_entries, set_channel_data,
    set_user_data,
};
pub use file_storage::{get_config_path, init_config_file, load_config, save_config};
pub use key_management::{
    delete_key, delete_key_default, get_all_keys_with_ttl, get_configured_key_ttl, get_key,
    get_key_default, get_key_status, get_key_status_human_readable, get_key_ttl,
    get_key_ttl_human_readable, get_keypair, get_our_keypair, is_key_about_to_expire, list_keys,
    set_configured_key_ttl, set_key, set_key_default, store_keypair,
};
pub use manual_channel_keys::{
    get_manual_channel_key, list_manual_channel_keys, set_manual_channel_key,
};
pub use networks::{
    count_network_mappings, count_unique_networks, delete_network, get_all_network_mappings,
    get_all_networks, get_network_for_nick, get_nicknames_by_network, has_network, merge_networks,
    remove_network_for_nick, rename_network, set_network_for_nick,
};
pub use settings::{
    get_encryption_mark, get_fish11_config, get_plain_prefix, get_startup_time,
    get_startup_time_formatted, is_fish10_legacy_disabled, should_encrypt_message,
    should_process_incoming, should_process_outgoing, update_fish11_config, update_startup_time,
};

pub use state_management::{add_nonce, check_nonce, init_ratchet_state, with_ratchet_state_mut};
