//! Configuration module for FiSH_11

use std::sync::Mutex;
pub mod config_access;
pub mod entries;
pub mod file_storage;
pub mod key_management;
pub mod models;
pub mod networks;
pub mod settings;

use std::thread;
use std::time::{Duration, Instant};

// Re-export models
pub use models::{EntryData, Fish11Section, FishConfig, StartupSection};
use once_cell::sync::Lazy;

/// Global configuration instance
pub static CONFIG: Lazy<Mutex<FishConfig>> = Lazy::new(|| {
    // Try to load config from disk, or create a new one if it doesn't exist
    match file_storage::load_config() {
        Ok(config) => Mutex::new(config),
        Err(_) => Mutex::new(FishConfig::new()),
    }
});

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
pub use entries::{
    get_channel_data, get_user_data, list_channel_entries, list_user_entries, set_channel_data,
    set_user_data,
};
pub use file_storage::{get_config_path, init_config_file, load_config, save_config};
pub use key_management::{
    delete_key, delete_key_default, get_key, get_key_default, get_keypair, get_our_keypair,
    list_keys, set_key, set_key_default, store_keypair,
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
