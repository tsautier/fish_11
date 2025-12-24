//! Master Key module for FiSH_11
//!
//! This module provides secure master key management for encrypting config files and logs.

pub mod derivation;
pub mod encryption;
pub mod keystore;
pub mod memory;
pub mod password_change;
pub mod password_validation;
pub mod rotation;

use once_cell::sync::Lazy;
use std::sync::Mutex;

/// Global handle for the master key in memory. The key is kept in memory only when unlocked
static MASTER_KEY_HANDLE: Lazy<Mutex<Option<Vec<u8>>>> = Lazy::new(|| Mutex::new(None));

// Re-export derivation functions
pub use derivation::{
    derive_channel_key, derive_config_kek, derive_export_kek, derive_log_key, derive_logs_kek,
    derive_master_key, derive_master_key_with_salt,
};

// Re-export encryption functions
pub use encryption::{
    EncryptedBlob, decrypt_data, encrypt_data, get_nonce_counter, set_nonce_counter,
};

// Re-export memory wrappers
pub use memory::{SecureBytes, SecureString};

// Re-export keystore
pub use keystore::{KeyMetadata, Keystore};

// Re-export rotation
pub use rotation::{
    RotationReason, calculate_usage_percentages, rotation_warning_message, should_rotate_key,
};
