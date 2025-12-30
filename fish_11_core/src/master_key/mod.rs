//! Master Key module for FiSH_11
//!
//! This module provides secure master key management for encrypting config files and logs.
//!
//! The new core system provides a clearer separation between different key types:
//! - MasterKey: Primary key that protects all other keys
//! - ConfigKey: Specialized key for configuration encryption
//! - LogKey: Specialized key for log encryption

// Note: the master key is stored in fish_11_core::globals::LOGGING_KEY for logging operations
// and in fish_11_dll::dll_interface::fish11_masterkey::MASTER_KEY for general master key operations

// New core key system with clear separation of concerns
pub mod core;

// Legacy system (to be deprecated)
pub mod derivation;
pub mod encryption;
pub mod keystore;
pub mod memory;
pub mod password_change;
pub mod password_validation;
pub mod rotation;
// New core system exports
pub use core::{
    ConfigKey, ConfigKeyGuard, LogKey, LogKeyGuard, LogRotationPolicy, MasterKey, MasterKeyGuard,
    get_config_key, get_log_key, initialize_key_system, is_key_system_unlocked, lock_key_system,
    rotate_all_keys,
};

// Legacy system exports (to be deprecated)
pub use derivation::{
    derive_channel_key, derive_config_kek, derive_export_kek, derive_log_key, derive_logs_kek,
    derive_master_key, derive_master_key_with_salt,
};
pub use encryption::{
    EncryptedBlob, decrypt_data, encrypt_data, get_nonce_counter, set_nonce_counter,
};
pub use keystore::{KeyMetadata, Keystore};
pub use memory::{SecureBytes, SecureString};
pub use rotation::{
    RotationReason, calculate_usage_percentages, rotation_warning_message, should_rotate_key,
};
pub mod keystore_encryption;
