//! Configuration module for FiSH_11
//!
//! Provides configuration management functionality including
//! encrypted configuration file storage.

pub mod encrypted_config;

/// Re-export the encrypted config functions for easy access
pub use encrypted_config::{
    decrypt_config_data,
    encrypt_config_data,
    get_config_path,
    is_encrypted_config,
};