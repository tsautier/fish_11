//! Master Key module for FiSH_11
//!
//! This module provides secure master key management for encrypting config files and logs.

pub mod derivation;
pub mod encryption;
pub mod memory;

use once_cell::sync::Lazy;
use std::sync::Mutex;

/// Global handle for the master key in memory. The key is kept in memory only when unlocked
static MASTER_KEY_HANDLE: Lazy<Mutex<Option<Vec<u8>>>> = Lazy::new(|| Mutex::new(None));

pub use derivation::{derive_master_key, derive_subkey};
pub use encryption::{EncryptedBlob, decrypt_data, encrypt_data};
pub use memory::{SecureBytes, SecureString};
