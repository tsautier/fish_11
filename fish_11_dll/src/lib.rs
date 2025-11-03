//! FiSH 11 - A secure encryption DLL for mIRC
//!
//! This DLL provides secure communication capabilities for mIRC clients
//! using Curve25519 for key exchange and ChaCha20-Poly1305 for encryption.
//!
//! This is the entry point for the DLL.
//!
//! In the file :
//!   - dll_interface contains the exported functions for mIRC
//!   - crypto contains the cryptographic functions
//!   - error contains the error handling code
//!   - config contains the configuration file handling code
//!   - tests contains the unit tests
//!   - utils contains utility functions
//!   - logging contains the file logging functionality
//!
//! Written by [GuY], 2025. Licensed under the GPL v3.

pub mod config;
pub mod crypto;
pub mod dll_interface;
pub mod error;
pub mod logging;
pub mod utils;

pub mod buffer_utils;
pub mod dll_function_utils;
pub mod logging_macros;

// Unified error handling system (standardized approach)
pub mod unified_error;

pub mod engine_registration;

/// Get build information from VERGEN or use fallbacks
pub const FISH_11_BUILD_DATE: &str = match option_env!("VERGEN_BUILD_DATE") {
    Some(date) => date,
    None => env!("FISH_FALLBACK_DATE"),
};

/// Get build information from VERGEN or use fallbacks
pub const FISH_11_BUILD_TIME: &str = match option_env!("VERGEN_BUILD_TIME") {
    Some(time) => time,
    None => env!("FISH_FALLBACK_TIME"),
};

/// Version of the FiSH_11 DLL
pub const FISH_11_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Complete version string with all information
pub const FISH_MAIN_VERSION: &str = env!("FISH_MAIN_VERSION");
