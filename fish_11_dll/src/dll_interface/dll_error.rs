//! Centralized error handling for DLL interface functions

use std::ffi::c_char;
use std::os::raw::c_int;

use crate::buffer_utils;
use crate::dll_interface::{MIRC_COMMAND, MIRC_HALT};

/// Common DLL interface errors
#[derive(Debug)]
pub enum DllError {
    InvalidInput(String),
    BufferError(String),
    ConfigError(String),
    CryptoError(String),
    Timeout,
    NullPointer,
}

impl DllError {
    /// Convert error to appropriate mIRC return code and write error message
    pub unsafe fn handle_error(self, data: *mut c_char) -> c_int {
        match self {
            DllError::NullPointer => {
                // Cannot write to null pointer
                MIRC_HALT
            }
            DllError::Timeout => {
                buffer_utils::write_error_message(data, "Operation timed out");
                MIRC_COMMAND
            }
            DllError::InvalidInput(msg) => {
                buffer_utils::write_error_message(data, &format!("Invalid input: {}", msg));
                MIRC_COMMAND
            }
            DllError::BufferError(msg) => {
                buffer_utils::write_error_message(data, &format!("Buffer error: {}", msg));
                MIRC_COMMAND
            }
            DllError::ConfigError(msg) => {
                buffer_utils::write_error_message(data, &format!("Configuration error: {}", msg));
                MIRC_COMMAND
            }
            DllError::CryptoError(msg) => {
                buffer_utils::write_error_message(data, &format!("Cryptography error: {}", msg));
                MIRC_COMMAND
            }
        }
    }
}

/// Result type for DLL operations
pub type DllResult<T> = Result<T, DllError>;

/// Macro for early return with error handling
#[macro_export]
macro_rules! dll_try {
    ($expr:expr, $data:expr) => {
        match $expr {
            Ok(val) => val,
            Err(err) => return unsafe { err.handle_error($data) },
        }
    };
}
