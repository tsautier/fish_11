use once_cell::sync::Lazy;
use regex::Regex;
use std::ffi::{CStr, CString, c_char};
use std::os::raw::c_int;
use std::ptr;
use std::sync::Mutex;
use std::time::Duration;

mod fish11_decryptmsg;
mod fish11_encryptmsg;
mod fish11_filedelkey;
mod fish11_filegetkey;
mod fish11_filelistkeys;
mod fish11_filelistkeysitem;
mod fish11_genkey;
mod fish11_getconfigpath;
mod fish11_help;
mod fish11_setkey;
mod fish11_setmircdir;
mod key_management;
mod utility;

pub mod dll_error;
pub mod fish11_exchangekey;
pub mod function_template;
pub mod ini_types;

pub(crate) mod core;
pub(crate) const MIRC_HALT: c_int = 0;
#[allow(dead_code)]
pub(crate) const MIRC_CONTINUE: c_int = 1;
pub(crate) const MIRC_COMMAND: c_int = 2;
pub(crate) const MIRC_IDENTIFIER: c_int = 3;
#[allow(dead_code)]
pub(crate) const MIRC_ERROR: c_int = 4;

// Default maximum bytes that can be returned to mIRC
// Default maximum bytes that can be returned to mIRC. We still cap
// the runtime-reported buffer size to a safe maximum below.
pub(crate) const DEFAULT_MIRC_BUFFER_SIZE: usize = 4096;
// Maximum buffer size we will ever report to callers (including content, we'll
// subtract one for the null terminator in get_buffer_size()). This prevents
// accidentally writing too much to caller buffers; mIRC historically uses 900.
pub(crate) const MAX_MIRC_BUFFER_SIZE: usize = 900;

/// Timeout duration for key exchange operations in seconds
pub const KEY_EXCHANGE_TIMEOUT_SECONDS: u64 = 10;

// Typical buffer size for mIRC, used for initial allocation
pub(crate) const MIRC_TYPICAL_BUFFER_SIZE: usize = 20480;

pub const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const CURRENT_YEAR: &str = "2025";

pub const FUNCTION_TIMEOUT_SECONDS: Duration = Duration::from_secs(5);

pub static NICK_VALIDATOR: Lazy<Regex> = Lazy::new(|| {
    // RFC 1459 compliant nickname validation
    Regex::new(r"^[a-zA-Z\[\]\\`_^{|}][a-zA-Z0-9\[\]\\`_^{|}-]{0,15}$")
        .expect("Hardcoded RFC 1459 nickname regex should always be valid")
});

// Mutex for accessing/modifying the maximum buffer size
// This value can be changed at runtime based on mIRC buffer settings
pub(crate) static MIRC_BUFFER_SIZE: Mutex<usize> = Mutex::new(DEFAULT_MIRC_BUFFER_SIZE);

/// Helper function to safely read string input from mIRC
pub(crate) fn read_input(data: *mut c_char) -> Result<String, &'static str> {
    if data.is_null() {
        return Err("Data buffer pointer is null");
    }

    unsafe {
        match CStr::from_ptr(data).to_str() {
            Ok(s) => Ok(s.to_owned()),
            Err(_) => Err("Invalid ANSI input"),
        }
    }
}

/// Helper function to safely write string output to mIRC
pub(crate) fn write_output(data: *mut c_char, output: &str, buffer_size: usize) {
    let c_string = CString::new(output).unwrap_or_else(|_| {
        CString::new("Error").expect("Failed to create fallback error message")
    });

    unsafe {
        // Clear buffer first
        ptr::write_bytes(data as *mut u8, 0, buffer_size);

        // Copy result with null terminator, ensuring we don't exceed buffer
        let bytes = c_string.as_bytes_with_nul();
        let copy_len = bytes.len().min(buffer_size - 1);
        ptr::copy_nonoverlapping(bytes.as_ptr(), data as *mut u8, copy_len);
        *data.add(copy_len) = 0; // Ensure null termination
    }
}

/// Returns the maximum amount of data that can be written into the output buffer.
/// This implementation includes fallback to global buffer size if LOAD_INFO is not available.
pub(crate) fn get_buffer_size() -> usize {
    use self::core::LOAD_INFO;

    // First try to get buffer size from mIRC information
    let buffer_size = {
        let guard = LOAD_INFO.lock().expect("LOAD_INFO mutex should not be poisoned");

        guard.as_ref().map(|info| info.m_bytes as usize).unwrap_or_else(|| {
            // Fall back to our global buffer size
            match MIRC_BUFFER_SIZE.lock() {
                Ok(size) => *size,
                Err(_) => DEFAULT_MIRC_BUFFER_SIZE,
            }
        })
    };

    // Always leave room for null terminator, and cap to MAX_MIRC_BUFFER_SIZE
    let available = buffer_size.saturating_sub(1);
    std::cmp::min(available, MAX_MIRC_BUFFER_SIZE)
}

#[cfg(test)]
/// Test helper: temporarily override both MIRC_BUFFER_SIZE and LOAD_INFO
/// to ensure get_buffer_size() returns the test's actual buffer size.
/// Returns the previous values so they can be restored.
pub(crate) fn override_buffer_size_for_test(size: usize) -> Option<usize> {
    use self::core::LOAD_INFO;

    // Clear LOAD_INFO so get_buffer_size() will use MIRC_BUFFER_SIZE
    let _ = LOAD_INFO.lock().ok().map(|mut guard| *guard = None);

    // Set MIRC_BUFFER_SIZE to the test's buffer size
    MIRC_BUFFER_SIZE.lock().ok().map(|mut g| {
        let prev = *g;
        *g = size;
        prev
    })
}

#[cfg(test)]
/// Test helper: restore the buffer size after a test
pub(crate) fn restore_buffer_size_for_test(prev_size: Option<usize>) {
    if let Some(size) = prev_size {
        let _ = MIRC_BUFFER_SIZE.lock().ok().map(|mut g| *g = size);
    }
}

pub use crate::channel_encryption::init_key::FiSH11_InitChannelKey;
pub use crate::channel_encryption::process_key::FiSH11_ProcessChannelKey;
