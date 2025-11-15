//use once_cell::sync::Lazy;
//use regex::Regex;
use std::ffi::{CStr, CString, c_char};
//use std::os::raw::c_int;
use std::ptr;
//use std::sync::Mutex;
//use std::time::Duration;

mod fish11_decryptmsg;
mod fish11_encryptmsg;
mod fish11_filedelkey;
mod fish11_filegetkey;
mod fish11_filelistkeys;
mod fish11_filelistkeysitem;
mod fish11_genkey;
mod fish11_getconfigpath;
mod fish11_help;
mod fish11_setnetwork;
mod key_management;
mod utility;

pub mod dll_error;
pub mod fish11_exchangekey;
pub mod fish11_setkey;
pub mod fish11_setmircdir;
pub mod function_template;
pub mod ini_types;

pub(crate) mod core;

// Re-export fish_11_core globals for use within fish_11_dll
pub use fish_11_core::globals::{
    CRATE_VERSION, CURRENT_YEAR, DEFAULT_MIRC_BUFFER_SIZE, FUNCTION_TIMEOUT_SECONDS,
    KEY_EXCHANGE_TIMEOUT_SECONDS, MAX_MIRC_BUFFER_SIZE, MIRC_BUFFER_SIZE, MIRC_COMMAND,
    MIRC_CONTINUE, MIRC_ERROR, MIRC_HALT, MIRC_IDENTIFIER, MIRC_TYPICAL_BUFFER_SIZE,
    NICK_VALIDATOR,
};

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
mod ini_tests;

#[cfg(test)]
/// Test helper: restore the buffer size after a test
pub(crate) fn restore_buffer_size_for_test(prev_size: Option<usize>) {
    if let Some(size) = prev_size {
        let _ = MIRC_BUFFER_SIZE.lock().ok().map(|mut g| *g = size);
    }
}

pub use crate::channel_encryption::init_key::FiSH11_InitChannelKey;
pub use crate::channel_encryption::process_key::FiSH11_ProcessChannelKey;
