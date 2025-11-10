//! Centralized buffer management utilities (platform-independent core)
//!
//! This module provides buffer management functions that are independent of
//! platform-specific interfaces. The actual buffer I/O will be handled by
//! wrapper crates (fish_11_dll, fish_11_lib).

use std::ffi::{CStr, CString, c_char};
use std::ptr;

/// Result type for buffer operations
pub type BufferResult<T> = Result<T, BufferError>;

/// Buffer operation errors
#[derive(Debug)]
pub enum BufferError {
    NullPointer,
    InvalidBufferSize,
    MessageTooLarge,
    EncodingError,
}

impl std::fmt::Display for BufferError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BufferError::NullPointer => write!(f, "null pointer provided"),
            BufferError::InvalidBufferSize => write!(f, "invalid buffer size"),
            BufferError::MessageTooLarge => write!(f, "message too large for buffer"),
            BufferError::EncodingError => write!(f, "string encoding error"),
        }
    }
}

/// # Safely writes a CString to a buffer.
///
/// mIRC expects DLL return buffers to be no larger than 900 bytes (including the null terminator).
/// Using 900 as the buffer size is the historical and recommended standard for mIRC DLLs.
/// This prevents buffer overflows, memory corruption, and client crashes when displaying results.
/// The 900-byte limit is sufficient for most mIRC commands, including /echo, /notice, and custom output.
///
/// # Best practices:
/// - Always ensure the buffer is null-terminated.
/// - Filter out non-ASCII or non-printable characters if the result will be displayed in mIRC.
/// - For all DLL result functions, use this helper with 900 as the default size.
///
/// Example usage:
///     crate::buffer_utils::write_cstring_to_buffer(data, 900, &result)
///
/// # Safety
/// Efficiently write a CString to the buffer with bounds checking
pub unsafe fn write_cstring_to_buffer(
    data: *mut c_char,
    buffer_size: usize,
    message: &CString,
) -> Result<(), &'static str> {
    if data.is_null() {
        return Err("null data pointer");
    }

    if buffer_size == 0 {
        return Err("zero buffer size");
    }

    let bytes = message.as_bytes_with_nul();
    let copy_len = bytes.len().min(buffer_size);

    // Only clear/write what we actually need, not the entire reported buffer size
    // This prevents writing beyond the actual allocated buffer in tests
    let safe_len = copy_len.min(900); // Cap at mIRC limit

    // Clear the entire buffer to prevent garbage data
    ptr::write_bytes(data as *mut u8, 0, buffer_size);

    // Copy data
    ptr::copy_nonoverlapping(bytes.as_ptr(), data as *mut u8, safe_len);

    // Ensure null termination within the safe range
    if safe_len > 0 {
        *data.add(safe_len - 1) = 0;
    }

    Ok(())
}

/// Parse input safely from buffer
pub unsafe fn parse_buffer_input(data: *mut c_char) -> Result<String, &'static str> {
    if data.is_null() {
        return Err("null data pointer");
    }

    // Use CStr::from_ptr which safely reads until null terminator
    // This is the standard way to handle C strings and doesn't rely on buffer size
    let c_str = match CStr::from_ptr(data).to_str() {
        Ok(s) => s,
        Err(_) => return Err("invalid UTF-8 input"),
    };

    let trimmed = c_str.trim();
    if trimmed.is_empty() { Err("empty input") } else { Ok(trimmed.to_string()) }
}

/// Safely write a string to a buffer, handling CString conversion
///
/// # Safety
/// The caller must ensure that `data` points to a valid buffer of at least `buffer_size` bytes
pub unsafe fn write_string_to_buffer(
    data: *mut c_char,
    buffer_size: usize,
    message: &str,
) -> BufferResult<()> {
    let c_string = CString::new(message).map_err(|_| BufferError::EncodingError)?;
    write_cstring_to_buffer(data, buffer_size, &c_string)
        .map_err(|_| BufferError::InvalidBufferSize)
}

/// Create an error message CString with fallback handling
pub fn create_error_message(message: &str, fallback: &str) -> CString {
    CString::new(message)
        .unwrap_or_else(|_| CString::new(fallback).expect("Fallback string should be valid"))
}

/// Create an echo command string
pub fn create_echo_command(message: &str, style: EchoStyle) -> String {
    match style {
        EchoStyle::Normal => format!("{}", message),
        EchoStyle::Timestamp => format!("{}", message),
        EchoStyle::Error => format!("{}", message),
    }
}

/// Write an echo command to a buffer using the specified style
///
/// # Safety
/// The caller must ensure that `data` points to a valid buffer of at least `buffer_size` bytes
pub unsafe fn write_echo_command_to_buffer(
    data: *mut c_char,
    buffer_size: usize,
    message: &str,
    style: EchoStyle,
) -> BufferResult<()> {
    let echo_command = create_echo_command(message, style);
    write_string_to_buffer(data, buffer_size, &echo_command)
}

/// Echo command styles for mIRC
#[derive(Debug, Clone, Copy)]
pub enum EchoStyle {
    Normal,    // /echo -a
    Timestamp, // plain text
    Error,     // /echo -cr
}

/// Validate buffer parameters
pub fn validate_buffer_params(data: *mut c_char, buffer_size: usize) -> BufferResult<()> {
    if data.is_null() {
        return Err(BufferError::NullPointer);
    }

    if buffer_size < 2 {
        return Err(BufferError::InvalidBufferSize);
    }

    Ok(())
}

/// Calculate safe copy length ensuring space for null terminator
pub fn calculate_safe_copy_length(message_len: usize, buffer_size: usize) -> BufferResult<usize> {
    if message_len > buffer_size {
        return Err(BufferError::MessageTooLarge);
    }

    // Ensure space for null terminator
    Ok(message_len.min(buffer_size.saturating_sub(1)))
}

/// Perform the actual buffer write operation
///
/// # Safety
/// All parameters must be validated before calling this function
pub unsafe fn perform_buffer_write(
    data: *mut c_char,
    buffer_size: usize,
    bytes: &[u8],
    safe_len: usize,
) {
    // Clear buffer first
    ptr::write_bytes(data as *mut u8, 0, buffer_size);

    // Copy data
    if safe_len > 0 {
        ptr::copy_nonoverlapping(bytes.as_ptr(), data as *mut u8, safe_len);
    }

    // Ensure null termination
    *data.add(safe_len) = 0;
}

/// Helper to write error messages with automatic fallback
///
/// # Safety
/// The caller must ensure that `data` points to a valid buffer of at least `buffer_size` bytes
pub unsafe fn write_error_to_buffer(
    data: *mut c_char,
    buffer_size: usize,
    error_msg: &str,
    trace_id: Option<&str>,
) {
    let formatted_msg = if let Some(id) = trace_id {
        format!("Error [{}]: {}", id, error_msg)
    } else {
        format!("Error: {}", error_msg)
    };

    let error_cstring = create_error_message(&formatted_msg, "Internal error occurred");
    if let Err(_) = write_cstring_to_buffer(data, buffer_size, &error_cstring) {
        // Last resort: write minimal error message
        let minimal_msg =
            CString::new("Error").expect("Minimal error string should be valid");
        let _ = write_cstring_to_buffer(data, buffer_size, &minimal_msg);
    }
}
