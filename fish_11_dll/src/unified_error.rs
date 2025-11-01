//! Unified error handling system for FiSH_11 DLL
//!
//! This module provides a comprehensive, standardized error handling approach
//! for the entire DLL, replacing fragmented error types with a single unified system.
//!

use crate::buffer_utils;
use std::error::Error;
use std::ffi::{NulError, c_char};
use std::os::raw::c_int;
use thiserror::Error;

use crate::buffer_utils::BufferError;
use crate::dll_interface::{MIRC_COMMAND, MIRC_HALT};

// Re-export for convenience
pub use crate::error::FishError;

/// Unified error type for all DLL operations
///
/// This enum consolidates all possible error conditions across the DLL,
/// providing a single, consistent error type for all operations.
///
/// Uses `thiserror` for automatic Display and Error trait implementations.
#[derive(Error, Debug)]
pub enum DllError {
    // ===== Configuration Errors =====
    /// Configuration file not found or inaccessible
    #[error("configuration file not found: {0}")]
    ConfigNotFound(String),

    /// Configuration file is malformed or contains invalid data
    #[error("configuration malformed: {0}")]
    ConfigMalformed(String),

    /// Configuration setting has invalid value
    #[error("invalid config value for '{key}': '{value}' ({reason})")]
    ConfigInvalidValue { key: String, value: String, reason: String },

    // ===== Cryptography Errors =====
    /// Key not found for specified target (nick/channel)
    #[error("no encryption key found for '{0}'")]
    KeyNotFound(String),

    /// Key has invalid length or format
    #[error("invalid key: {reason}")]
    KeyInvalid { reason: String },

    /// Key has an invalid size
    #[error("invalid key size: expected {expected} bytes, got {actual}")]
    InvalidKeySize { expected: usize, actual: usize },

    /// Encryption operation failed
    #[error("encryption failed ({context}): {cause}")]
    EncryptionFailed { context: String, cause: String },

    /// Decryption operation failed
    #[error("decryption failed ({context}): {cause}")]
    DecryptionFailed { context: String, cause: String },

    /// Key exchange protocol error
    #[error("key exchange failed: {0}")]
    KeyExchangeFailed(String),

    /// Message authentication failed (AEAD tag mismatch)
    #[error("message authentication failed (possibly tampered)")]
    AuthenticationFailed,

    /// Potential replay attack detected
    #[error("potential replay attack detected")]
    ReplayAttackDetected,

    /// Message size exceeds security limits
    #[error("message too large ({size} bytes, limit: {limit})")]
    MessageTooLarge { size: usize, limit: usize },

    // ===== Input Validation Errors =====
    /// Input parameter is null or empty
    #[error("invalid input for '{param}': {reason}")]
    InvalidInput { param: String, reason: String },

    /// Input contains invalid characters or format
    #[error("malformed input: '{input}' (expected: {expected})")]
    MalformedInput { input: String, expected: String },

    /// Input exceeds maximum allowed length
    #[error("input too long ({length} chars, max: {max})")]
    InputTooLong { length: usize, max: usize },

    /// Required parameter is missing
    #[error("missing required parameter: {0}")]
    MissingParameter(String),

    // ===== Buffer & Memory Errors =====
    /// Buffer pointer is null
    #[error("null pointer in {context}")]
    NullPointer { context: String },

    /// Buffer size is invalid or insufficient
    #[error("buffer too small ({size} bytes, need: {required})")]
    InvalidBufferSize { size: usize, required: usize },

    /// Failed to write to output buffer
    #[error("failed to write to buffer: {0}")]
    BufferWriteFailed(String),

    /// String contains null byte (incompatible with C strings)
    #[error("null byte in string ({context})")]
    NullByteInString { context: String },

    // ===== I/O Errors =====
    /// File system operation failed with underlying cause
    #[error("I/O error during {operation} on '{path}': {source}")]
    IoError {
        operation: String,
        path: String,
        #[source]
        source: std::io::Error,
    },

    /// Simple I/O error wrapper (for use with #[from])
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    /// File not found
    #[error("file not found: {0}")]
    FileNotFound(String),

    /// Permission denied
    #[error("permission denied: {resource}")]
    PermissionDenied { resource: String },

    // ===== Encoding Errors =====
    /// Base64 encoding/decoding failed with underlying cause
    #[error("base64 error ({context}): {source}")]
    Base64Error {
        context: String,
        #[source]
        source: base64::DecodeError,
    },

    /// Base64 decoding failed with context
    #[error("base64 decoding failed ({context}): {cause}")]
    Base64DecodeFailed { context: String, cause: String },

    /// Simple Base64 error wrapper (for use with #[from])
    #[error("base64 decoding failed: {0}")]
    Base64(#[from] base64::DecodeError),

    /// UTF-8 encoding/decoding failed
    #[error("invalid UTF-8 ({context})")]
    Utf8Error { context: String },

    /// Simple UTF-8 string error wrapper (for use with #[from])
    #[error("UTF-8 conversion failed: {0}")]
    FromUtf8(#[from] std::string::FromUtf8Error),

    /// Simple UTF-8 validation error wrapper (for use with #[from])
    #[error("invalid UTF-8: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    /// Simple null byte error wrapper (for use with #[from])
    #[error("null byte in string: {0}")]
    NulByte(#[from] NulError),

    /// Non-ASCII character in ASCII-only context
    #[error("non-ASCII character '{char}' in {context}")]
    NonAsciiCharacter { char: char, context: String },

    // ===== State & Logic Errors =====
    /// Duplicate entry (e.g., key already exists)
    #[error("entry already exists: {0}")]
    DuplicateEntry(String),

    /// Operation attempted in invalid state
    #[error("invalid state: {current} (required: {required})")]
    InvalidState { current: String, required: String },

    /// Operation timeout
    #[error("operation '{operation}' timed out after {duration_secs}s during stage: {stage}")]
    Timeout { operation: String, duration_secs: u64, stage: String },

    // ===== Network & Protocol Errors =====
    /// Invalid network name
    #[error("invalid network name: {0}")]
    InvalidNetwork(String),

    /// Protocol version mismatch
    #[error("protocol version mismatch: expected {expected}, got {got}")]
    ProtocolMismatch { expected: String, got: String },

    // ===== System Errors =====
    /// Cryptographically secure random number generation failed
    #[error("RNG failed: {context}")]
    RngFailed { context: String },

    /// Internal error (should never happen in production)
    #[error("internal error: {0}")]
    Internal(String),

    /// Feature not implemented
    #[error("not implemented: {0}")]
    NotImplemented(String),
}

impl DllError {
    /// Convert error to mIRC response code and write error message to buffer
    ///
    /// # Safety
    ///
    /// `data` must point to a valid mIRC buffer with sufficient size
    pub unsafe fn to_mirc_response(self, data: *mut c_char) -> c_int {
        // Handle null pointer case specially (cannot write error message)
        if let DllError::NullPointer { .. } = self {
            log::error!("DLL Error: null pointer provided, cannot write error message");
            return MIRC_HALT;
        }

        if data.is_null() {
            log::error!("DLL Error: {}, but buffer pointer is null", self);
            return MIRC_HALT;
        }

        // Log the error with its full source chain for debugging
        if let Some(source) = self.source() {
            log::error!("DLL Error: {} (caused by: {})", self, source);

            // Log the full error chain if available
            let mut current_source = source.source();
            let mut depth = 1;
            while let Some(src) = current_source {
                log::error!("  [{}] caused by: {}", depth, src);
                current_source = src.source();
                depth += 1;
            }
        } else {
            log::error!("DLL Error: {}", self);
        }

        // Write error message to mIRC buffer (using thiserror-generated Display)
        let error_msg = self.to_string();
        match std::ffi::CString::new(error_msg) {
            Ok(cstring) => {
                let buf_size = crate::dll_interface::get_buffer_size();
                let _ = buffer_utils::write_cstring_to_buffer(data, buf_size, &cstring);
            }
            Err(e) => {
                log::error!("Failed to convert error message to CString: {}", e);
                // Fallback: write generic error
                let fallback = std::ffi::CString::new("Error: message contains null byte").unwrap();
                let buf_size = crate::dll_interface::get_buffer_size();
                let _ = buffer_utils::write_cstring_to_buffer(data, buf_size, &fallback);
            }
        }

        // Determine return code based on error severity
        match self {
            // Fatal errors that should halt execution
            DllError::NullPointer { .. }
            | DllError::Internal(_)
            | DllError::InvalidBufferSize { .. } => MIRC_HALT,

            // Non-fatal errors (command executed, but with error message)
            _ => MIRC_COMMAND,
        }
    }

    /// Create error with context helper
    pub fn with_context(self, context: &str) -> Self {
        match self {
            DllError::EncryptionFailed { cause, .. } => {
                DllError::EncryptionFailed { context: context.to_string(), cause }
            }
            DllError::DecryptionFailed { cause, .. } => {
                DllError::DecryptionFailed { context: context.to_string(), cause }
            }
            _ => self,
        }
    }
}

// ===== Conversions from existing error types =====

impl From<FishError> for DllError {
    fn from(err: FishError) -> Self {
        match err {
            FishError::ConfigError(msg) => DllError::ConfigMalformed(msg),
            FishError::CryptoError(msg) => {
                DllError::EncryptionFailed { context: "crypto operation".to_string(), cause: msg }
            }
            FishError::IoError(e) => {
                DllError::Io(std::io::Error::new(std::io::ErrorKind::Other, e))
            }
            FishError::InvalidInput(msg) => {
                DllError::InvalidInput { param: "unknown".to_string(), reason: msg }
            }
            FishError::KeyNotFound(target) => DllError::KeyNotFound(target),
            FishError::DuplicateEntry(name) => DllError::DuplicateEntry(name),
            FishError::InvalidNetworkName(name) => DllError::InvalidNetwork(name),
            FishError::MalformedEntry(entry) => DllError::MalformedInput {
                input: entry,
                expected: "valid entry format".to_string(),
            },
            FishError::InvalidKeyLength(len) => DllError::KeyInvalid {
                reason: format!("invalid length: {} bytes (expected 32)", len),
            },
            FishError::AuthenticationFailed => DllError::AuthenticationFailed,
            FishError::NonceReuse => DllError::ReplayAttackDetected,
            FishError::OversizedMessage => {
                DllError::MessageTooLarge { size: 0, limit: crate::crypto::MAX_MESSAGE_SIZE }
            }
            FishError::InvalidCiphertext => DllError::DecryptionFailed {
                context: "ciphertext validation".to_string(),
                cause: "invalid format or corrupted data".to_string(),
            },
            FishError::Base64Error(e) => DllError::Base64(e),
            FishError::NullByteInString => {
                DllError::NullByteInString { context: "string conversion".to_string() }
            }
            FishError::NonAsciiCharacter(c) => {
                DllError::NonAsciiCharacter { char: c, context: "ASCII validation".to_string() }
            }
        }
    }
}

impl From<BufferError> for DllError {
    fn from(err: BufferError) -> Self {
        match err {
            BufferError::NullPointer => {
                DllError::NullPointer { context: "buffer operation".to_string() }
            }
            BufferError::InvalidBufferSize => DllError::InvalidBufferSize { size: 0, required: 1 },
            BufferError::MessageTooLarge => {
                DllError::BufferWriteFailed("message exceeds buffer capacity".to_string())
            }
            BufferError::EncodingError => {
                DllError::Utf8Error { context: "buffer encoding".to_string() }
            }
        }
    }
}

impl From<&str> for DllError {
    fn from(err: &str) -> Self {
        DllError::InvalidInput { param: "data".to_string(), reason: err.to_string() }
    }
}

/// Result type for DLL operations
pub type DllResult<T> = Result<T, DllError>;

/// Helper macro for DLL functions with automatic error handling
///
/// # Example
///
/// ```rust
/// dll_function!(FiSH11_MyFunction, data, {
///     let input = parse_input(data)?;
///     let result = do_work(&input)?;
///     Ok(result)
/// });
/// ```
#[macro_export]
macro_rules! dll_function {
    ($name:ident, $data:ident, $body:block) => {
        #[no_mangle]
        #[allow(non_snake_case)]
        pub extern "stdcall" fn $name(
            _m_wnd: HWND,
            _a_wnd: HWND,
            $data: *mut c_char,
            _parms: *mut c_char,
            _show: BOOL,
            _nopause: BOOL,
        ) -> c_int {
            use $crate::unified_error::DllResult;

            fn inner($data: *mut c_char) -> DllResult<String> {
                $body
            }

            match inner($data) {
                Ok(result) => {
                    unsafe {
                        let cstring = match std::ffi::CString::new(result) {
                            Ok(s) => s,
                            Err(e) => return DllError::from(e).to_mirc_response($data),
                        };
                        // Use the runtime-determined buffer size to avoid overwriting caller memory
                        let buf_size = $crate::dll_interface::get_buffer_size();
                        $crate::buffer_utils::write_cstring_to_buffer($data, buf_size, &cstring).ok();
                    }
                    $crate::dll_interface::MIRC_COMMAND
                }
                Err(e) => unsafe { e.to_mirc_response($data) },
            }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = DllError::KeyNotFound("alice".to_string());
        assert_eq!(err.to_string(), "No encryption key found for 'alice'");

        let err = DllError::InvalidInput {
            param: "message".to_string(),
            reason: "empty string".to_string(),
        };
        assert_eq!(err.to_string(), "Invalid input for 'message': empty string");
    }

    #[test]
    fn test_fish_error_conversion() {
        let fish_err = FishError::KeyNotFound("bob".to_string());
        let dll_err: DllError = fish_err.into();
        assert!(matches!(dll_err, DllError::KeyNotFound(_)));
    }

    #[test]
    fn test_io_error_conversion() {
        let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "test");
        let dll_err: DllError = io_err.into();
        assert!(matches!(dll_err, DllError::Io(_)));
    }
}
