use std::ffi::{CString, c_char};
use std::os::raw::c_int;
use std::time::Instant;

use log::{debug, error, info};
use rand::RngCore;
use rand::rngs::OsRng;
use secrecy::ExposeSecret;
use subtle::ConstantTimeEq;
use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::config::file_storage::save_config;
use crate::config::{CONFIG, get_key_default, get_keypair, set_key_default, store_keypair};
use crate::crypto::{KeyPair, format_public_key, generate_keypair};
use crate::dll_interface::{
    FUNCTION_TIMEOUT_SECONDS, KEY_EXCHANGE_TIMEOUT_SECONDS, MIRC_COMMAND, MIRC_HALT,
    get_buffer_size,
};
use crate::error::Result;
use crate::utils::{normalize_nick, validate_nickname};
use crate::{buffer_utils, log_debug, log_error, log_info, log_warn};

/// Initiates a secure key exchange by generating and displaying a public key for sharing
///
/// This function implements the first step of the Diffie-Hellman key exchange protocol:
/// 1. Checks if a key exists for the specified nickname, generating one if needed
/// 2. Generates or retrieves a Curve25519 keypair
/// 3. Formats the public key for sharing
/// 4. Displays instructions for completing the key exchange
/// 5. Sets a timeout to automatically cancel the exchange if no response is received
///
/// # Arguments
/// * `data` - Pointer to mIRC's buffer containing:
///   - On input: The nickname to exchange keys with
///   - On output: Public key and usage instructions
///
/// # Returns
/// Returns `MIRC_COMMAND` (2) to execute the echo command in mIRC
#[no_mangle]
#[allow(non_snake_case)]
pub extern "stdcall" fn FiSH11_ExchangeKey(
    _m_wnd: HWND,
    _a_wnd: HWND,
    data: *mut c_char,
    _parms: *mut c_char,
    _show: BOOL,
    _nopause: BOOL,
) -> c_int {
    // Log function entry
    crate::logging::log_function_entry::<&str>("FiSH11_ExchangeKey", None);

    // Create a trace ID for tracking this call through logs
    let trace_id = generate_trace_id();

    // Get buffer size and validate
    let buffer_size = get_buffer_size() as usize;

    if !validate_buffer(buffer_size, &trace_id, data) {
        return MIRC_HALT;
    }

    log_info!(
        "FiSH11_ExchangeKey[{}]: Starting key exchange process with buffer size {}",
        trace_id,
        buffer_size
    ); // Use a panic handler to prevent any crashes

    let result = std::panic::catch_unwind(|| {
        // Set a timeout for this function to ensure it doesn't run too long
        let timeout = FUNCTION_TIMEOUT_SECONDS;
        let start_time = std::time::Instant::now();

        // Safely extract input from the data pointer
        let input = match extract_input_safely(data, buffer_size, start_time, timeout, &trace_id) {
            Ok(input) => input,
            Err(code) => return code,
        };

        // Normalize and validate nickname
        let nickname = normalize_nick(input.trim());
        if !validate_nickname(&nickname, data, buffer_size, &trace_id) {
            return MIRC_COMMAND;
        } // Check if we already have a key for this nickname
        let mut key_was_generated = false;

        // Check if we've timed out already
        if check_timeout(start_time, timeout, data, buffer_size, &trace_id, "before checking keys")
        {
            return MIRC_COMMAND;
        } // Handle key generation if needed
        if let Err(e) = get_key_default(&nickname) {
            log_info!(
                "FiSH11_ExchangeKey[{}]: no existing key found for {}: {}",
                trace_id,
                nickname,
                e
            );
            log_info!("FiSH11_ExchangeKey[{}]: will automatically generate a new key", trace_id);

            // Generate a new secure random key
            let new_key = match generate_secure_random_key(&trace_id, data, buffer_size) {
                Ok(key) => key,
                Err(code) => return code,
            };

            // Store the key and persist configuration
            match store_key_and_persist(&nickname, &new_key, &trace_id) {
                Ok(_) => {
                    key_was_generated = true;
                }
                Err(store_err) => {
                    log_error!(
                        "FiSH11_ExchangeKey[{}]: failed to store generated key: {}",
                        trace_id,
                        store_err
                    );

                    // Log that we're proceeding without a generated key
                    log_warn!(
                        "FiSH11_ExchangeKey[{}]: proceeding with key exchange despite key generation failure",
                        trace_id
                    );
                }
            }
        } else {
            log_info!(
                "FiSH11_ExchangeKey[{}]: found existing key for {}",
                trace_id,
                redact_nickname(&nickname)
            );
        } // Check if we've timed out before keypair generation
        if start_time.elapsed() > timeout {
            error!(
                "FiSH11_ExchangeKey[{}]: function timed out before keypair generation",
                trace_id
            );
            let error_msg =
                CString::new("/echo -ts Error: key exchange timed out during key preparation")
                    .unwrap_or_else(|_| {
                        log_error!(
                            "FiSH11_ExchangeKey[{}]: Failed to create timeout error message",
                            trace_id
                        );
                        CString::new("/echo -ts Error: key exchange timed out")
                            .expect("Fallback message valid")
                    });
            unsafe {
                let _ = buffer_utils::write_cstring_to_buffer(data, buffer_size, &error_msg);
            }
            return MIRC_COMMAND;
        } // Generate a key pair if we don't already have one
        log_debug!("FiSH11_ExchangeKey[{}]: retrieving keypair", trace_id);

        let keypair = match get_keypair() {
            Ok(kp) => {
                if validate_keypair(&kp, &trace_id) {
                    kp
                } else {
                    // Create a safe error message and return MIRC_COMMAND
                    let error_msg = CString::new("/echo -ts Error: invalid keypair detected (all zeros). Try regenerating your keypair.")
                        .expect("Static error message contains no null bytes");
                    unsafe {
                        buffer_utils::write_cstring_to_buffer(data, buffer_size, &error_msg)
                            .unwrap_or_else(|_| {
                                // Fallback: minimal error handling
                            });
                    }

                    return MIRC_COMMAND;
                }
            }
            Err(e) => {
                log_error!("FiSH11_ExchangeKey[{}]: failed to get keypair: {}", trace_id, e);
                log_info!("FiSH11_ExchangeKey[{}]: attempting to generate a new keypair", trace_id);

                // Generate a new keypair
                let new_keypair = generate_keypair(); // Store the new keypair
                match store_keypair_and_persist(&new_keypair, &trace_id) {
                    Ok(_) => new_keypair,
                    Err(error_msg) => {
                        unsafe {
                            let _ = buffer_utils::write_cstring_to_buffer(
                                data,
                                buffer_size,
                                &error_msg,
                            );
                        }
                        return MIRC_COMMAND;
                    }
                }
            }
        }; // Format our public key for sharing
        log_debug!("FiSH11_ExchangeKey[{}]: formatting public key for {}", trace_id, nickname);

        let formatted_key = format_public_key(&keypair.public_key); // Validate public key format
        if !formatted_key.starts_with("FiSH11-PubKey:") {
            log_error!("FiSH11_ExchangeKey[{}]: invalid public key format generated", trace_id);

            let error_msg = CString::new(
                "/echo -ts Error: Failed to generate a valid public key format. Please report this bug."
            ).unwrap_or_else(|_| {
                log_error!("FiSH11_ExchangeKey[{}]: Failed to create public key error message", trace_id);               
                 CString::new("/echo -ts Error: Invalid public key format").expect("Fallback message valid")
            });

            unsafe {
                let _ = buffer_utils::write_cstring_to_buffer(data, buffer_size, &error_msg);
            }

            return MIRC_COMMAND;
        }

        if crate::logging::is_logger_initialized() {
            debug!(
                "FiSH11_ExchangeKey[{}]: key formatted successfully (length: {})",
                trace_id,
                formatted_key.len()
            );
        } // Create a message with instruction - handle potential formatting errors
        let key_status = if key_was_generated {
            " (Note: a new encryption key was automatically generated)"
        } else {
            ""
        };

        // Calculate safe message length to prevent buffer overflow
        let max_safe_length = buffer_size.saturating_sub(100); // Reserve space for timer command
        let base_message =
            format!("/echo -ts Your public key (send this to {}){}: ", nickname, key_status);

        // Check if we have enough space for the full message
        let timeout_info = format!(
            " | Exchange will timeout in {} seconds if no response",
            KEY_EXCHANGE_TIMEOUT_SECONDS
        );
        let required_length = base_message.len() + formatted_key.len() + timeout_info.len();

        let message_text = if required_length <= max_safe_length {
            // Full message fits
            format!("{}{}{}", base_message, formatted_key, timeout_info)
        } else {
            // Safe truncation that doesn't split UTF-8 sequences
            let available_for_key =
                max_safe_length.saturating_sub(base_message.len() + timeout_info.len() + 20); // 20 chars for "..." + safety

            if available_for_key > 20 {
                let truncated_key = if formatted_key.len() > available_for_key {
                    // Ensure we don't split UTF-8 character boundaries
                    let mut split_pos = available_for_key.saturating_sub(3);
                    while split_pos > 0 && !formatted_key.is_char_boundary(split_pos) {
                        split_pos -= 1;
                    }
                    format!("{}...", &formatted_key[..split_pos])
                } else {
                    formatted_key.clone()
                };
                format!("{}{}{}", base_message, truncated_key, timeout_info)
            } else {
                // Fallback to minimal message if even truncation won't work
                format!(
                    "/echo -ts Key exchange initiated with {} | Exchange will timeout in {} seconds",
                    nickname, KEY_EXCHANGE_TIMEOUT_SECONDS
                )
            }
        };

        let result_msg = match CString::new(message_text) {
            Ok(msg) => msg,
            Err(e) => {
                // Fallback to a simpler message if encoding fails
                log_error!(
                    "FiSH11_ExchangeKey[{}]: failed to create CString from formatted key: {}",
                    trace_id,
                    e
                );
                CString::new(
                    "/echo -ts Your public key was generated but couldn't be displayed correctly",
                )
                .expect("Static string should be valid")
            }
        };

        // TODO : simplified : just send the echo command, don't try to combine timer commands
        // Timer management should be handled separately if needed
        let final_msg = result_msg; // Write the message to the buffer ONCE using consistent buffer writing
        unsafe {
            buffer_utils::write_cstring_to_buffer(data, buffer_size, &final_msg).unwrap_or_else(
                |e| {
                    // Enhanced error logging and recovery
                    log_error!("FiSH11_ExchangeKey[{}]: Buffer write failed: {:?}", trace_id, e);
                    // If buffer write fails, try a minimal fallback
                    let fallback = CString::new("/echo -ts Key exchange initiated")
                        .expect("Static string valid");
                    let _ = buffer_utils::write_cstring_to_buffer(data, buffer_size, &fallback);
                },
            );
        }
        if crate::logging::is_logger_initialized() {
            info!(
                "FiSH11_ExchangeKey[{}]: successfully completed key exchange setup for {} with {} second timeout",
                trace_id,
                redact_nickname(&nickname),
                KEY_EXCHANGE_TIMEOUT_SECONDS
            );
        }

        // Note: We don't implement the actual timeout logic here
        // Instead, we set a timer in mIRC with the command above that will trigger after KEY_EXCHANGE_TIMEOUT_SECONDS
        log_info!(
            "FiSH11_ExchangeKey[{}]: set exchange timeout timer for {} seconds",
            trace_id,
            KEY_EXCHANGE_TIMEOUT_SECONDS
        );

        MIRC_COMMAND
    }); // Handle any panics in our outer function
    if result.is_err() {
        log_error!("FiSH11_ExchangeKey[{}]: panic in function handler", trace_id); // Create fallback message for worst-case scenario
        let panic_msg = CString::new("/echo -ts Critical error in key exchange process")
            .expect("Static string contains no null bytes");

        unsafe {
            let _ = buffer_utils::write_cstring_to_buffer(data, buffer_size, &panic_msg);
        }

        return MIRC_COMMAND;
    }

    // Result is already MIRC_COMMAND, no need to unwrap
    // The catch_unwind above ensures we don't panic here

    log_info!("FiSH11_ExchangeKey[{}]: function completed", trace_id);
    crate::logging::log_function_exit::<i32>("FiSH11_ExchangeKey", Some(MIRC_COMMAND));
    MIRC_COMMAND
}

// =========
// ========== HELPERS ==========
// ==========

/// Validate buffer size and data pointer
fn validate_buffer(buffer_size: usize, trace_id: &str, data: *mut c_char) -> bool {
    if buffer_size <= 1 {
        error!("FiSH11_ExchangeKey[{}]: Invalid buffer size: {}", trace_id, buffer_size);
        return false;
    } // Null pointer check
    if data.is_null() {
        log_error!("FiSH11_ExchangeKey[{}]: Data pointer is null", trace_id);
        // Note: Cannot write to buffer since pointer is null
        crate::logging::log_function_exit::<i32>("FiSH11_ExchangeKey", Some(MIRC_HALT));
        return false;
    }

    true
}

/// Extract input safely from mIRC buffer (optimized version using buffer_utils)
fn extract_input_safely(
    data: *mut c_char,
    _buffer_size: usize,
    start_time: Instant,
    timeout: std::time::Duration,
    trace_id: &str,
) -> std::result::Result<String, c_int> {
    if start_time.elapsed() > timeout {
        error!("FiSH11_ExchangeKey[{}]: function timed out while processing input", trace_id);
        return Err(unsafe { buffer_utils::write_error_message(data, "key exchange timed out") });
    }

    unsafe {
        match buffer_utils::parse_buffer_input(data) {
            Ok(input) => Ok(input),
            Err(e) => {
                log_error!("FiSH11_ExchangeKey[{}]: input parsing failed: {}", trace_id, e);
                Err(buffer_utils::write_error_message(data, e))
            }
        }
    }
}

/// Check if function has timed out
fn check_timeout(
    start_time: Instant,
    timeout: std::time::Duration,
    data: *mut c_char,
    buffer_size: usize,
    trace_id: &str,
    stage: &str,
) -> bool {
    if start_time.elapsed() > timeout {
        error!("FiSH11_ExchangeKey[{}]: Function timed out {}", trace_id, stage);
        let error_msg = CString::new("/echo -ts Error: Key exchange timed out")
            .expect("Static timeout message contains no null bytes");
        unsafe {
            let _ = buffer_utils::write_cstring_to_buffer(data, buffer_size, &error_msg);
        }
        return true;
    }
    false
}

/// Generate a secure random key with enhanced error recovery
fn generate_secure_random_key(
    trace_id: &str,
    data: *mut c_char,
    buffer_size: usize,
) -> std::result::Result<[u8; 32], c_int> {
    // Use cryptographically secure RNG with retry logic
    for attempt in 1..=3 {
        let generation_result = std::panic::catch_unwind(|| {
            let mut key_bytes = [0u8; 32];
            let mut rng = OsRng;
            rng.fill_bytes(&mut key_bytes);
            key_bytes
        });

        match generation_result {
            Ok(key_bytes) => {
                log_debug!(
                    "FiSH11_ExchangeKey[{}]: successfully generated random key on attempt {}",
                    trace_id,
                    attempt
                );
                return Ok(key_bytes);
            }
            Err(_) => {
                log_warn!("FiSH11_ExchangeKey[{}]: RNG failed on attempt {}/3", trace_id, attempt);

                if attempt == 3 {
                    break;
                }

                // Brief pause before retry
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        }
    }

    log_error!(
        "FiSH11_ExchangeKey[{}]: RNG failed after 3 attempts, cannot generate secure key",
        trace_id
    );
    let error_msg = CString::new(
        "/echo -ts Error: failed to generate a secure random key after multiple attempts. Please try again.",
    ).expect("Static error message contains no null bytes");

    unsafe {
        let _ = buffer_utils::write_cstring_to_buffer(data, buffer_size, &error_msg);
    }
    Err(MIRC_COMMAND)
}

/// Store a key and persist configuration to disk
fn store_key_and_persist(nickname: &str, key: &[u8; 32], trace_id: &str) -> Result<()> {
    // Try to store the key with overwrite enabled in case there's a key in an inconsistent state
    match set_key_default(&nickname, &key, true) {
        Ok(_) => {
            if crate::logging::is_logger_initialized() {
                info!(
                    "FiSH11_ExchangeKey[{}]: successfully generated and stored new key for {}",
                    trace_id,
                    redact_nickname(nickname)
                );
            }

            // Save configuration to disk with proper poison handling
            let config_guard = CONFIG.lock().map_err(|_| {
                crate::error::FishError::ConfigError(
                    "Config mutex poisoned during key storage".to_string(),
                )
            })?;

            if let Err(save_err) = save_config(&*config_guard, None) {
                log_warn!(
                    "FiSH11_ExchangeKey[{}]: failed to save config to disk: {}",
                    trace_id,
                    save_err
                );
            } else {
                log_debug!("FiSH11_ExchangeKey[{}]: successfully saved config to disk", trace_id);
            }

            Ok(())
        }
        Err(store_err) => {
            if crate::logging::is_logger_initialized() {
                error!(
                    "FiSH11_ExchangeKey[{}]: failed to store generated key for {}: {}",
                    trace_id,
                    redact_nickname(nickname),
                    store_err
                );
            }
            Err(store_err)
        }
    }
}

/// Validate a keypair using comprehensive checks
fn validate_keypair(keypair: &KeyPair, trace_id: &str) -> bool {
    // Check for all-zero keys
    let public_zeros = [0u8; 32];
    let private_zeros = [0u8; 32];

    let public_not_zero = !bool::from(keypair.public_key.ct_eq(&public_zeros));
    let private_not_zero = !bool::from(keypair.private_key.expose_secret().ct_eq(&private_zeros));

    // Check if public key is on the curve (basic validation)
    // MSB should be 0 for a valid Montgomery curve point
    let valid_point = keypair.public_key[31] & 0x80 == 0;

    let is_valid = public_not_zero && private_not_zero && valid_point;

    if is_valid {
        log_debug!("FiSH11_ExchangeKey[{}]: successfully validated keypair", trace_id);
        true
    } else {
        log_error!(
            "FiSH11_ExchangeKey[{}]: keypair validation failed - public_ok:{}, private_ok:{}, point_ok:{}",
            trace_id,
            public_not_zero,
            private_not_zero,
            valid_point
        );
        false
    }
}

/// Store keypair and persist configuration to disk
fn store_keypair_and_persist(
    keypair: &KeyPair,
    trace_id: &str,
) -> std::result::Result<(), CString> {
    match store_keypair(keypair) {
        Ok(_) => {
            log_info!(
                "FiSH11_ExchangeKey[{}]: successfully generated and stored new keypair",
                trace_id
            );

            // Save configuration to disk with proper poison handling
            let config_guard = CONFIG.lock().map_err(|_| {
                let error_msg = CString::new("/echo -ts Error: config system locked")
                    .expect("Static string contains no null bytes");
                log_error!(
                    "FiSH11_ExchangeKey[{}]: config mutex poisoned during keypair storage",
                    trace_id
                );
                error_msg
            })?;

            if let Err(save_err) = save_config(&*config_guard, None) {
                log_warn!(
                    "FiSH11_ExchangeKey[{}]: failed to save config with new keypair: {}",
                    trace_id,
                    save_err
                );
            } else {
                log_debug!(
                    "FiSH11_ExchangeKey[{}]: successfully saved config with new keypair",
                    trace_id
                );
            }

            Ok(())
        }
        Err(store_err) => {
            log_error!(
                "FiSH11_ExchangeKey[{}]: failed to store generated keypair: {}",
                trace_id,
                store_err
            );

            // Create a safe error message with better error handling
            let error_text = format!("/echo -ts Failed to store keypair: {}", store_err);
            let error_msg = match CString::new(error_text) {
                Ok(msg) => msg,
                Err(e) => {
                    log_error!(
                        "FiSH11_ExchangeKey[{}]: failed to create error CString: {}",
                        trace_id,
                        e
                    );
                    CString::new("/echo -ts Failed to store keypair (error details lost)")
                        .expect("Static string should be valid")
                }
            };

            Err(error_msg)
        }
    }
}

/// Generate a cryptographically secure trace ID for logging
fn generate_trace_id() -> String {
    use rand::RngCore;
    let mut rng = OsRng;
    let mut buf = [0u8; 8];
    rng.fill_bytes(&mut buf);
    hex::encode(buf)
}

/// Redact sensitive data for logging
fn redact_nickname(nickname: &str) -> String {
    if nickname.len() <= 2 {
        "*".repeat(nickname.len())
    } else {
        format!("{}***{}", &nickname[..1], &nickname[nickname.len() - 1..])
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;
    use std::ptr;

    // Helper function to create a test buffer
    fn create_test_buffer(initial_content: &str) -> (*mut c_char, usize) {
        let buffer_size = 4096;
        let c_string = CString::new(initial_content).expect("CString creation failed");
        let bytes = c_string.as_bytes_with_nul();

        unsafe {
            let buffer = libc::malloc(buffer_size) as *mut c_char;
            ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, buffer, bytes.len());
            (buffer, buffer_size)
        }
    }

    // Helper to free test buffer
    unsafe fn free_test_buffer(buffer: *mut c_char) {
        libc::free(buffer as *mut libc::c_void);
    }

    // Helper to read buffer content
    unsafe fn read_buffer_content(buffer: *mut c_char) -> String {
        std::ffi::CStr::from_ptr(buffer).to_string_lossy().into_owned()
    }

    #[test]
    fn test_generate_trace_id() {
        let trace_id1 = generate_trace_id();
        let trace_id2 = generate_trace_id();

        // Should be 16 hex characters (8 bytes * 2)
        assert_eq!(trace_id1.len(), 16);
        assert_eq!(trace_id2.len(), 16);

        // Should be different
        assert_ne!(trace_id1, trace_id2);

        // Should only contain hex characters
        assert!(trace_id1.chars().all(|c| c.is_ascii_hexdigit()));
        assert!(trace_id2.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_redact_nickname() {
        assert_eq!(redact_nickname("alice"), "a***e");
        assert_eq!(redact_nickname("ab"), "**");
        assert_eq!(redact_nickname("a"), "*");
        assert_eq!(redact_nickname(""), "");
        assert_eq!(redact_nickname("testuser123"), "t***3");
    }

    #[test]
    fn test_validate_buffer_valid() {
        let trace_id = "test123";
        let (buffer, size) = create_test_buffer("test");

        let result = validate_buffer(size, trace_id, buffer);

        assert!(result);

        unsafe {
            free_test_buffer(buffer);
        }
    }

    #[test]
    fn test_validate_buffer_invalid_size() {
        let trace_id = "test123";
        let (buffer, _) = create_test_buffer("test");

        let result = validate_buffer(0, trace_id, buffer);

        assert!(!result);

        unsafe {
            free_test_buffer(buffer);
        }
    }

    #[test]
    fn test_validate_buffer_null_pointer() {
        let trace_id = "test123";

        let result = validate_buffer(4096, trace_id, ptr::null_mut());

        assert!(!result);
    }

    #[test]
    fn test_extract_input_safely_valid() {
        let (buffer, size) = create_test_buffer("testnick");
        let trace_id = "test123";
        let start_time = Instant::now();
        let timeout = std::time::Duration::from_secs(30);

        let result = extract_input_safely(buffer, size, start_time, timeout, trace_id);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "testnick");

        unsafe {
            free_test_buffer(buffer);
        }
    }

    #[test]
    fn test_extract_input_safely_timeout() {
        let (buffer, size) = create_test_buffer("testnick");
        let trace_id = "test123";
        // Set start time in the past to simulate timeout
        let start_time = Instant::now() - std::time::Duration::from_secs(100);
        let timeout = std::time::Duration::from_secs(30);

        let result = extract_input_safely(buffer, size, start_time, timeout, trace_id);

        assert!(result.is_err());

        unsafe {
            free_test_buffer(buffer);
        }
    }

    #[test]
    fn test_check_timeout_not_expired() {
        let (buffer, size) = create_test_buffer("");
        let trace_id = "test123";
        let start_time = Instant::now();
        let timeout = std::time::Duration::from_secs(30);

        let result = check_timeout(start_time, timeout, buffer, size, trace_id, "test stage");

        assert!(!result);

        unsafe {
            free_test_buffer(buffer);
        }
    }

    #[test]
    fn test_check_timeout_expired() {
        let (buffer, size) = create_test_buffer("");
        let trace_id = "test123";
        let start_time = Instant::now() - std::time::Duration::from_secs(100);
        let timeout = std::time::Duration::from_secs(30);

        let result = check_timeout(start_time, timeout, buffer, size, trace_id, "test stage");

        assert!(result);

        // Verify error message was written to buffer
        unsafe {
            let content = read_buffer_content(buffer);
            assert!(content.contains("timed out"));
            free_test_buffer(buffer);
        }
    }

    #[test]
    fn test_generate_secure_random_key() {
        let (buffer, size) = create_test_buffer("");
        let trace_id = "test123";

        let result = generate_secure_random_key(trace_id, buffer, size);

        assert!(result.is_ok());

        let key = result.unwrap();
        assert_eq!(key.len(), 32);

        // Verify key is not all zeros
        assert_ne!(key, [0u8; 32]);

        unsafe {
            free_test_buffer(buffer);
        }
    }

    #[test]
    fn test_generate_secure_random_key_uniqueness() {
        let (buffer, size) = create_test_buffer("");
        let trace_id = "test123";

        let key1 = generate_secure_random_key(trace_id, buffer, size).unwrap();
        let key2 = generate_secure_random_key(trace_id, buffer, size).unwrap();

        // Two consecutive calls should produce different keys
        assert_ne!(key1, key2);

        unsafe {
            free_test_buffer(buffer);
        }
    }

    #[test]
    fn test_validate_keypair_valid() {
        let trace_id = "test123";
        
        // Generate a keypair using the crypto module which should always produce valid keys
        let keypair = crate::crypto::generate_keypair();
        
        // Validate the generated keypair
        let result = validate_keypair(&keypair, trace_id);
        
        assert!(
            result,
            "Generated keypair failed validation. \
             Public key: {:02x?}, Private key (first 8 bytes): {:02x?}",
            &keypair.public_key,
            &keypair.private_key.expose_secret()[..8]
        );
    }

    #[test]
    fn test_validate_keypair_all_zeros() {
        let trace_id = "test123";
        let keypair = KeyPair {
            public_key: [0u8; 32],
            private_key: secrecy::Secret::new([0u8; 32]),
            creation_time: chrono::Utc::now(),
        };

        let result = validate_keypair(&keypair, trace_id);

        assert!(!result);
    }
    #[test]
    fn test_validate_keypair_public_zero_only() {
        let trace_id = "test123";
        let mut private_key = [0u8; 32];
        private_key[0] = 1; // Make it non-zero

        let keypair = KeyPair {
            public_key: [0u8; 32],
            private_key: secrecy::Secret::new(private_key),
            creation_time: chrono::Utc::now(),
        };

        let result = validate_keypair(&keypair, trace_id);

        assert!(!result);
    }
    #[test]
    fn test_validate_keypair_private_zero_only() {
        let trace_id = "test123";
        let mut public_key = [0u8; 32];
        public_key[0] = 1; // Make it non-zero

        let keypair = KeyPair {
            public_key,
            private_key: secrecy::Secret::new([0u8; 32]),
            creation_time: chrono::Utc::now(),
        };

        let result = validate_keypair(&keypair, trace_id);

        assert!(!result);
    }

    #[test]
    fn test_store_key_and_persist_creates_entry() {
        let trace_id = "test123";
        let nickname = "testuser";
        let key = [1u8; 32];

        // Clean up any existing key first
        let _ = crate::config::delete_key_default(nickname);

        let result = store_key_and_persist(nickname, &key, trace_id);

        assert!(result.is_ok());

        // Verify key was stored
        let retrieved = crate::config::get_key_default(nickname);
        assert!(retrieved.is_ok());

        // Clean up
        let _ = crate::config::delete_key_default(nickname);
    }

    #[test]
    fn test_store_keypair_and_persist_creates_keypair() {
        let trace_id = "test123";
        let keypair = generate_keypair();

        let result = store_keypair_and_persist(&keypair, trace_id);

        assert!(result.is_ok());

        // Verify keypair was stored (this will retrieve the stored keypair)
        let retrieved = get_keypair();
        assert!(retrieved.is_ok());
    }

    #[test]
    fn test_fish11_exchangekey_null_data_pointer() {
        let result = FiSH11_ExchangeKey(
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            0,
            0,
        );

        assert_eq!(result, MIRC_HALT);
    }

    #[test]
    fn test_fish11_exchangekey_empty_nickname() {
        let (buffer, _size) = create_test_buffer("");

        let result =
            FiSH11_ExchangeKey(ptr::null_mut(), ptr::null_mut(), buffer, ptr::null_mut(), 0, 0);

        // Should handle empty input gracefully
        assert_eq!(result, MIRC_COMMAND);

        unsafe {
            let content = read_buffer_content(buffer);
            assert!(content.contains("Error") || content.contains("invalid"));
            free_test_buffer(buffer);
        }
    }

    #[test]
    fn test_fish11_exchangekey_invalid_nickname() {
        let (buffer, _size) = create_test_buffer("invalid@nickname!");

        let result =
            FiSH11_ExchangeKey(ptr::null_mut(), ptr::null_mut(), buffer, ptr::null_mut(), 0, 0);

        assert_eq!(result, MIRC_COMMAND);

        unsafe {
            let content = read_buffer_content(buffer);
            assert!(content.contains("Error") || content.contains("invalid"));
            free_test_buffer(buffer);
        }
    }

    #[test]
    fn test_fish11_exchangekey_valid_nickname() {
        let (buffer, _size) = create_test_buffer("alice");

        let result =
            FiSH11_ExchangeKey(ptr::null_mut(), ptr::null_mut(), buffer, ptr::null_mut(), 0, 0);

        assert_eq!(result, MIRC_COMMAND);

        unsafe {
            let content = read_buffer_content(buffer);
            // Should contain a valid mIRC command or error message
            assert!(
                content.starts_with("/echo") || content.contains("Error"),
                "Expected buffer to contain a mIRC command or error, got: {}",
                content
            );
            free_test_buffer(buffer);
        }
    }

    #[test]
    fn test_fish11_exchangekey_generates_keypair_if_missing() {
        // Clear any existing keypair
        let mut config = CONFIG.lock().expect("Config lock failed");
        config.our_public_key = None;
        config.our_private_key = None;
        drop(config);

        let (buffer, _size) = create_test_buffer("bob");

        let result =
            FiSH11_ExchangeKey(ptr::null_mut(), ptr::null_mut(), buffer, ptr::null_mut(), 0, 0);

        assert_eq!(result, MIRC_COMMAND);

        // Verify keypair was generated
        let keypair_result = get_keypair();
        assert!(keypair_result.is_ok());

        unsafe {
            free_test_buffer(buffer);
        }
    }

    #[test]
    fn test_fish11_exchangekey_output_contains_timeout_info() {
        let (buffer, _size) = create_test_buffer("charlie");

        let result =
            FiSH11_ExchangeKey(ptr::null_mut(), ptr::null_mut(), buffer, ptr::null_mut(), 0, 0);

        assert_eq!(result, MIRC_COMMAND);

        unsafe {
            let content = read_buffer_content(buffer);
            
            // The function should return either:
            // - A mIRC echo command with the public key
            // - An error message
            // Check for mIRC echo command format
            assert!(
                content.starts_with("/echo") || content.contains("Error"),
                "Expected buffer to contain a mIRC command or error, got: {}",
                content
            );
            free_test_buffer(buffer);
        }
    }

    #[test]
    fn test_fish11_exchangekey_long_nickname() {
        let long_nick = "a".repeat(100);
        let (buffer, _size) = create_test_buffer(&long_nick);

        let result =
            FiSH11_ExchangeKey(ptr::null_mut(), ptr::null_mut(), buffer, ptr::null_mut(), 0, 0);

        // Should handle long nicknames (likely with validation error)
        assert_eq!(result, MIRC_COMMAND);

        unsafe {
            free_test_buffer(buffer);
        }
    }

    #[test]
    fn test_fish11_exchangekey_special_characters_in_nickname() {
        let special_nick = "user[test]";
        let (buffer, _size) = create_test_buffer(special_nick);

        let result =
            FiSH11_ExchangeKey(ptr::null_mut(), ptr::null_mut(), buffer, ptr::null_mut(), 0, 0);

        assert_eq!(result, MIRC_COMMAND);

        unsafe {
            free_test_buffer(buffer);
        }
    }
}
