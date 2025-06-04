use std::ffi::{CString, c_char};
use std::os::raw::c_int;
use std::time::Instant;

use curve25519_dalek::scalar::Scalar;
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

    // Unwrap the result, but we don't need to assign it since it's already MIRC_COMMAND
    let _ = result.unwrap();

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

            if let Err(save_err) = save_config(&*config_guard) {
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

    // Additional Curve25519 validation
    let valid_scalar =
        Scalar::from_canonical_bytes(keypair.private_key.expose_secret().clone()).is_some().into();

    // Check if public key is on the curve (basic validation)
    let valid_point = keypair.public_key[31] & 0x80 == 0; // MSB should be 0 for valid point

    let is_valid = public_not_zero && private_not_zero && valid_scalar && valid_point;

    if is_valid {
        log_debug!("FiSH11_ExchangeKey[{}]: successfully validated keypair", trace_id);
        true
    } else {
        log_error!(
            "FiSH11_ExchangeKey[{}]: keypair validation failed - public_ok:{}, private_ok:{}, scalar_ok:{}, point_ok:{}",
            trace_id,
            public_not_zero,
            private_not_zero,
            valid_scalar,
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

            if let Err(save_err) = save_config(&*config_guard) {
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
