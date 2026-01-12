//! FiSH 10 Engine Integration for fish_inject
//!
//! This module provides an engine that can be registered with fish_inject
//! to automatically detect and process FiSH 10 messages.

use crate::legacy::encryption::{is_legacy_message, legacy_decrypt, legacy_encrypt};
use crate::legacy::key_management::{
    compute_dh1080_shared_secret, generate_dh1080_keypair, set_legacy_key,
};
use crate::legacy::message_detection::{
    extract_dh1080_public_key, is_dh1080_message, parse_dh1080_message_type,
};
use crate::unified_error::DllError;
use fish_11_core::globals::FISH_INJECT_ENGINE_VERSION;
use log::{debug, error, info, trace};
use std::ffi::{CStr, CString};
use std::sync::OnceLock;

// Re-export for use in handle_dh1080_message
use sha2::{Digest, Sha256};

/// FiSH 10 Engine structure
#[repr(C)]
pub struct Fish10Engine {
    pub version: u32,
    pub engine_name: *const i8,
    pub is_postprocessor: bool,
    pub on_outgoing_irc_line: unsafe extern "C" fn(u32, *const i8, usize) -> *mut i8,
    pub on_incoming_irc_line: unsafe extern "C" fn(u32, *const i8, usize) -> *mut i8,
    pub on_socket_closed: unsafe extern "C" fn(u32),
    pub free_string: unsafe extern "C" fn(*mut i8),
    pub get_network_name: unsafe extern "C" fn(u32) -> *mut i8,
}

unsafe impl Sync for Fish10Engine {}
unsafe impl Send for Fish10Engine {}

/// Global instance of the FiSH 10 engine
static FISH10_ENGINE_INSTANCE: OnceLock<Fish10Engine> = OnceLock::new();

/// Global storage for the engine name to prevent dangling pointer
/// This is intentionally leaked because the engine lives for the entire program lifetime
static mut ENGINE_NAME_PTR: *mut i8 = std::ptr::null_mut();

/// Initialize the FiSH 10 engine
pub fn init_fish10_engine() -> Result<*const Fish10Engine, DllError> {
    info!("LEGACY: initializing FiSH 10 engine for fish_inject integration");

    let engine_name = CString::new("FiSH10_Legacy_Engine").map_err(|e| DllError::LegacyError {
        context: "Engine initialization".to_string(),
        cause: format!("Failed to create engine name: {}", e),
    })?;

    // SAFETY: we intentionally leak the CString to keep the pointer valid
    // for the entire program lifetime. This is acceptable because the engine
    // is a singleton that lives forever.
    let engine_name_ptr = engine_name.into_raw();

    unsafe {
        ENGINE_NAME_PTR = engine_name_ptr;
    }

    let engine = Fish10Engine {
        version: FISH_INJECT_ENGINE_VERSION,
        engine_name: engine_name_ptr,
        is_postprocessor: false, // Process before other engines
        on_outgoing_irc_line: fish10_on_outgoing_irc_line,
        on_incoming_irc_line: fish10_on_incoming_irc_line,
        on_socket_closed: fish10_on_socket_closed,
        free_string: fish10_free_string,
        get_network_name: fish10_get_network_name,
    };

    match FISH10_ENGINE_INSTANCE.set(engine) {
        Ok(()) => Ok(FISH10_ENGINE_INSTANCE.get().unwrap() as *const _),
        Err(_engine) => Ok(FISH10_ENGINE_INSTANCE.get().unwrap() as *const _),
    }
}

/// Get a reference to the FiSH 10 engine instance
pub fn get_fish10_engine() -> Option<*const Fish10Engine> {
    FISH10_ENGINE_INSTANCE.get().map(|e| e as *const _)
}

/// Callback for outgoing IRC lines
unsafe extern "C" fn fish10_on_outgoing_irc_line(
    socket: u32,
    line: *const i8,
    len: usize,
) -> *mut i8 {
    trace!("FiSH10 Engine: processing outgoing line on socket {}", socket);

    if line.is_null() {
        error!("FiSH10 Engine: received null pointer for outgoing line");
        return std::ptr::null_mut();
    }

    // Use len parameter to validate and create a slice
    // This is safer than relying solely on null termination
    let line_str = if len > 0 {
        // If len is provided, use it for validation
        let slice = std::slice::from_raw_parts(line as *const u8, len);
        match std::str::from_utf8(slice) {
            Ok(s) => s.trim_end_matches('\0'),
            Err(e) => {
                error!("FiSH10 Engine: failed to convert outgoing line to UTF-8: {}", e);
                return std::ptr::null_mut();
            }
        }
    } else {
        // Fallback to CStr for null-terminated strings
        match CStr::from_ptr(line).to_str() {
            Ok(s) => s,
            Err(e) => {
                error!("FiSH10 Engine: failed to convert outgoing line to UTF-8: {}", e);
                return std::ptr::null_mut();
            }
        }
    };

    // Check if this is a PRIVMSG or NOTICE that should be encrypted with FiSH 10
    if let Some(encrypted_line) = process_outgoing_fish10_message(line_str) {
        match CString::new(encrypted_line) {
            Ok(c_string) => c_string.into_raw(),
            Err(e) => {
                error!("FiSH10 Engine: failed to convert encrypted line to CString: {}", e);
                std::ptr::null_mut()
            }
        }
    } else {
        std::ptr::null_mut() // No modification
    }
}

/// Process an outgoing message and encrypt it with FiSH 10 if appropriate
fn process_outgoing_fish10_message(line: &str) -> Option<String> {
    // Parse the IRC line to extract target and message
    let parts: Vec<&str> = line.splitn(3, ' ').collect();

    if parts.len() < 3 {
        debug!("FiSH10 Engine: line is too short for encryption: {}", line);
        return None;
    }

    let command = parts[0];
    let target = parts[1];
    let message = parts[2];

    // Only encrypt PRIVMSG and NOTICE commands
    if command != "PRIVMSG" && command != "NOTICE" {
        debug!("FiSH10 Engine: not encrypting non-message command: {}", command);
        return None;
    }

    // Check if we have a legacy key for this target
    if !crate::legacy::is_legacy_target(target) {
        debug!("FiSH10 Engine: no legacy key found for target: {}", target);
        return None;
    }

    // Encrypt the message
    match legacy_encrypt(target, message) {
        Ok(encrypted) => {
            info!("FiSH10 Engine: encrypted message for {}: {}", target, encrypted);
            Some(format!("{} {} {}", command, target, encrypted))
        }
        Err(e) => {
            error!("FiSH10 Engine: failed to encrypt message for {}: {}", target, e);
            None
        }
    }
}

/// Callback for incoming IRC lines
unsafe extern "C" fn fish10_on_incoming_irc_line(
    socket: u32,
    line: *const i8,
    len: usize,
) -> *mut i8 {
    trace!("FiSH10 Engine: processing incoming line on socket {}", socket);

    if line.is_null() {
        error!("FiSH10 Engine: received null pointer for incoming line");
        return std::ptr::null_mut();
    }

    // Use len parameter to validate and create a slice
    // This is safer than relying solely on null termination
    let line_str = if len > 0 {
        // If len is provided, use it for validation
        let slice = std::slice::from_raw_parts(line as *const u8, len);
        match std::str::from_utf8(slice) {
            Ok(s) => s.trim_end_matches('\0'),
            Err(e) => {
                error!("FiSH10 Engine: failed to convert incoming line to UTF-8: {}", e);
                return std::ptr::null_mut();
            }
        }
    } else {
        // Fallback to CStr for null-terminated strings
        match CStr::from_ptr(line).to_str() {
            Ok(s) => s,
            Err(e) => {
                error!("FiSH10 Engine: failed to convert incoming line to UTF-8: {}", e);
                return std::ptr::null_mut();
            }
        }
    };

    // Check if this is a FiSH 10 message or DH1080 message
    if let Some(decrypted_line) = process_incoming_fish10_message(line_str) {
        match CString::new(decrypted_line) {
            Ok(c_string) => c_string.into_raw(),
            Err(e) => {
                error!("FiSH10 Engine: failed to convert decrypted line to CString: {}", e);
                std::ptr::null_mut()
            }
        }
    } else {
        std::ptr::null_mut() // No modification
    }
}

/// Process an incoming message and decrypt it if it's a FiSH 10 message
fn process_incoming_fish10_message(line: &str) -> Option<String> {
    // Check if this is a FiSH 10 encrypted message
    if is_legacy_message(line) {
        return handle_fish10_encrypted_message(line);
    }

    // Check if this is a DH1080 key exchange message
    if is_dh1080_message(line) {
        return handle_dh1080_message(line);
    }

    None // Not a FiSH 10 message
}

/// Handle an incoming FiSH 10 encrypted message
fn handle_fish10_encrypted_message(line: &str) -> Option<String> {
    // Parse the IRC line to extract the encrypted payload
    let parts: Vec<&str> = line.splitn(3, ' ').collect();

    if parts.len() < 3 {
        debug!("FiSH10 Engine: FiSH10 is line too short: {}", line);
        return None;
    }

    let command = parts[0];
    let target = parts[1];
    let encrypted_payload = parts[2];

    // Extract the actual encrypted data (remove +OK prefix)
    let payload = encrypted_payload.trim();
    let payload = if let Some(stripped) = payload.strip_prefix("+OK ") {
        stripped
    } else {
        error!("FiSH10 Engine: message does not have +OK prefix: {}", encrypted_payload);
        return None;
    };

    if payload.is_empty() {
        error!("FiSH10 Engine: empty payload after removing +OK prefix");
        return None;
    }

    // Decrypt the message
    match legacy_decrypt(target, &payload) {
        Ok(decrypted) => {
            info!("FiSH10 Engine: Decrypted message from {}: {}", target, decrypted);
            Some(format!("{} {} {}", command, target, decrypted))
        }
        Err(e) => {
            error!("FiSH10 Engine: failed to decrypt message from {}: {}", target, e);
            None
        }
    }
}

/// Handle an incoming DH1080 key exchange message
fn handle_dh1080_message(line: &str) -> Option<String> {
    // Parse the IRC line to extract the DH1080 message
    let parts: Vec<&str> = line.splitn(3, ' ').collect();

    if parts.len() < 3 {
        debug!("FiSH10 Engine: DH1080 line is too short: {}", line);
        return None;
    }

    let command = parts[0];
    let target = parts[1];
    let dh1080_message = parts[2];

    // Extract message type and public key
    let message_type = parse_dh1080_message_type(dh1080_message)?;
    let public_key = extract_dh1080_public_key(dh1080_message)?;

    match message_type {
        "INIT" => {
            // Generate our DH1080 key pair and send FINISH message
            match generate_dh1080_keypair() {
                Ok(keypair) => {
                    // Store our private key for later use
                    let mut config = super::LEGACY_CONFIG.write();
                    let mut dh1080_keys = config.dh1080_keys.write();
                    dh1080_keys.insert(target.to_string(), keypair.private_key());

                    // Compute shared secret
                    let shared_secret =
                        compute_dh1080_shared_secret(&keypair.private_key(), &public_key);

                    match shared_secret {
                        Ok(secret) => {
                            // Convert shared secret to Blowfish key and store it
                            // For FiSH 10, we use the first 8 bytes of the SHA256 hash as the Blowfish key
                            let mut hasher = Sha256::new();
                            hasher.update(secret.as_bytes());
                            let hash = hasher.finalize();
                            let blowfish_key = &hash[..8]; // First 8 bytes for Blowfish (64 bits)

                            // Store the Blowfish key for this target
                            set_legacy_key(target, &hex::encode(blowfish_key)).ok();

                            info!(
                                "FiSH10 Engine: DH1080 key exchange completed for {}, Blowfish key set",
                                target
                            );

                            // Return the FINISH message
                            Some(format!(
                                "{} {} DH1080_FINISH {}",
                                command, target, keypair.public_key
                            ))
                        }
                        Err(e) => {
                            error!(
                                "FiSH10 Engine: Failed to compute shared secret for {}: {}",
                                target, e
                            );
                            None
                        }
                    }
                }
                Err(e) => {
                    error!(
                        "FiSH10 Engine: Failed to generate DH1080 keypair for {}: {}",
                        target, e
                    );
                    None
                }
            }
        }
        "FINISH" => {
            // We received a FINISH message, compute shared secret using our stored private key
            let config = super::LEGACY_CONFIG.read();
            let dh1080_keys = config.dh1080_keys.read();

            if let Some(private_key_bn) = dh1080_keys.get(target) {
                let shared_secret = compute_dh1080_shared_secret(private_key_bn, &public_key);

                match shared_secret {
                    Ok(secret) => {
                        // Convert shared secret to Blowfish key and store it
                        let mut hasher = Sha256::new();
                        hasher.update(secret.as_bytes());
                        let hash = hasher.finalize();
                        let blowfish_key = &hash[..8]; // First 8 bytes for Blowfish (64 bits)

                        // Store the Blowfish key for this target
                        set_legacy_key(target, &hex::encode(blowfish_key)).ok();

                        info!(
                            "FiSH10 Engine: DH1080 key exchange completed for {}, Blowfish key set",
                            target
                        );

                        // Return the original message (no modification needed)
                        Some(line.to_string())
                    }
                    Err(e) => {
                        error!(
                            "FiSH10 Engine: failed to compute shared secret for {}: {}",
                            target, e
                        );
                        None
                    }
                }
            } else {
                error!("FiSH10 Engine: no private key found for DH1080 FINISH from {}", target);
                None
            }
        }
        _ => {
            debug!("FiSH10 Engine: unknown DH1080 message type: {}", message_type);
            None
        }
    }
}

/// Callback for socket closed events
unsafe extern "C" fn fish10_on_socket_closed(socket: u32) {
    info!("FiSH10 Engine: Socket {} closed", socket);
    // Clean up any legacy state associated with this socket
    // TODO: implement socket-specific cleanup if needed
}

/// Callback to free strings allocated by the engine
unsafe extern "C" fn fish10_free_string(ptr: *mut i8) {
    if !ptr.is_null() {
        let _ = CString::from_raw(ptr);
    }
}

/// TODO : callback to get network name for a socket
unsafe extern "C" fn fish10_get_network_name(_socket: u32) -> *mut i8 {
    // For now, return NULL as we don't use the existing function for doing that
    std::ptr::null_mut()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn test_engine_initialization() {
        let engine_ptr = init_fish10_engine();
        assert!(engine_ptr.is_ok());

        let engine = engine_ptr.unwrap();
        unsafe {
            assert!(!engine.is_null());
            let engine_ref = &*engine;
            assert_eq!(engine_ref.version, FISH_INJECT_ENGINE_VERSION);
        }
    }

    #[test]
    fn test_fish10_message_detection() {
        let test_line = "PRIVMSG #channel :+OK abc123";
        let c_line = CString::new(test_line).unwrap();

        unsafe {
            let result = fish10_on_incoming_irc_line(123, c_line.as_ptr(), test_line.len());
            // Should return a decrypted version or null if no key is set
            // For this test, we just check it doesn't crash
            if !result.is_null() {
                let _ = CString::from_raw(result);
            }
        }
    }

    #[test]
    fn test_dh1080_message_detection() {
        let test_line = "PRIVMSG #channel :DH1080_INIT abc123";
        let c_line = CString::new(test_line).unwrap();

        unsafe {
            let result = fish10_on_incoming_irc_line(123, c_line.as_ptr(), test_line.len());
            // Should return a response or null
            if !result.is_null() {
                let _ = CString::from_raw(result);
            }
        }
    }
}
