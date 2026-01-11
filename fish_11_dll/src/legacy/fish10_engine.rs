//! FiSH 10 Engine Integration for fish_inject
//!
//! This module provides an engine that can be registered with fish_inject
//! to automatically detect and process FiSH 10 messages.

use fish_11_core::globals::FISH_INJECT_ENGINE_VERSION;
use log::{debug, error, info, trace};
use std::ffi::{CStr, CString};

use crate::legacy::encryption::{is_legacy_message, legacy_decrypt, legacy_encrypt};
use crate::unified_error::DllError;

/// FiSH 10 Engine structure that implements the fish_inject engine interface
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

/// Global instance of the FiSH 10 engine
static mut FISH10_ENGINE_INSTANCE: Option<Fish10Engine> = None;

/// Initialize the FiSH 10 engine
pub fn init_fish10_engine() -> Result<*const Fish10Engine, DllError> {
    info!("LEGACY: Initializing FiSH 10 engine for fish_inject integration");

    let engine_name = CString::new("FiSH10_Legacy_Engine").map_err(|e| DllError::LegacyError {
        context: "Engine initialization".to_string(),
        cause: format!("Failed to create engine name: {}", e),
    })?;

    let engine = Fish10Engine {
        version: FISH_INJECT_ENGINE_VERSION,
        engine_name: engine_name.as_ptr(),
        is_postprocessor: false, // Process before other engines
        on_outgoing_irc_line: fish10_on_outgoing_irc_line,
        on_incoming_irc_line: fish10_on_incoming_irc_line,
        on_socket_closed: fish10_on_socket_closed,
        free_string: fish10_free_string,
        get_network_name: fish10_get_network_name,
    };

    unsafe {
        FISH10_ENGINE_INSTANCE = Some(engine);
        Ok(FISH10_ENGINE_INSTANCE.as_ref().unwrap())
    }
}

/// Get a reference to the FiSH 10 engine instance
pub fn get_fish10_engine() -> Option<*const Fish10Engine> {
    unsafe { FISH10_ENGINE_INSTANCE.as_ref().map(|e| e as *const _) }
}

/// Callback for outgoing IRC lines
unsafe extern "C" fn fish10_on_outgoing_irc_line(
    socket: u32,
    line: *const i8,
    len: usize,
) -> *mut i8 {
    trace!("FiSH10 Engine: Processing outgoing line on socket {}", socket);

    // Convert the C string to a Rust string
    let line_str = match CStr::from_ptr(line).to_str() {
        Ok(s) => s,
        Err(e) => {
            error!("FiSH10 Engine: Failed to convert outgoing line to UTF-8: {}", e);
            return std::ptr::null_mut();
        }
    };

    // Check if this is a PRIVMSG or NOTICE that should be encrypted with FiSH 10
    if let Some(encrypted_line) = process_outgoing_fish10_message(line_str) {
        match CString::new(encrypted_line) {
            Ok(c_string) => c_string.into_raw(),
            Err(e) => {
                error!("FiSH10 Engine: Failed to convert encrypted line to CString: {}", e);
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
        debug!("FiSH10 Engine: Line too short for encryption: {}", line);
        return None;
    }

    let command = parts[0];
    let target = parts[1];
    let message = parts[2];

    // Only encrypt PRIVMSG and NOTICE commands
    if command != "PRIVMSG" && command != "NOTICE" {
        debug!("FiSH10 Engine: Not encrypting non-message command: {}", command);
        return None;
    }

    // Check if we have a legacy key for this target
    if !crate::legacy::is_legacy_target(target) {
        debug!("FiSH10 Engine: No legacy key found for target: {}", target);
        return None;
    }

    // Encrypt the message
    match legacy_encrypt(target, message) {
        Ok(encrypted) => {
            info!("FiSH10 Engine: Encrypted message for {}: {}", target, encrypted);
            Some(format!("{} {} {}", command, target, encrypted))
        }
        Err(e) => {
            error!("FiSH10 Engine: Failed to encrypt message for {}: {}", target, e);
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
    trace!("FiSH10 Engine: Processing incoming line on socket {}", socket);

    // Convert the C string to a Rust string
    let line_str = match CStr::from_ptr(line).to_str() {
        Ok(s) => s,
        Err(e) => {
            error!("FiSH10 Engine: Failed to convert incoming line to UTF-8: {}", e);
            return std::ptr::null_mut();
        }
    };

    // Check if this is a FiSH 10 message or DH1080 message
    if let Some(decrypted_line) = process_incoming_fish10_message(line_str) {
        match CString::new(decrypted_line) {
            Ok(c_string) => c_string.into_raw(),
            Err(e) => {
                error!("FiSH10 Engine: Failed to convert decrypted line to CString: {}", e);
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

    None // Not a FiSH 10 message
}

/// Handle an incoming FiSH 10 encrypted message
fn handle_fish10_encrypted_message(line: &str) -> Option<String> {
    // Parse the IRC line to extract the encrypted payload
    let parts: Vec<&str> = line.splitn(3, ' ').collect();

    if parts.len() < 3 {
        debug!("FiSH10 Engine: FiSH 10 line too short: {}", line);
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
        error!("FiSH10 Engine: Message does not have +OK prefix: {}", encrypted_payload);
        return None;
    };

    if payload.is_empty() {
        error!("FiSH10 Engine: Empty payload after removing +OK prefix");
        return None;
    }

    // Decrypt the message
    match legacy_decrypt(target, &payload) {
        Ok(decrypted) => {
            info!("FiSH10 Engine: Decrypted message from {}: {}", target, decrypted);
            Some(format!("{} {} {}", command, target, decrypted))
        }
        Err(e) => {
            error!("FiSH10 Engine: Failed to decrypt message from {}: {}", target, e);
            None
        }
    }
}

/// Callback for socket closed events
unsafe extern "C" fn fish10_on_socket_closed(socket: u32) {
    info!("FiSH10 Engine: Socket {} closed", socket);
    // Clean up any legacy state associated with this socket
    // TODO: Implement socket-specific cleanup if needed
}

/// Callback to free strings allocated by the engine
unsafe extern "C" fn fish10_free_string(ptr: *mut i8) {
    if !ptr.is_null() {
        let _ = CString::from_raw(ptr);
    }
}

/// Callback to get network name for a socket
unsafe extern "C" fn fish10_get_network_name(socket: u32) -> *mut i8 {
    // For now, return NULL as we don't have network information
    // This could be enhanced later if needed
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
