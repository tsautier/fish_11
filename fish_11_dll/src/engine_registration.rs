//! engine_registration.rs
//! Handles the registration of the fish_11_dll as an engine within fish_11_inject.

use std::ffi::{CString, c_char};
use std::ptr;

use log::{error, info, warn};
use winapi::shared::minwindef::{FARPROC, HMODULE};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};

use crate::crypto::{decrypt_message, encrypt_message};

// C-style struct for engine registration
#[repr(C)]
pub struct FishInjectEngine {
    pub version: u32,
    pub engine_name: *const c_char,
    pub is_postprocessor: bool,
    pub on_outgoing_irc_line: unsafe extern "C" fn(u32, *const c_char, usize) -> *mut c_char,
    pub on_incoming_irc_line: unsafe extern "C" fn(u32, *const c_char, usize) -> *mut c_char,
    pub on_socket_closed: unsafe extern "C" fn(u32),
    pub free_string: unsafe extern "C" fn(*mut c_char),
}

// SAFETY: FishInjectEngine contains raw pointers but is used for FFI with static data
unsafe impl Sync for FishInjectEngine {}

// Callback for outgoing messages (encryption)
unsafe extern "C" fn on_outgoing(_socket: u32, line: *const c_char, _len: usize) -> *mut c_char {
    if line.is_null() {
        return ptr::null_mut();
    }
    
    // CRITICAL: Use CStr::from_ptr (borrow) NOT CString::from_raw (take ownership)
    // The caller (inject DLL) still owns this pointer!
    let c_str = match std::ffi::CStr::from_ptr(line).to_str() {
        Ok(s) => s,
        Err(e) => {
            error!("Invalid UTF-8 in outgoing line: {}", e);
            return ptr::null_mut();
        }
    };

    if let Some(encrypted) = attempt_encryption(c_str) {
        match CString::new(encrypted) {
            Ok(s) => return s.into_raw(),
            Err(e) => {
                error!("Failed to create CString for encrypted data: {}", e);
                return ptr::null_mut();
            }
        }
    }
    ptr::null_mut()
}

// Callback for incoming messages (decryption)
unsafe extern "C" fn on_incoming(_socket: u32, line: *const c_char, _len: usize) -> *mut c_char {
    if line.is_null() {
        return ptr::null_mut();
    }
    
    // CRITICAL: Use CStr::from_ptr (borrow) NOT CString::from_raw (take ownership)
    // The caller (inject DLL) still owns this pointer!
    let c_str = match std::ffi::CStr::from_ptr(line).to_str() {
        Ok(s) => s,
        Err(e) => {
            error!("Invalid UTF-8 in incoming line: {}", e);
            return ptr::null_mut();
        }
    };

    if let Some(decrypted) = attempt_decryption(c_str) {
        match CString::new(decrypted) {
            Ok(s) => return s.into_raw(),
            Err(e) => {
                error!("Failed to create CString for decrypted data: {}", e);
                return ptr::null_mut();
            }
        }
    }
    ptr::null_mut()
}

// Placeholder for socket close event
unsafe extern "C" fn on_close(_socket: u32) {}

// Function to free memory allocated for returned strings
unsafe extern "C" fn free_string(s: *mut c_char) {
    if !s.is_null() {
        drop(CString::from_raw(s));
    }
}

// Engine definition
#[no_mangle]
pub static FISH_INJECT_ENGINE: FishInjectEngine = FishInjectEngine {
    version: 1,
    engine_name: b"FiSH_11_Engine".as_ptr() as *const _,
    is_postprocessor: false,
    on_outgoing_irc_line: on_outgoing,
    on_incoming_irc_line: on_incoming,
    on_socket_closed: on_close,
    free_string,
};

// Function to attempt encryption
fn attempt_encryption(line: &str) -> Option<String> {
    // Only encrypt outgoing PRIVMSG/NOTICE commands
    if !line.contains(" PRIVMSG ") && !line.contains(" NOTICE ") {
        return None;
    }
    
    log::debug!("Engine: attempting to encrypt outgoing line");
    
    // Parse the line to extract target and message
    // Format expected: "PRIVMSG target :message" or ":prefix PRIVMSG target :message"
    let parts: Vec<&str> = line.split(" :").collect();
    if parts.len() < 2 {
        log::warn!("Engine: malformed outgoing line (no message part)");
        return None;
    }
    
    // Get the command part (before the first " :")
    let cmd_part = parts[0];
    let message = parts[1..].join(" :");
    
    // Extract target from command part
    // Could be "PRIVMSG #channel" or ":prefix PRIVMSG #channel"
    let target = if let Some(privmsg_pos) = cmd_part.find(" PRIVMSG ") {
        cmd_part[privmsg_pos + 9..].trim()
    } else if let Some(notice_pos) = cmd_part.find(" NOTICE ") {
        cmd_part[notice_pos + 8..].trim()
    } else {
        log::warn!("Engine: could not extract target from command part");
        return None;
    };
    
    log::debug!("Engine: target={}, message_len={}", target, message.len());
    
    // Try to get encryption key for target
    let key = match crate::config::get_key_default(target) {
        Ok(k) => k,
        Err(_) => {
            // No key = no encryption, pass through
            log::debug!("Engine: no key for target '{}', not encrypting", target);
            return None;
        }
    };
    
    let key_array: &[u8; 32] = match key.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => {
            log::error!("Engine: invalid key length for target '{}'", target);
            return None;
        }
    };
    
    // Encrypt the message
    let encrypted = match encrypt_message(key_array, &message, Some(target)) {
        Ok(enc) => enc,
        Err(e) => {
            log::error!("Engine: encryption failed for target '{}': {}", target, e);
            return None;
        }
    };
    
    log::info!("Engine: successfully encrypted message to '{}'", target);
    
    // Reconstruct line with encrypted data
    // Keep prefix if present, replace message with "+FiSH <encrypted>"
    // Add \r\n for IRC protocol compliance
    let encrypted_line = format!("{} :+FiSH {}\r\n", cmd_part, encrypted);
    
    Some(encrypted_line)
}

// Function to attempt decryption
fn attempt_decryption(line: &str) -> Option<String> {
    // Check if line contains FiSH encrypted data
    if !line.contains(":+FiSH ") {
        return None;
    }
    
    // CRITICAL: Do NOT decrypt key exchange messages!
    // X25519_INIT and X25519_FINISH must pass through unchanged so mIRC can handle them
    if line.contains("X25519_INIT") || line.contains("X25519_FINISH") || line.contains("FiSH11-PubKey:") {
        log::debug!("Engine: ignoring key exchange message (X25519_INIT/FINISH)");
        return None;
    }
    
    log::debug!("Engine: attempting to decrypt line: {}", line);
    
    // Parse IRC line format: ":nick!user@host PRIVMSG target :+FiSH <data>"
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        log::warn!("Engine: malformed IRC line (not enough parts): {}", line);
        return None;
    }
    
    // Extract sender nickname (remove : prefix and everything after !)
    let sender_raw = parts[0].trim_start_matches(':');
    let sender = if let Some(pos) = sender_raw.find('!') {
        &sender_raw[..pos]
    } else {
        sender_raw
    };
    
    // Find the encrypted data after ":+FiSH "
    let fish_marker = ":+FiSH ";
    let fish_start = match line.find(fish_marker) {
        Some(pos) => pos + fish_marker.len(),
        None => {
            log::warn!("Engine: FiSH marker found but position parse failed");
            return None;
        }
    };
    let encrypted_data = line[fish_start..].trim();
    
    log::debug!("Engine: sender={}, encrypted_data_len={}", sender, encrypted_data.len());
    
    // Try to get the decryption key
    let key = match crate::config::get_key_default(sender) {
        Ok(k) => k,
        Err(e) => {
            log::warn!("Engine: no key found for sender '{}': {}", sender, e);
            return None;
        }
    };
    
    let key_array: &[u8; 32] = match key.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => {
            log::error!("Engine: invalid key length for sender '{}'", sender);
            return None;
        }
    };
    
    // Decrypt the message
    let decrypted = match decrypt_message(key_array, encrypted_data) {
        Ok(msg) => msg,
        Err(e) => {
            log::error!("Engine: decryption failed for sender '{}': {}", sender, e);
            return None;
        }
    };
    
    log::info!("Engine: successfully decrypted message from '{}'", sender);
    
    // Reconstruct the IRC line with decrypted plaintext
    // Format: ":nick!user@host PRIVMSG target :decrypted_message\r\n"
    // CRITICAL: IRC protocol requires \r\n at the end of each line!
    let prefix_end = line.find(" PRIVMSG ").unwrap_or(0);
    let target_start = prefix_end + 9; // Length of " PRIVMSG "
    let target_end = line[target_start..].find(' ').map(|p| target_start + p).unwrap_or(line.len());
    
    let reconstructed = format!(
        "{} PRIVMSG {} :{}\r\n",
        &line[..prefix_end],
        &line[target_start..target_end],
        decrypted
    );
    
    Some(reconstructed)
}

type RegisterEngineFn = extern "C" fn(*const FishInjectEngine) -> i32;

pub fn register_engine() {
    info!("Attempting to register FiSH_11 engine with injector...");
    unsafe {
        let inject_dll_name = CString::new("fish_11_inject.dll").unwrap();
        let h_module: HMODULE = GetModuleHandleA(inject_dll_name.as_ptr());

        if h_module.is_null() {
            warn!("fish_11_inject.dll not found in process. Engine not registered.");
            return;
        }

        let register_fn_name = CString::new("RegisterEngine").unwrap();
        let register_fn: FARPROC = GetProcAddress(h_module, register_fn_name.as_ptr());

        if register_fn.is_null() {
            error!("RegisterEngine function not found in fish_11_inject.dll.");
            return;
        }

        let register_engine_fn: RegisterEngineFn = std::mem::transmute(register_fn);
        let result = register_engine_fn(&FISH_INJECT_ENGINE);

        if result == 0 {
            info!("Successfully registered FiSH_11 engine.");
        } else {
            error!("Failed to register FiSH_11 engine. Error code: {}", result);
        }
    }
}
