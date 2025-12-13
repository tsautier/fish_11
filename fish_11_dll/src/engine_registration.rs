//! engine_registration.rs
//! Handles the registration of the fish_11_dll as an engine within fish_11_inject.

use std::ffi::{CString, c_char};
use std::ptr;

use winapi::shared::minwindef::{FARPROC, HMODULE};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};

use crate::config::settings::get_encryption_prefix;
use crate::crypto::{decrypt_message, encrypt_message};
use crate::{log_debug, log_error, log_info, log_warn};

type GetNetworkNameFn = unsafe extern "C" fn(u32) -> *mut c_char;
static mut GET_NETWORK_NAME_FN: Option<GetNetworkNameFn> = None;

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
    pub get_network_name: unsafe extern "C" fn(u32) -> *mut c_char,
}

// SAFETY: FishInjectEngine contains raw pointers but is used for FFI with static data
unsafe impl Sync for FishInjectEngine {}

// Real implementation for get_network_name (calls fish_inject's GetNetworkName)
unsafe extern "C" fn get_network_name_impl(socket: u32) -> *mut c_char {
    if let Some(get_network_name_fn) = GET_NETWORK_NAME_FN {
        return get_network_name_fn(socket);
    }
    ptr::null_mut()
}

// Callback for outgoing messages (encryption)
unsafe extern "C" fn on_outgoing(socket: u32, line: *const c_char, _len: usize) -> *mut c_char {
    if line.is_null() {
        return ptr::null_mut();
    }

    // CRITICAL: use CStr::from_ptr (borrow) NOT CString::from_raw (take ownership)
    //
    // The caller (inject DLL) still owns this pointer!
    let c_str = match std::ffi::CStr::from_ptr(line).to_str() {
        Ok(s) => s,
        Err(e) => {
            log_error!("Invalid UTF-8 in outgoing line: {}", e);
            return ptr::null_mut();
        }
    };

    // CRITICAL: update the global current network before processing
    //
    // This ensures encryption uses the correct network context
    let network_name = get_network_name_from_inject(socket);
    if let Some(ref net) = network_name {
        crate::set_current_network(net);
    }

    if let Some(encrypted) = attempt_encryption(c_str, network_name.as_deref()) {
        match CString::new(encrypted) {
            Ok(s) => return s.into_raw(),
            Err(e) => {
                log_error!("Failed to create CString for encrypted data: {}", e);
                return ptr::null_mut();
            }
        }
    }
    ptr::null_mut()
}

// Callback for incoming messages (decryption)
unsafe extern "C" fn on_incoming(socket: u32, line: *const c_char, _len: usize) -> *mut c_char {
    if line.is_null() {
        return ptr::null_mut();
    }

    // CRITICAL: use CStr::from_ptr (borrow) NOT CString::from_raw (take ownership)
    //
    // The caller (inject DLL) still owns this pointer!
    let c_str = match std::ffi::CStr::from_ptr(line).to_str() {
        Ok(s) => s,
        Err(e) => {
            log_error!("Invalid UTF-8 in incoming line: {}", e);
            return ptr::null_mut();
        }
    };

    // CRITICAL: update the global current network before processing
    //
    // This ensures that any DLL functions called (like set_key during key exchange)
    // will use the correct network name for this socket
    let network_name = get_network_name_from_inject(socket);
    if let Some(ref net) = network_name {
        crate::set_current_network(net);
        log_debug!("Engine: set current network to '{}' for socket {}", net, socket);
    }

    if let Some(decrypted) = attempt_decryption(c_str, network_name.as_deref()) {
        match CString::new(decrypted) {
            Ok(s) => return s.into_raw(),
            Err(e) => {
                log_error!("Failed to create CString for decrypted data: {}", e);
                return ptr::null_mut();
            }
        }
    }
    ptr::null_mut()
}

// Placeholder for socket close event
unsafe extern "C" fn on_close(_socket: u32) {
    // No special handling needed on socket close for now
    // TODO : Implement any necessary cleanup if needed in the future
}

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
    get_network_name: get_network_name_impl,
};

// Function to attempt encryption
fn attempt_encryption(line: &str, network_name: Option<&str>) -> Option<String> {
    // Only encrypt outgoing PRIVMSG/NOTICE/TOPIC commands
    if !line.contains(" PRIVMSG ") && !line.contains(" NOTICE ") && !line.contains(" TOPIC ") {
        return None;
    }

    log_debug!("Engine: attempting to encrypt outgoing line");

    // Parse the line to extract target and message
    // Format expected: "PRIVMSG target :message" or ":prefix PRIVMSG target :message"
    let parts: Vec<&str> = line.split(" :").collect();

    if parts.len() < 2 {
        log_warn!("Engine: malformed outgoing line (no message part)");
        return None;
    }

    // Get the command part (before the first " :")
    let cmd_part = parts[0];
    let message = parts[1..].join(" :");

    // Extract target from command part
    // Could be "PRIVMSG #channel" or ":prefix PRIVMSG #channel"
    let (target, is_topic) = if let Some(privmsg_pos) = cmd_part.find(" PRIVMSG ") {
        (cmd_part[privmsg_pos + 9..].trim(), false)
    } else if let Some(notice_pos) = cmd_part.find(" NOTICE ") {
        (cmd_part[notice_pos + 8..].trim(), false)
    } else if let Some(topic_pos) = cmd_part.find(" TOPIC ") {
        (cmd_part[topic_pos + 7..].trim(), true)
    } else {
        log_warn!("Engine: could not extract target from command part");
        return None;
    };

    log_debug!("Engine: target={}, message_len={}", target, message.len());

    // Normalize target to strip STATUSMSG prefixes (@#chan, +#chan, etc.)
    let target = crate::utils::normalize_target(target);

    // For topics, we need to use the channel key but NOT advance the ratchet (topics are special)
    // For channels (#, &) in regular messages, we handle encryption with ratchet advancement (like fish11_encryptmsg.rs)
    // For private messages, we use standard key lookup
    let encrypted = if is_topic {
        // Handle topic encryption using the channel key but without ratchet advancement
        log_debug!("Engine: attempting topic encryption for '{}'", target);

        // First try to get a channel key (either manual or ratchet-based)
        let key = match crate::config::get_channel_key_with_fallback(target) {
            Ok(k) => k.to_vec(), // Convert to vec for compatibility with existing code
            Err(_) => {
                // If no channel key exists, try the regular key lookup (for backward compatibility)
                match crate::config::get_key(target, network_name.as_deref()) {
                    Ok(k) => k,
                    Err(_) => {
                        // No key = no encryption, pass through
                        log_debug!(
                            "Engine: no key for topic on channel '{}' on network '{:?}', not encrypting",
                            target,
                            network_name
                        );
                        return None;
                    }
                }
            }
        };

        let key_array: &[u8; 32] = match key.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => {
                log_error!("Engine: invalid key length for topic on channel '{}'", target);
                return None;
            }
        };

        // Encrypt the message with the channel name as Associated Data (to prevent cross-channel replay)
        let encrypted =
            match encrypt_message(key_array, &message, Some(target), Some(target.as_bytes())) {
                Ok(enc) => enc,
                Err(e) => {
                    log_error!("Engine: topic encryption failed for channel '{}': {}", target, e);
                    return None;
                }
            };

        encrypted
    } else if target.starts_with('#') || target.starts_with('&') {
        log_debug!("Engine: attempting channel message encryption for '{}'", target);

        // For channels, first check if we have a manual key. If so, use it for simple encryption (no ratchet)
        // If not, use the ratchet state (handles FCEP-1 encryption with forward secrecy)
        if crate::config::has_channel_key(target) {
            // Use the channel key (manual or ratchet-based) but without ratchet advancement
            // This is for when we want to use a fixed key for a channel without forward secrecy
            match crate::config::get_channel_key_with_fallback(target) {
                Ok(key) => {
                    // Encrypt with the fixed key, using the channel name as Associated Data.
                    match encrypt_message(&key, &message, Some(target), Some(target.as_bytes())) {
                        Ok(encrypted_b64) => encrypted_b64,
                        Err(e) => {
                            log_error!(
                                "Engine: channel encryption failed for '{}' (manual key): {}",
                                target,
                                e
                            );
                            return None;
                        }
                    }
                }
                Err(e) => {
                    log_error!("Engine: failed to get channel key for '{}': {}", target, e);
                    return None;
                }
            }
        } else {
            // Use ratchet-based encryption (FCEP-1 with forward secrecy)
            match crate::config::with_ratchet_state_mut(target, |state| {
                let current_key = state.current_key;

                // Encrypt with the current key, using the channel name as Associated Data.
                let encrypted_b64 =
                    encrypt_message(&current_key, &message, Some(target), Some(target.as_bytes()))
                        .map_err(crate::unified_error::DllError::from)?;

                // Extract the nonce from the encrypted payload to derive the next key.
                let encrypted_bytes = crate::utils::base64_decode(&encrypted_b64)
                    .map_err(crate::unified_error::DllError::from)?;
                if encrypted_bytes.len() < 12 {
                    return Err(crate::unified_error::DllError::EncryptionFailed {
                        context: "payload validation".to_string(),
                        cause: "Encrypted payload too short to contain a nonce".to_string(),
                    });
                }
                let nonce: [u8; 12] = encrypted_bytes[..12].try_into().map_err(|_| {
                    crate::unified_error::DllError::EncryptionFailed {
                        context: "nonce extraction".to_string(),
                        cause: "Could not convert slice to 12-byte nonce array".to_string(),
                    }
                })?;

                // Advance the ratchet to the next key.
                let next_key = crate::crypto::advance_ratchet_key(&current_key, &nonce, target)?;
                state.advance(next_key);

                Ok(encrypted_b64)
            }) {
                Ok(encrypted_b64) => encrypted_b64,
                Err(e) => {
                    log_error!("Engine: channel encryption failed for '{}': {}", target, e);
                    return None;
                }
            }
        }
    } else {
        // For private messages, use standard key lookup
        log_debug!("Engine: attempting private message encryption for '{}'", target);

        let key = match crate::config::get_key(target, network_name.as_deref()) {
            Ok(k) => k,
            Err(_) => {
                // No key = no encryption, pass through
                log_debug!(
                    "Engine: no key for target '{}' on network '{:?}', not encrypting",
                    target,
                    network_name
                );
                return None;
            }
        };

        let key_array: &[u8; 32] = match key.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => {
                log_error!("Engine: invalid key length for target '{}'", target);
                return None;
            }
        };

        // Encrypt the message (no AD for private messages).
        let encrypted = match encrypt_message(key_array, &message, Some(target), None) {
            Ok(enc) => enc,
            Err(e) => {
                log_error!("Engine: encryption failed for target '{}': {}", target, e);
                return None;
            }
        };

        encrypted
    };

    let msg_type = if is_topic {
        "topic"
    } else if target.starts_with('#') || target.starts_with('&') {
        "channel message"
    } else {
        "private message"
    };
    log_info!("Engine: successfully encrypted {} to '{}'", msg_type, target);

    // Get the encryption prefix from config (defaults to "+FiSH")
    let encryption_prefix = get_encryption_prefix().unwrap_or_else(|_| "+FiSH".to_string());

    // Reconstruct line with encrypted data
    // Keep prefix if present, replace message with configurable prefix + encrypted data or "+FCEP_TOPIC+ <encrypted>"
    // Add \r\n for IRC protocol compliance
    let prefix = if is_topic { "+FCEP_TOPIC+" } else { encryption_prefix.as_str() };
    let encrypted_line = format!("{} :{} {}\r\n", cmd_part, prefix, encrypted);

    Some(encrypted_line)
}

// Function to attempt decryption
fn attempt_decryption(line: &str, network: Option<&str>) -> Option<String> {
    log_debug!("Engine: attempt_decryption called for line: {}, network: {:?}", line, network);

    // Handle RPL_TOPIC (332) for encrypted channel topics (when joining a channel)
    if line.contains(" 332 ") && line.contains(":+FCEP_TOPIC+") {
        log_info!("Engine: processing encrypted RPL_TOPIC (332) for channel topic");

        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            log_warn!("Engine: malformed encrypted topic line (not enough parts): {}", line);
            return None;
        }

        let key_identifier = parts[3]; // Channel name is the key identifier
        log_debug!(
            "Engine: RPL_TOPIC detected - channel: {}, parts count: {}",
            key_identifier,
            parts.len()
        );

        let topic_marker = ":+FCEP_TOPIC+";
        let topic_start = match line.find(topic_marker) {
            Some(pos) => pos + topic_marker.len(),
            None => {
                log_warn!("Engine: FCEP_TOPIC marker not found in topic line: {}", line);
                return None;
            }
        };
        let encrypted_data = line[topic_start..].trim();

        log_debug!(
            "Engine: topic_key_identifier={}, encrypted_data_len={}, encrypted_data='{}'",
            key_identifier,
            encrypted_data.len(),
            encrypted_data
        );

        // Try to get a channel key (either manual or ratchet-based) first
        let key = match crate::config::get_channel_key_with_fallback(key_identifier) {
            Ok(k) => {
                log_debug!(
                    "Engine: found channel key for topic channel '{}', length: {}",
                    key_identifier,
                    k.len()
                );
                k.to_vec() // Convert to vec for compatibility with existing code
            }
            Err(_) => {
                // If no channel key exists, try the regular key lookup (for backward compatibility)
                match crate::config::get_key(key_identifier, network) {
                    Ok(k) => {
                        log_debug!(
                            "Engine: found regular key for topic channel '{}', length: {}",
                            key_identifier,
                            k.len()
                        );
                        k
                    }
                    Err(e) => {
                        log_warn!(
                            "Engine: no key found for topic channel '{}': {}",
                            key_identifier,
                            e
                        );
                        return None;
                    }
                }
            }
        };

        let key_array: &[u8; 32] = match key.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => {
                log_error!("Engine: invalid key length for topic channel '{}'", key_identifier);
                return None;
            }
        };

        let decrypted =
            match decrypt_message(key_array, encrypted_data, Some(key_identifier.as_bytes())) {
                Ok(msg) => {
                    log_debug!(
                        "Engine: successfully decrypted topic for channel '{}', length: {}",
                        key_identifier,
                        msg.len()
                    );
                    msg
                }
                Err(e) => {
                    log_error!(
                        "Engine: topic decryption failed for channel '{}': {}",
                        key_identifier,
                        e
                    );
                    return None;
                }
            };

        log_info!("Engine: successfully decrypted topic for channel '{}'", key_identifier);

        let message_part_start = match line.find(" :+FCEP_TOPIC+") {
            Some(pos) => pos,
            None => {
                log_error!("Engine: could not find topic part ' :+FCEP_TOPIC+' in line: {}", line);
                return None;
            }
        };

        let prefix_and_command = &line[..message_part_start];
        let reconstructed = format!("{} :{}\r\n", prefix_and_command, decrypted);
        log_debug!("Engine: reconstructed topic line length: {}", reconstructed.len());
        return Some(reconstructed);
    }

    // Handle incoming TOPIC notifications (when someone changes the topic)
    // Format: :nick!user@host TOPIC #channel :+FCEP_TOPIC+ encrypted_data
    if line.starts_with(':') && line.contains(" TOPIC ") && line.contains(":+FCEP_TOPIC+") {
        log_info!("Engine: processing encrypted incoming TOPIC notification");
        log_debug!("Engine: detected encrypted incoming TOPIC notification: {}", line);

        // Find where the actual topic data begins
        let topic_marker = ":+FCEP_TOPIC+";
        let topic_start = match line.find(topic_marker) {
            Some(pos) => pos + topic_marker.len(),
            None => {
                log_warn!("Engine: FCEP_TOPIC marker not found in TOPIC notification: {}", line);
                return None;
            }
        };
        let encrypted_data = line[topic_start..].trim();

        // Extract channel from the line: find after the " TOPIC " part
        let topic_pos = match line.find(" TOPIC ") {
            Some(pos) => pos,
            None => {
                log_warn!("Engine: could not find TOPIC command in line: {}", line);
                return None;
            }
        };

        // The channel follows the " TOPIC " part
        let after_topic_cmd = &line[topic_pos + 7..]; // " TOPIC " is 7 chars
        let parts: Vec<&str> = after_topic_cmd.split_whitespace().collect();
        if parts.is_empty() {
            log_warn!("Engine: no channel found after TOPIC command in line: {}", line);
            return None;
        }
        let key_identifier = parts[0]; // First token after " TOPIC " is the channel

        log_debug!(
            "Engine: incoming_topic_key_identifier={}, encrypted_data_len={}, encrypted_data='{}'",
            key_identifier,
            encrypted_data.len(),
            encrypted_data
        );

        // Try to get a channel key (either manual or ratchet-based) first
        let key = match crate::config::get_channel_key_with_fallback(key_identifier) {
            Ok(k) => {
                log_debug!(
                    "Engine: found channel key for incoming topic channel '{}', length: {}",
                    key_identifier,
                    k.len()
                );
                k.to_vec() // Convert to vec for compatibility with existing code
            }
            Err(_) => {
                // If no channel key exists, try the regular key lookup (for backward compatibility)
                match crate::config::get_key(key_identifier, network) {
                    Ok(k) => {
                        log_debug!(
                            "Engine: found regular key for incoming topic channel '{}', length: {}",
                            key_identifier,
                            k.len()
                        );
                        k
                    }
                    Err(e) => {
                        log_warn!(
                            "Engine: no key found for incoming topic channel '{}': {}",
                            key_identifier,
                            e
                        );
                        return None;
                    }
                }
            }
        };

        let key_array: &[u8; 32] = match key.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => {
                log_error!(
                    "Engine: invalid key length for incoming topic channel '{}'",
                    key_identifier
                );
                return None;
            }
        };

        let decrypted = match decrypt_message(
            key_array,
            encrypted_data,
            Some(key_identifier.as_bytes()),
        ) {
            Ok(msg) => {
                log_debug!(
                    "Engine: successfully decrypted incoming topic for channel '{}', length: {}",
                    key_identifier,
                    msg.len()
                );
                msg
            }
            Err(e) => {
                log_error!(
                    "Engine: incoming topic decryption failed for channel '{}': {}",
                    key_identifier,
                    e
                );
                return None;
            }
        };

        log_info!("Engine: successfully decrypted incoming topic for channel '{}'", key_identifier);

        let message_part_start = match line.find(" :+FCEP_TOPIC+") {
            Some(pos) => pos,
            None => {
                log_error!("Engine: could not find topic part ' :+FCEP_TOPIC+' in line: {}", line);
                return None;
            }
        };

        let prefix_and_command = &line[..message_part_start];
        let reconstructed = format!("{} :{}\r\n", prefix_and_command, decrypted);
        log_debug!("Engine: reconstructed incoming topic line length: {}", reconstructed.len());
        return Some(reconstructed);
    }

    // Get the encryption prefix from config (defaults to "+FiSH")
    let encryption_prefix = get_encryption_prefix().unwrap_or_else(|_| "+FiSH".to_string());

    // Check if line contains FiSH encrypted data with the configured prefix
    let fish_marker = format!(":{}", encryption_prefix);
    if !line.contains(&fish_marker) {
        log_debug!("Engine: line does not contain '{} ', skipping", fish_marker);
        return None;
    }

    // CRITICAL: do NOT decrypt key exchange messages !#@
    // X25519_INIT and X25519_FINISH must pass through unchanged so mIRC can handle them
    if line.contains("X25519_INIT:")
        || line.contains("X25519_FINISH")
    {
        log_debug!("Engine: ignoring key exchange message (X25519_INIT/FINISH)");
        return None;
    }

    log_debug!("Engine: attempting to decrypt line: {}", line);

    // Parse IRC line format: ":nick!user@host PRIVMSG target :+FiSH <data>"
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() < 4 {
        log_warn!("Engine: malformed IRC line (not enough parts): {}", line);
        return None;
    }

    // Extract sender nickname (remove : prefix and everything after !)
    let sender_raw = parts[0].trim_start_matches(':');
    let sender = if let Some(pos) = sender_raw.find('!') { &sender_raw[..pos] } else { sender_raw };

    // Extract target (channel or nickname)
    // Format: ":nick!user@host PRIVMSG target :message"
    let target_raw = parts.get(2).unwrap_or(&"");

    // Normalize target to strip STATUSMSG prefixes (@#chan, +#chan..)
    let target = crate::utils::normalize_target(target_raw);

    // Find the encrypted data after the configured prefix (e.g., ":+FiSH ")
    let fish_marker_search = format!(":{}", encryption_prefix);
    let fish_start = match line.find(&fish_marker_search) {
        Some(pos) => pos + fish_marker_search.len(),
        None => {
            log_warn!("Engine: FiSH11 marker found but position parse failed");
            return None;
        }
    };
    let encrypted_data = line[fish_start..].trim();

    // Determine which identifier to use for key lookup
    // For channels (#, &) : we use the channel name and it's already normalized.
    // For private messages :  we use the sender's nickname
    let key_identifier =
        if target.starts_with('#') || target.starts_with('&') { target } else { sender };

    log_debug!(
        "Engine: sender={}, target={}, key_identifier={}, encrypted_data_len={}",
        sender,
        target,
        key_identifier,
        encrypted_data.len()
    );

    // Try to get the decryption key
    let key = if key_identifier.starts_with('#') || key_identifier.starts_with('&') {
        // For channel messages, try channel key (manual or ratchet-based) first
        match crate::config::get_channel_key_with_fallback(key_identifier) {
            Ok(k) => {
                log_debug!("Engine: using channel key for '{}'", key_identifier);
                k.to_vec() // Convert to vec for compatibility with existing code
            }
            Err(_) => {
                // If no channel key, try the regular key lookup
                match crate::config::get_key(key_identifier, network) {
                    Ok(k) => {
                        log_debug!("Engine: using regular key for '{}'", key_identifier);
                        k
                    }
                    Err(e) => {
                        log_warn!("Engine: no key found for '{}': {}", key_identifier, e);
                        return None;
                    }
                }
            }
        }
    } else {
        // For private messages, use regular key lookup
        match crate::config::get_key(key_identifier, network) {
            Ok(k) => {
                log_debug!("Engine: using private key for '{}'", key_identifier);
                k
            }
            Err(e) => {
                log_warn!("Engine: no key found for '{}': {}", key_identifier, e);
                return None;
            }
        }
    };

    let key_array: &[u8; 32] = match key.as_slice().try_into() {
        Ok(arr) => arr,
        Err(_) => {
            log_error!("Engine: invalid key length for identifier '{}'", key_identifier);
            return None;
        }
    };

    // Decrypt the message
    let decrypted = match decrypt_message(key_array, encrypted_data, None) {
        Ok(msg) => msg,
        Err(e) => {
            log_error!("Engine: decryption failed for sender '{}': {}", sender, e);
            return None;
        }
    };

    log_info!("Engine: successfully decrypted message from '{}'", sender);

    // Reconstruct the IRC line with decrypted plaintext
    // Format: ":nick!user@host COMMAND target :decrypted_message\r\n"
    // CRITICAL: IRC protocol requires \r\n at the end of each line!

    // Find the start of the message part (the configured prefix, e.g., " :+FiSH ...")
    let prefix_search = format!(" :{}", encryption_prefix);
    let message_part_start = match line.find(&prefix_search) {
        Some(pos) => pos,
        None => {
            log_error!("Engine: could not find message part ' {} ' in line", prefix_search);
            return None;
        }
    };

    // The part of the line before the message is the full prefix, command, and target
    let prefix_and_command = &line[..message_part_start];

    let reconstructed = format!("{} :{}\r\n", prefix_and_command, decrypted);

    Some(reconstructed)
}

type RegisterEngineFn = extern "C" fn(*const FishInjectEngine) -> i32;

pub fn register_engine() {
    log_info!("Attempting to register FiSH_11 engine with inject0r...");
    unsafe {
        let inject_dll_name = CString::new("fish_11_inject.dll").unwrap();
        let h_module: HMODULE = GetModuleHandleA(inject_dll_name.as_ptr());

        if h_module.is_null() {
            log_warn!("fish_11_inject.dll not found in process. Engine not registered.");
            return;
        }

        let get_network_name_fn_name = CString::new("GetNetworkName").unwrap();
        let get_network_name_fn: FARPROC =
            GetProcAddress(h_module, get_network_name_fn_name.as_ptr());

        if get_network_name_fn.is_null() {
            log_error!("GetNetworkName function not found in fish_11_inject.dll.");
        } else {
            GET_NETWORK_NAME_FN = Some(std::mem::transmute(get_network_name_fn));
        }

        let register_fn_name = CString::new("RegisterEngine").unwrap();
        let register_fn: FARPROC = GetProcAddress(h_module, register_fn_name.as_ptr());

        if register_fn.is_null() {
            log_error!("RegisterEngine function not found in fish_11_inject.dll.");
            return;
        }

        let register_engine_fn: RegisterEngineFn = std::mem::transmute(register_fn);
        let result = register_engine_fn(&FISH_INJECT_ENGINE);

        if result == 0 {
            log_info!("Successfully registered FiSH_11 engine.");
        } else {
            log_error!("Failed to register FiSH_11 engine. Error code : {}", result);
        }
    }
}

pub fn get_network_name_from_inject(socket_id: u32) -> Option<String> {
    unsafe {
        if let Some(get_network_name_fn) = GET_NETWORK_NAME_FN {
            let c_char_ptr = get_network_name_fn(socket_id);
            if !c_char_ptr.is_null() {
                let c_string = CString::from_raw(c_char_ptr);
                if let Ok(rust_string) = c_string.into_string() {
                    return Some(rust_string);
                }
            }
        }
    }
    None
}
