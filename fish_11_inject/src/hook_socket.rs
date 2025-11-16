//! This module contains the hooks for Winsock functions
//! It includes the hooks for recv, send, connect, and closesocket

use std::ffi::c_int;
use std::sync::{Arc, Mutex as StdMutex};

use log::{debug, error, info, trace, warn};
use retour::GenericDetour;
use sha2::{Digest, Sha256};
use winapi::shared::ws2def::SOCKADDR;
use winapi::um::winsock2::{SOCKET, SOCKET_ERROR, WSAEINTR};
use fish_11_core::globals::{
    CMD_JOIN, CMD_NOTICE, CMD_PRIVMSG, ENCRYPTION_PREFIX_FISH, ENCRYPTION_PREFIX_OK,
    KEY_EXCHANGE_INIT, KEY_EXCHANGE_PUBKEY,
};
use crate::hook_ssl::{SOCKET_TO_SSL, SSL_TO_SOCKET};
use crate::socket_info::SocketState;
use crate::{ACTIVE_SOCKETS, DISCARDED_SOCKETS, ENGINES, InjectEngines, SocketInfo};

// Type definitions for Winsock functions and ensure "system" ABI (stdcall) for function types
pub type RecvFn = unsafe extern "system" fn(SOCKET, *mut i8, c_int, c_int) -> c_int;
pub type SendFn = unsafe extern "system" fn(SOCKET, *const i8, c_int, c_int) -> c_int;
pub type ConnectFn = unsafe extern "system" fn(SOCKET, *const SOCKADDR, c_int) -> c_int;
pub type ClosesocketFn = unsafe extern "system" fn(SOCKET) -> c_int;

// Thread-safe static variables for function hooks
pub static RECV_HOOK: StdMutex<Option<GenericDetour<RecvFn>>> = StdMutex::new(None);
pub static SEND_HOOK: StdMutex<Option<GenericDetour<SendFn>>> = StdMutex::new(None);
pub static CONNECT_HOOK: StdMutex<Option<GenericDetour<ConnectFn>>> = StdMutex::new(None);
pub static CLOSESOCKET_HOOK: StdMutex<Option<GenericDetour<ClosesocketFn>>> = StdMutex::new(None);

// Maximum number of bytes to preview in debug logs
const MAXIMUM_PREVIEW_SIZE: usize = 64;
const TRACE_PREVIEW_SIZE: usize = 16;

/// Hook implementation for recv
pub unsafe extern "system" fn hooked_recv(
    s: SOCKET,
    buf: *mut i8,
    len: c_int,
    flags: c_int,
) -> c_int {
    info!("* hooked_recv() called for socket {}", s);

    let socket_info = get_or_create_socket(s as u32, true);

    if socket_info.is_ssl() {
        // For SSL sockets, skip processing here; SSL_read will handle it.
        let binding = RECV_HOOK.lock().unwrap();
        let original = binding.as_ref().unwrap();
        return original.call(s, buf, len, flags);
    }

    let binding = RECV_HOOK.lock().unwrap();
    let original = binding.as_ref().unwrap();
    let bytes_received = original.call(s, buf, len, flags);

    if bytes_received > 0 {
        let data_slice = std::slice::from_raw_parts(buf as *mut u8, bytes_received as usize); // Write raw data to buffer and process through engines

        #[cfg(debug_assertions)]
        {
            // Detailed debug logging for received socket data
            debug!("[RECV DEBUG] socket {}: received {} bytes from recv()", s, bytes_received);

            // Log hex preview of first 64 bytes
            let preview_len = std::cmp::min(MAXIMUM_PREVIEW_SIZE, data_slice.len());

            debug!(
                "[RECV DEBUG] socket {}: hex preview (first {} bytes): {:02X?}",
                s,
                preview_len,
                &data_slice[..preview_len]
            );

            // Try to parse as UTF-8 and log sanitized version
            if let Ok(text) = std::str::from_utf8(data_slice) {
                // Check for network name in server greeting
                if text.contains(" 005 ") {
                    if let Some(network_part) =
                        text.split_whitespace().find(|s| s.starts_with("NETWORK="))
                    {
                        let network_name = network_part.trim_start_matches("NETWORK=");
                        let mut network_name_guard: parking_lot::lock_api::RwLockWriteGuard<
                            '_,
                            parking_lot::RawRwLock,
                            Option<String>,
                        > = socket_info.network_name.write();
                        *network_name_guard = Some(network_name.to_string());
                        info!("Socket {}: detected network name: {}", s, network_name);
                    }
                }

                let sanitized: String = text
                    .chars()
                    .map(|c| {
                        if c.is_control() && c != '\r' && c != '\n' && c != '\t' { '.' } else { c }
                    })
                    .collect();
                debug!("[RECV DEBUG] socket {}: UTF-8 content (sanitized): {:?}", s, sanitized);

                // Check for IRC protocol markers
                if text.contains(CMD_PRIVMSG) || text.contains(CMD_NOTICE) || text.contains(CMD_JOIN) {
                    debug!("[RECV DEBUG] socket {}: detected IRC protocol command", s);
                }

                // Check for FiSH key exchange markers
                if text.contains(KEY_EXCHANGE_INIT) || text.contains(KEY_EXCHANGE_PUBKEY) {
                    debug!("[RECV DEBUG] socket {}: detected FiSH key exchange data", s);
                }
            } else {
                debug!("[RECV DEBUG] socket {}: non-UTF8 binary data", s);
            }
        }

        socket_info.write_received_data(data_slice);
        if let Err(e) = socket_info.process_received_lines() {
            error!("Error processing received lines: {:?}", e);
        }

        // Read processed data back into mIRC's buffer.
        // This is the critical step where decrypted data replaces the original encrypted data.
        let processed_buffer = socket_info.get_processed_buffer();
        let bytes_to_copy = std::cmp::min(len as usize, processed_buffer.len());

        if bytes_to_copy > 0 {
            let target_buf = std::slice::from_raw_parts_mut(buf as *mut u8, bytes_to_copy);
            target_buf.copy_from_slice(&processed_buffer[..bytes_to_copy]);

            #[cfg(debug_assertions)]
            {
                debug!(
                    "[RECV DEBUG] socket {}: returning {} bytes to mIRC (processed buffer had {} bytes)",
                    s,
                    bytes_to_copy,
                    processed_buffer.len()
                );

                // Log what we're actually returning
                if let Ok(text) = std::str::from_utf8(&processed_buffer[..bytes_to_copy]) {
                    let sanitized: String = text
                        .chars()
                        .map(|c| {
                            if c.is_control() && c != '\r' && c != '\n' && c != '\t' {
                                '.'
                            } else {
                                c
                            }
                        })
                        .collect();
                    debug!("[RECV DEBUG] socket {}: returning to mIRC: {:?}", s, sanitized);
                } else {
                    debug!(
                        "[RECV DEBUG] socket {}: returning binary data (first 64 bytes): {:02X?}",
                        s,
                        &processed_buffer[..std::cmp::min(MAXIMUM_PREVIEW_SIZE, bytes_to_copy)]
                    );
                }
            }
        }

        // After reading, clear the processed buffer for the next round.
        socket_info.clear_processed_buffer();

        return bytes_to_copy as c_int;
    }

    bytes_received
}

/// Hook implementation for send
pub unsafe extern "system" fn hooked_send(
    s: SOCKET,
    buf: *const i8,
    len: c_int,
    flags: c_int,
) -> c_int {
    info!("* hooked_send() called for socket {}", s);

    let socket_info = get_or_create_socket(s as u32, false);
    if socket_info.is_ssl() {
        // For SSL sockets, skip processing here; SSL_write will handle it.
        let hook_guard = SEND_HOOK.lock().unwrap();
        let original = match hook_guard.as_ref() {
            Some(hook) => hook,
            None => {
                error!("Original send function not available!");
                return -1;
            }
        };
        return original.call(s, buf, len, flags);
    }

    let data_slice = std::slice::from_raw_parts(buf as *const u8, len as usize);

    #[cfg(debug_assertions)]
    {
        // Detailed debug logging for outgoing socket data
        debug!("[SEND DEBUG] socket {}: sending {} bytes via send()", s, len);

        // Log hex preview of first 64 bytes
        let preview_len = std::cmp::min(MAXIMUM_PREVIEW_SIZE, data_slice.len());

        debug!(
            "[SEND DEBUG] socket {}: hex preview (first {} bytes): {:02X?}",
            s,
            preview_len,
            &data_slice[..preview_len]
        );

        // Try to parse as UTF-8 and log sanitized version
        if let Ok(text) = std::str::from_utf8(data_slice) {
            let sanitized: String = text
                .chars()
                .map(
                    |c| if c.is_control() && c != '\r' && c != '\n' && c != '\t' { '.' } else { c },
                )
                .collect();
            debug!("[SEND DEBUG] Socket {}: UTF-8 content (sanitized): {:?}", s, sanitized);

            // Check for IRC protocol markers
            if text.contains(CMD_PRIVMSG ) || text.contains(CMD_NOTICE) || text.contains(CMD_JOIN) {
                debug!("[SEND DEBUG] socket {}: detected IRC protocol command", s);
            }

            // Check for FiSH key exchange markers
            if text.contains("X25519_INIT") || text.contains("FiSH11-PubKey:") {
                debug!("[SEND DEBUG] socket {}: detected FiSH key exchange data", s);
            }

            // Check for encrypted message markers
            if text.contains("+FiSH ") || text.contains("+FiSH ") || text.contains("mcps ") {
                debug!("[SEND DEBUG] socket {}: detected FiSH encrypted message", s);
            }
        } else {
            debug!("[SEND DEBUG] socket {}: non-UTF8 binary data", s);
        }
    }

    trace!(
        "Socket {}: [SEND HOOK] full outgoing buffer ({} bytes): {:02X?}",
        s,
        data_slice.len(),
        data_slice
    );
    if let Ok(data_str) = std::str::from_utf8(data_slice) {
        trace!("Socket {}: [SEND HOOK] UTF-8: {}", s, data_str.trim_end());
    } else {
        trace!("Socket {}: [SEND HOOK] non-UTF8 data", s);
    }
    if data_slice.len() > 128 {
        let mut hasher = Sha256::new();
        hasher.update(data_slice);
        let hash = hasher.finalize();
        trace!(
            "Socket {}: [SEND HOOK] large buffer: len={} SHA256={:x} preview={:02X?}",
            s,
            data_slice.len(),
            hash,
            &data_slice[..32.min(data_slice.len())]
        );
    }

    // Check first packet for protocol detection
    let stats = socket_info.stats.lock();
    if stats.bytes_sent == 0 && socket_info.get_state() == SocketState::Initializing {
        drop(stats); // Release the lock before protocol detection

        if SocketInfo::is_initial_irc_command(data_slice) {
            socket_info.set_state(SocketState::IrcIdentified);
            debug!("Socket {}: identified as IRC connection", s);

            if let Ok(utf8_str) = std::str::from_utf8(data_slice) {
                trace!("Socket {}: sending initial IRC data: {}", s, utf8_str.trim());
            }
        } else if SocketInfo::is_tls_handshake_packet(data_slice) {
            socket_info.set_ssl(true);
            socket_info.set_state(SocketState::TlsHandshake);
            debug!("Socket {}: identified as TLS handshake", s);
            trace!(
                "Socket {}: sending TLS handshake [first 16 bytes]: {:?}",
                s,
                &data_slice[..std::cmp::min(TRACE_PREVIEW_SIZE, data_slice.len())]
            );
        } else {
            debug!("Socket {}: protocol not identified as IRC or TLS", s);
            trace!(
                "Socket {}: unknown protocol [first 16 bytes]: {:?}",
                s,
                &data_slice[..std::cmp::min(TRACE_PREVIEW_SIZE, data_slice.len())]
            );
        }
    } else {
        drop(stats); // Release the lock if we didn't use protocol detection
    } // Process the data through socket_info
    if let Err(e) = socket_info.on_sending(data_slice) {
        error!("Error processing outgoing data: {:?}", e);
    }

    // Log encrypted/plaintext data being sent
    if socket_info.is_ssl() {
        trace!(
            "Socket {}: [SSL OUT] encrypted packet ({} bytes): {:02X?}",
            s,
            data_slice.len(),
            data_slice
        );
    } else {
        trace!(
            "Socket {}: [RAW OUT] plaintext packet ({} bytes): {:02X?}",
            s,
            data_slice.len(),
            data_slice
        );
    }

    // Call the original function
    let result = {
        let hook_guard = SEND_HOOK.lock().unwrap();
        let original = match hook_guard.as_ref() {
            Some(hook) => hook,
            None => {
                error!("Original send function not available !");
                return -1;
            }
        };
        original.call(s, buf, len, flags)
    };

    // Return the result from the original function
    result
}

/// Hook implementation for connect
pub unsafe extern "system" fn hooked_connect(
    s: SOCKET,
    name: *const SOCKADDR,
    namelen: c_int,
) -> c_int {
    info!("* hooked_connect() called for socket {}", s);
    // Get or create socket info
    let _socket_info = get_or_create_socket(s as u32, true);

    // Call original
    let binding = CONNECT_HOOK.lock().unwrap();
    let original = binding.as_ref().unwrap();
    let result = original.call(s, name, namelen);

    // Process result
    let socket_info = get_or_create_socket(s as u32, false);

    if result == 0 {
        // Connection successful
        debug!("Socket {}: connection established", s);
        socket_info.set_state(SocketState::Connected);

        // Check if this is likely to be a TLS connection (e.g., port 6697)
        //
        // TODO : add logic here to determine if the connection is likely SSL/TLS
        //
        // EG. : by checking the port number from the SOCKADDR structure
    } else if result == SOCKET_ERROR {
        // Connection failed
        let error = winapi::um::winsock2::WSAGetLastError();
        if error != WSAEINTR {
            // Not interrupted
            debug!("Socket {}: connection failed with error {}", s, error);
            socket_info.set_state(SocketState::Closed);
        }
    }

    result
}

/// Hook implementation for closesocket
/// Cleans up all socket tracking, notifies engines, and removes any SSL associations as well.
///
/// # Safety
/// - May call C FFI, Win32 APIs, and external hooks. Must ensure global state consistency.
pub unsafe extern "system" fn hooked_closesocket(s: SOCKET) -> c_int {
    info!("* hooked_closesocket() called for socket {}", s);
    let socket_id = s as u32;

    // Notify engines about the closure
    {
        let active_sockets = match ACTIVE_SOCKETS.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("ACTIVE_SOCKETS mutex poisoned in hooked_closesocket()");
                poisoned.into_inner()
            }
        };
        if let Some(socket_info) = active_sockets.get(&socket_id) {
            let engines = Arc::clone(&socket_info.engines);
            engines.on_socket_closed(socket_id);
        }
    }

    {
        let mut socket_to_ssl = match SOCKET_TO_SSL.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("SOCKET_TO_SSL mutex poisoned in hooked_closesocket()");
                poisoned.into_inner()
            }
        };

        if let Some(wrapper) = socket_to_ssl.remove(&socket_id) {
            let mut ssl_to_socket = match SSL_TO_SOCKET.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    error!("SSL_TO_SOCKET mutex poisoned in hooked_closesocket()");
                    poisoned.into_inner()
                }
            };
            // Remove the corresponding SSL* to socket mapping as well
            let ssl_ptr = wrapper.ssl as usize;
            if ssl_to_socket.remove(&ssl_ptr).is_some() {
                debug!(
                    "Removed SSL mapping for SSL context {:p} associated with socket {}",
                    wrapper.ssl, socket_id
                );
            }
        }
    }

    {
        let mut active_sockets = match ACTIVE_SOCKETS.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("ACTIVE_SOCKETS mutex poisoned (removal) in hooked_closesocket()");
                poisoned.into_inner()
            }
        };
        if active_sockets.remove(&socket_id).is_some() {
            debug!("Socket {} removed from tracking", socket_id);
        }
    }

    // Call the original closesocket function
    let result = {
        let hook_guard = match CLOSESOCKET_HOOK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("CLOSESOCKET_HOOK mutex poisoned in hooked_closesocket()");
                poisoned.into_inner()
            }
        };
        let original = match hook_guard.as_ref() {
            Some(hook) => hook,
            None => {
                error!("Original closesocket() function not available !");
                return -1;
            }
        };
        original.call(s)
    };

    result
}

/// Get the socket info
pub fn get_or_create_socket(socket_id: u32, _is_ssl: bool) -> Arc<SocketInfo> {
    let mut sockets = ACTIVE_SOCKETS.lock().unwrap();

    if let Some(socket_info) = sockets.get(&socket_id) {
        socket_info.clone()
    } else {
        // Create engines if needed
        let engines = {
            let mut engines_guard = ENGINES.lock().unwrap();
            if engines_guard.is_none() {
                *engines_guard = Some(Arc::new(InjectEngines::new()));
            }
            engines_guard.as_ref().unwrap().clone()
        };

        // Create new socket info
        let socket_info = Arc::new(SocketInfo::new(socket_id, engines));
        sockets.insert(socket_id, socket_info.clone());
        socket_info
    }
}

/// Get the socket info for a given socket ID
pub(crate) fn _remove_socket(socket_id: u32) {
    let mut sockets = ACTIVE_SOCKETS.lock().unwrap();
    sockets.remove(&socket_id);

    let mut discarded = DISCARDED_SOCKETS.lock().unwrap();
    discarded.push(socket_id);
}

pub fn uninstall_socket_hooks() {
    // Disable and drop hooks in reverse order of installation
    unsafe {
        // Closesocket hook
        if let Some(hook) = CLOSESOCKET_HOOK.lock().unwrap().take() {
            match hook.disable() {
                Ok(_) => info!("  - closesocket() hook disabled"),
                Err(e) => warn!("  - failed to disable closesocket() hook: {:?}", e),
            }
        }

        // Connect hook
        if let Some(hook) = CONNECT_HOOK.lock().unwrap().take() {
            match hook.disable() {
                Ok(_) => info!("  - connect() hook disabled"),
                Err(e) => warn!("  - failed to disable connect() hook: {:?}", e),
            }
        }

        // Send hook
        if let Some(hook) = SEND_HOOK.lock().unwrap().take() {
            match hook.disable() {
                Ok(_) => info!("  - send() hook disabled"),
                Err(e) => warn!("  - failed to disable send() hook: {:?}", e),
            }
        }

        // Recv hook
        if let Some(hook) = RECV_HOOK.lock().unwrap().take() {
            match hook.disable() {
                Ok(_) => info!("  - recv() hook disabled"),
                Err(e) => warn!("  - failed to disable recv() hook: {:?}", e),
            }
        }
    }
}
