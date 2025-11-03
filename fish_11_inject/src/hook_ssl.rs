use std::collections::HashMap;
use std::ffi::{CString, c_int, c_void};
use std::sync::Mutex as StdMutex;

use lazy_static::lazy_static;
use log::{debug, error, info, trace, warn};
use retour::GenericDetour;
use winapi::shared::minwindef::FARPROC;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};

use crate::SOCKET;
use crate::helpers_inject::handle_poison;
use crate::hook_socket::get_or_create_socket;
use crate::socket_info::SocketState;
// SSL structure (opaque)
#[repr(C)]
pub struct SSL {
    _private: [u8; 0],
}

pub struct SSLWrapper {
    pub ssl: *mut SSL,
}

// We need to implement Send and Sync unsafely for SSL*
// This is safe because we only access the pointers from within a mutex, ensuring thread-safe access
unsafe impl Send for SSLWrapper {}
unsafe impl Sync for SSLWrapper {}

// Manually implement Send + Sync for SSLWrapper
unsafe impl Send for SSL {}
unsafe impl Sync for SSL {}

// Function types for SSL library functions
pub type SslReadFn = unsafe extern "C" fn(*mut SSL, *mut u8, c_int) -> c_int;
pub type SslWriteFn = unsafe extern "C" fn(*mut SSL, *const u8, c_int) -> c_int;
pub type SslConnectFn = unsafe extern "C" fn(*mut SSL) -> c_int;
pub type SslNewFn = unsafe extern "C" fn(*mut c_void) -> *mut SSL; // SSL_CTX* as void*
pub type SslFreeFn = unsafe extern "C" fn(*mut SSL);
pub type SslGetFdFn = unsafe extern "C" fn(*mut SSL) -> c_int;
pub type SslSetFdFn = unsafe extern "C" fn(*mut SSL, c_int) -> c_int;
pub type SslIsInitFinishedProc = unsafe extern "C" fn(*mut SSL) -> i32;

lazy_static! {
    static ref SSL_IS_INIT_FINISHED: StdMutex<Option<SslIsInitFinishedProc>> = StdMutex::new(None);
}

lazy_static! {
    pub static ref SOCKET_TO_SSL: StdMutex<HashMap<u32, SSLWrapper>> =
        StdMutex::new(HashMap::new());
    pub static ref SSL_TO_SOCKET: StdMutex<HashMap<usize, u32>> = StdMutex::new(HashMap::new());
    pub static ref SSL_READ_HOOK: StdMutex<Option<GenericDetour<SslReadFn>>> = StdMutex::new(None);
    pub static ref SSL_WRITE_HOOK: StdMutex<Option<GenericDetour<SslWriteFn>>> =
        StdMutex::new(None);
    pub static ref SSL_CONNECT_HOOK: StdMutex<Option<GenericDetour<SslConnectFn>>> =
        StdMutex::new(None);
    pub static ref SSL_NEW_HOOK: StdMutex<Option<GenericDetour<SslNewFn>>> = StdMutex::new(None);
    pub static ref SSL_GET_FD: StdMutex<Option<SslGetFdFn>> = StdMutex::new(None);
    pub static ref SSL_FREE_HOOK: StdMutex<Option<GenericDetour<SslFreeFn>>> = StdMutex::new(None);
    pub static ref SSL_HOOKS_INSTALLED: StdMutex<bool> = StdMutex::new(false);
    pub static ref ORIGINAL_SSL_READ: StdMutex<Option<SslReadFn>> = StdMutex::new(None);
    pub static ref ORIGINAL_SSL_WRITE: StdMutex<Option<SslWriteFn>> = StdMutex::new(None);
    pub static ref ORIGINAL_SSL_CONNECT: StdMutex<Option<SslConnectFn>> = StdMutex::new(None);
    pub static ref ORIGINAL_SSL_NEW: StdMutex<Option<SslNewFn>> = StdMutex::new(None);
    pub static ref ORIGINAL_SSL_FREE: StdMutex<Option<SslFreeFn>> = StdMutex::new(None);
}

static SSL_SET_FD_HOOK: StdMutex<Option<GenericDetour<SslSetFdFn>>> = StdMutex::new(None);
static ORIGINAL_SSL_SET_FD: StdMutex<Option<SslSetFdFn>> = StdMutex::new(None);

/// Hook for SSL_set_fd to track which SSL context (SSL*) is associated with which socket (fd).
/// Also marks the socket as SSL-enabled for later checks in send/recv hooks.
///
/// # Safety
/// - Calls FFI pointers (Rust/WinAPI interop)
unsafe extern "C" fn hooked_ssl_set_fd(ssl: *mut SSL, fd: c_int) -> c_int {
    trace!("SSL_set_fd() called with ssl: {:p}, fd: {}", ssl, fd);

    // 1. Call the original function pointer
    //
    let original_fn = {
        let guard = match ORIGINAL_SSL_SET_FD.lock() {
            Ok(g) => g,
            Err(poisoned) => {
                error!("ORIGINAL_SSL_SET_FD mutex poisoned in hooked_ssl_set_fd()");
                poisoned.into_inner()
            }
        };
        *guard
    };

    let result = if let Some(func) = original_fn {
        func(ssl, fd)
    } else {
        error!("Original SSL_set_fd is NULL!");
        return -1;
    };

    // 2. Only proceed with tracking if original call succeeded and pointer valid
    if result > 0 && !ssl.is_null() {
        {
            // Map SSL* to fd
            let mut ssl_to_socket = match SSL_TO_SOCKET.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    error!("SSL_TO_SOCKET mutex poisoned in hooked_ssl_set_fd()");
                    poisoned.into_inner()
                }
            };
            ssl_to_socket.insert(ssl as usize, fd as u32);

            // Map fd to SSL* wrapped as your SSLWrapper
            let mut socket_to_ssl = match SOCKET_TO_SSL.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    error!("SOCKET_TO_SSL mutex poisoned in hooked_ssl_set_fd()");
                    poisoned.into_inner()
                }
            };
            socket_to_ssl.insert(fd as u32, SSLWrapper { ssl });

            trace!("Mapped SSL {:p} to socket {}", ssl, fd);
        }

        // Optionally set a flag in your socket info struct
        let socket_info = get_or_create_socket(fd as u32, true);
        socket_info.set_ssl(true);

        trace!("Socket {} marked as using SSL", fd);
    }

    result
}

/// Convert SSL pointer to a unique identifier for mapping
fn ssl_to_id(ssl: *mut SSL) -> usize {
    ssl as usize
}

/// Attempts to locate a function pointer by name within a set of well-known SSL-related libraries.
///
/// Searches for the function in all currently loaded libraries first (using WinAPI `GetModuleHandleA`),
/// then explicitly attempts to load each library using `LoadLibraryA` if necessary. For each candidate
/// library, checks a set of common function name mangling variants (to handle different calling conventions
/// or OpenSSL DLL builds). Returns the function address (`FARPROC`) on success, or null on error.
///
/// # Safety
/// - This function calls into Windows APIs and uses raw pointers and C FFI.
/// - Callers must ensure the returned `FARPROC` is safely cast and invoked according to the real function's ABI.
///
/// # Features & Corner Cases
/// - Handles multiple OpenSSL naming conventions and DLL versions.
/// - Supports searching both loaded and not-yet-loaded libraries (loads them as needed).
/// - Prints descriptive info when functions are found, and warns if none are found.
/// - Can be expanded with additional function name variants if needed.
///
/// # Concurrency
/// - Not thread safe with respect to library loading/unloading (matches typical FFI expectations).
///
/// # Errors
/// - Returns a NULL pointer (`std::ptr::null_mut()`) if the function is not found.
///
/// # Example
/// ```
/// let proc = find_ssl_function("SSL_read");
/// assert!(!proc.is_null());
/// ```
pub fn find_ssl_function(function_name: &str) -> FARPROC {
    // List of possible SSL library names to check, including common OpenSSL and Windows crypt libs.
    let ssl_lib_names = [
        "libssl-3.dll\0",
        "libssl-1_1.dll\0",
        "libssl-1_1-x64.dll\0",
        "ssleay32.dll\0",
        "libssl.dll\0",
        "crypt32.dll\0",  // Sometimes Windows uses its own crypto
        "schannel.dll\0", // Windows Secure Channel
    ];

    // Add function name variants - OpenSSL may have stdcall/@n or underscore prefixes
    let function_variants = [
        function_name.to_string(),        // "SSL_read"
        format!("{}@4", function_name),   // "SSL_read@4"
        format!("{}@8", function_name),   // "SSL_read@8"
        format!("{}@12", function_name),  // "SSL_read@12"
        format!("_{}@4", function_name),  // "_SSL_read@4"
        format!("_{}@8", function_name),  // "_SSL_read@8"
        format!("_{}@12", function_name), // "_SSL_read@12"
        format!("_{}", function_name),    // "_SSL_read"
    ];
    let func_name_cstr = |name: &str| -> CString {
        CString::new(name).unwrap_or_else(|_| {
            CString::new("invalid").expect("Failed to create fallback function name")
        })
    };

    // First: search already loaded libraries for the function variants
    for lib_name in &ssl_lib_names {
        unsafe {
            let handle = GetModuleHandleA(lib_name.as_ptr() as *const i8);
            if !handle.is_null() {
                for variant in &function_variants {
                    let func_ptr = GetProcAddress(handle, func_name_cstr(variant).as_ptr());
                    if !func_ptr.is_null() {
                        info!(
                            "Found {} ({}) in {}",
                            function_name,
                            variant,
                            String::from_utf8_lossy(
                                lib_name.strip_suffix("\0").unwrap().as_bytes()
                            )
                        );
                        return func_ptr;
                    }
                }
            }
        }
    }

    // Second: try to load each library and repeat the search if not already loaded
    for lib_name in &ssl_lib_names {
        unsafe {
            let handle = winapi::um::libloaderapi::LoadLibraryA(lib_name.as_ptr() as *const i8);
            if !handle.is_null() {
                for variant in &function_variants {
                    let func_ptr = GetProcAddress(handle, func_name_cstr(variant).as_ptr());
                    if !func_ptr.is_null() {
                        info!(
                            "Loaded {} and found {} ({}) in {}",
                            String::from_utf8_lossy(
                                lib_name.strip_suffix("\0").unwrap().as_bytes()
                            ),
                            function_name,
                            variant,
                            String::from_utf8_lossy(
                                lib_name.strip_suffix("\0").unwrap().as_bytes()
                            )
                        );
                        return func_ptr;
                    }
                }
            }
        }
    }

    // Failed: Function not found in any candidate DLL
    warn!("Could not find function {} in any SSL library", function_name);

    std::ptr::null_mut()
}

pub unsafe fn store_ssl_mapping(ssl: *mut SSL, socket: SOCKET) {
    if let Some(fd_fn) = *SSL_GET_FD.lock().unwrap_or_else(handle_poison) {
        let fd = fd_fn(ssl);
        SSL_TO_SOCKET.lock().unwrap().insert(ssl as usize, socket.0 as u32);
        SOCKET_TO_SSL.lock().unwrap().insert(socket.0 as u32, SSLWrapper { ssl });
        debug!("Mapped SSL {:p} to socket {:?} (fd={})", ssl, socket, fd);
    }
}

/// Hook implementation for SSL_read
///
/// # Safety
/// This function is an FFI boundary for an SSL_read call.
/// It:
/// - Retrieves socket context info from the SSL pointer
/// - Forwards to the original SSL_read
/// - After read, checks completion of TLS handshake using SSL_is_init_finished
/// - Processes, logs, and forwards the decrypted data to the socket processing pipeline
///
/// # Issues addressed:
/// - Double-processing: The data is processed twice if bytes_read > 0
/// - Redundant socket_id and get_or_create_socket lookups
/// - State handling and logging order
///
/// Callers must ensure:
/// - buf is valid for writes of up to num bytes
/// - ssl is a valid OpenSSL SSL* pointer
pub unsafe extern "C" fn hooked_ssl_read(ssl: *mut SSL, buf: *mut u8, num: c_int) -> c_int {
    trace!("[HOOK] hooked_ssl_read() called: ssl={:p}, buf={:p}, num={}", ssl, buf, num);
    let ssl_read_guard = SSL_READ_HOOK.lock().unwrap_or_else(handle_poison);
    let original = ssl_read_guard.as_ref().expect("SSL_read hook not initialized");

    // Get socket associated with SSL context
    let socket_id = match get_socket_from_ssl_context(ssl) {
        Some(id) => id,
        None => {
            error!("SSL_read called on unknown SSL context {:p}", ssl);
            return original.call(ssl, buf, num);
        }
    };

    // Call original SSL_read
    let bytes_read = original.call(ssl, buf, num);

    // Log the decrypted data received (first 32 bytes)
    if bytes_read > 0 && !buf.is_null() {
        let data_slice = std::slice::from_raw_parts(buf, bytes_read as usize);
        
        #[cfg(debug_assertions)]
        {
            // Detailed debug logging for decrypted SSL data
            debug!(
                "[SSL_READ DEBUG] Socket {}: received {} bytes from SSL_read",
                socket_id, bytes_read
            );
            
            // Log hex preview of first 64 bytes
            let preview_len = std::cmp::min(64, data_slice.len());
            debug!(
                "[SSL_READ DEBUG] Socket {}: hex preview (first {} bytes): {:02X?}",
                socket_id, preview_len, &data_slice[..preview_len]
            );
            
            // Try to parse as UTF-8 and log sanitized version (replace control chars)
            if let Ok(text) = std::str::from_utf8(data_slice) {
                let sanitized: String = text.chars()
                    .map(|c| if c.is_control() && c != '\r' && c != '\n' && c != '\t' { '.' } else { c })
                    .collect();
                debug!(
                    "[SSL_READ DEBUG] Socket {}: UTF-8 content (sanitized): {:?}",
                    socket_id, sanitized
                );
                
                // Check for IRC protocol markers
                if text.contains("PRIVMSG") || text.contains("NOTICE") || text.contains("JOIN") {
                    debug!("[SSL_READ DEBUG] Socket {}: detected IRC protocol command", socket_id);
                }
                
                // Check for FiSH key exchange markers
                if text.contains("X25519_INIT") || text.contains("FiSH11-PubKey:") {
                    debug!("[SSL_READ DEBUG] Socket {}: detected FiSH key exchange data", socket_id);
                }
            } else {
                debug!(
                    "[SSL_READ DEBUG] Socket {}: non-UTF8 binary data",
                    socket_id
                );
            }
        }
        
        // Human-readable log
        if let Ok(text) = std::str::from_utf8(data_slice) {
            info!(
                "[TLS IN] {}: {} bytes: {}",
                get_or_create_socket(socket_id, true).get_stats(),
                bytes_read,
                text.trim_end()
            );
        } else {
            info!(
                "[TLS IN] {}: {} bytes (non-UTF8): {:02X?}",
                get_or_create_socket(socket_id, true).get_stats(),
                bytes_read,
                &data_slice[..std::cmp::min(32, data_slice.len())]
            );
        }
        // Existing trace log
        trace!(
            "[HOOK] hooked_ssl_read() decrypted data for socket {} ({} bytes): {:02X?}",
            socket_id,
            bytes_read,
            &data_slice[..std::cmp::min(32, data_slice.len())]
        );
    }

    // Check TLS handshake completion
    if let Some(ssl_init_fn) = *SSL_IS_INIT_FINISHED.lock().unwrap_or_else(handle_poison) {
        let handshake_status = ssl_init_fn(ssl);
        debug!("[HANDSHAKE] SSL_is_init_finished({:p}) = {}", ssl, handshake_status);
        if handshake_status != 0 {
            let socket_info = get_or_create_socket(socket_id, true);
            if socket_info.get_state() == SocketState::TlsHandshake {
                debug!(
                    "[HANDSHAKE] Socket {}: state changing TlsHandshake -> Connected",
                    socket_id
                );
                socket_info.set_state(SocketState::Connected);
                debug!("Socket {}: TLS handshake completed via SSL_read()", socket_id);
            }
        }
    }

    if bytes_read <= 0 {
        trace!("SSL_read returned {} for socket {}", bytes_read, socket_id);
        return bytes_read;
    }

    // Process decrypted data through engines
    let socket_info = get_or_create_socket(socket_id, true);
    let data_slice = std::slice::from_raw_parts(buf, bytes_read as usize);

    trace!(
        "Socket {}: [SSL IN] Received {} bytes: {:?}",
        socket_id,
        bytes_read,
        &data_slice[..std::cmp::min(16, data_slice.len())]
    );
    socket_info.write_received_data(data_slice);
    if let Err(e) = socket_info.process_received_lines() {
        error!("Error processing received SSL lines: {:?}", e);
    }

    bytes_read
}

/// Hook implementation for SSL_write to handle plaintext tapping and handshake state.
/// # Safety
/// Uses raw pointers and C FFI. Must ensure buffer and SSL context are valid.
unsafe extern "C" fn hooked_ssl_write(ssl: *mut SSL, buf: *const u8, num: c_int) -> c_int {
    trace!("[HOOK] hooked_ssl_write() called: ssl={:p}, buf={:p}, num={}", ssl, buf, num);
    // Log the plaintext data being sent (first 32 bytes)
    if num > 0 && !buf.is_null() {
        let data_slice = std::slice::from_raw_parts(buf, std::cmp::min(num as usize, 32));
        trace!("[HOOK] hooked_ssl_write() plaintext data ({} bytes): {:02X?}", num, data_slice);
    }
    // Find socket ID associated with this SSL pointer.
    let socket_id = {
        let ssl_to_socket = match SSL_TO_SOCKET.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("SSL_TO_SOCKET mutex poisoned in hooked_ssl_write()");
                poisoned.into_inner()
            }
        };

        match ssl_to_socket.get(&ssl_to_id(ssl)) {
            Some(socket_id) => *socket_id,
            None => {
                trace!("SSL_write(): no socket ID found for SSL {:p}", ssl);
                // Fallback: Call original with no further processing.
                let original_fn: SslWriteFn = {
                    let lock = match ORIGINAL_SSL_WRITE.lock() {
                        Ok(guard) => guard,
                        Err(poisoned) => {
                            error!("ORIGINAL_SSL_WRITE mutex poisoned in hooked_ssl_write()");
                            poisoned.into_inner()
                        }
                    };
                    match *lock {
                        Some(fn_ptr) => fn_ptr,
                        None => {
                            error!("Original SSL_write() function is not available");
                            return -1;
                        }
                    }
                };
                return original_fn(ssl, buf, num);
            }
        }
    };

    trace!("SSL_write: socket {}, {} bytes", socket_id, num);

    // Prepare data slice safely
    let data_slice = std::slice::from_raw_parts(buf, num as usize);

    #[cfg(debug_assertions)]
    {
        // Detailed debug logging for outgoing SSL plaintext
        debug!(
            "[SSL_WRITE DEBUG] Socket {}: sending {} bytes to SSL_write (before encryption)",
            socket_id, num
        );
        
        // Log hex preview of first 64 bytes
        let preview_len = std::cmp::min(64, data_slice.len());
        debug!(
            "[SSL_WRITE DEBUG] Socket {}: hex preview (first {} bytes): {:02X?}",
            socket_id, preview_len, &data_slice[..preview_len]
        );
        
        // Try to parse as UTF-8 and log sanitized version
        if let Ok(text) = std::str::from_utf8(data_slice) {
            let sanitized: String = text.chars()
                .map(|c| if c.is_control() && c != '\r' && c != '\n' && c != '\t' { '.' } else { c })
                .collect();
            debug!(
                "[SSL_WRITE DEBUG] Socket {}: UTF-8 content (sanitized): {:?}",
                socket_id, sanitized
            );
            
            // Check for IRC protocol markers
            if text.contains("PRIVMSG") || text.contains("NOTICE") || text.contains("JOIN") {
                debug!("[SSL_WRITE DEBUG] Socket {}: detected IRC protocol command", socket_id);
            }
            
            // Check for FiSH key exchange markers
            if text.contains("X25519_INIT") || text.contains("FiSH11-PubKey:") {
                debug!("[SSL_WRITE DEBUG] Socket {}: detected FiSH key exchange data", socket_id);
            }
            
            // Check for encrypted message markers
            if text.contains("+OK ") || text.contains("+FiSH ") || text.contains("mcps ") {
                debug!("[SSL_WRITE DEBUG] Socket {}: detected FiSH encrypted message", socket_id);
            }
        } else {
            debug!(
                "[SSL_WRITE DEBUG] Socket {}: non-UTF8 binary data",
                socket_id
            );
        }
    }

    // Human-readable log for outgoing TLS
    if num > 0 && !buf.is_null() {
        if let Ok(text) = std::str::from_utf8(data_slice) {
            info!(
                "[TLS OUT] {}: {} bytes: {}",
                get_or_create_socket(socket_id, true).get_stats(),
                num,
                text.trim_end()
            );
        } else {
            info!(
                "[TLS OUT] {}: {} bytes (non-UTF8): {:02X?}",
                get_or_create_socket(socket_id, true).get_stats(),
                num,
                &data_slice[..std::cmp::min(32, data_slice.len())]
            );
        }
    }

    // Pre-process: log and allow for modification/event-op
    let socket_info = get_or_create_socket(socket_id, true);

    trace!(
        "Socket {}: [SSL PLAINTEXT] Outgoing data ({} bytes): {}",
        socket_id,
        num,
        String::from_utf8_lossy(data_slice).trim_end()
    );

    if let Err(e) = socket_info.on_sending(data_slice) {
        // [Pre-encryption]
        error!("Error processing outgoing SSL data: {:?}", e);
    }

    if log::log_enabled!(log::Level::Trace) {
        trace!("SSL_write() data: {:?}", data_slice);
    }

    // Always call the original SSL_write implementation
    let original_fn: SslWriteFn = {
        let lock = match ORIGINAL_SSL_WRITE.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("ORIGINAL_SSL_WRITE mutex poisoned in hooked_ssl_write()");
                poisoned.into_inner()
            }
        };
        match *lock {
            Some(fn_ptr) => fn_ptr,
            None => {
                error!("Original SSL_write() function is not available");
                return -1;
            }
        }
    };

    let result = original_fn(ssl, buf, num);

    // --- Post-handshake state detection ---
    {
        let ssl_is_init_finished = match SSL_IS_INIT_FINISHED.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("SSL_IS_INIT_FINISHED mutex poisoned in hooked_ssl_write()");
                poisoned.into_inner()
            }
        };
        if let Some(ssl_is_init_finished_fn) = *ssl_is_init_finished {
            let handshake_status = ssl_is_init_finished_fn(ssl);
            debug!("[HANDSHAKE] SSL_is_init_finished({:p}) = {}", ssl, handshake_status);
            if handshake_status != 0 {
                if let Some(handshake_sock_id) = get_socket_from_ssl_context(ssl) {
                    let handshake_info = get_or_create_socket(handshake_sock_id, true);
                    if handshake_info.get_state() == SocketState::TlsHandshake {
                        debug!(
                            "[HANDSHAKE] Socket {}: state changing TlsHandshake -> Connected",
                            handshake_sock_id
                        );
                        handshake_info.set_state(SocketState::Connected);
                        debug!(
                            "Socket {}: TLS handshake completed via SSL_write()",
                            handshake_sock_id
                        );
                    }
                }
            }
        }
    }

    result
}

/// Hook for SSL_connect to detect connection establishment
unsafe extern "C" fn hooked_ssl_connect(ssl: *mut SSL) -> c_int {
    debug!("SSL_connect() called for SSL {:p}", ssl);

    let original_fn: SslConnectFn = {
        let lock = match ORIGINAL_SSL_CONNECT.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("SSL_CONNECT_HOOK mutex poisoned in hooked_ssl_connect()");
                poisoned.into_inner()
            }
        };

        match *lock {
            Some(fn_ptr) => fn_ptr,
            None => {
                error!("Original SSL_connect() function is not available");
                return -1;
            }
        }
    };

    // Find the socket ID corresponding to this SSL pointer.
    let socket_id = find_socket_for_ssl(ssl);

    // Update state if the socket is found.
    if let Some(socket_id) = socket_id {
        let socket_info = get_or_create_socket(socket_id, true);
        debug!("[HANDSHAKE] Socket {}: state set to TlsHandshake", socket_id);
        socket_info.set_state(SocketState::TlsHandshake);
        debug!("Socket {}: Starting TLS handshake", socket_id);
    }

    let result = original_fn(ssl);
    if let Some(socket_id) = socket_id {
        if result > 0 {
            debug!("Socket {}: TLS handshake completed successfully", socket_id);
            // Update state or perform additional processing here.
        } else {
            debug!("Socket {}: TLS handshake failed with result {}", socket_id, result);
        }
    }

    // Get socket from SSL context if available
    if let Some(socket_id) = get_socket_from_ssl_context(ssl) {
        let socket_info = get_or_create_socket(socket_id, true);
        debug!("[HANDSHAKE] Socket {}: state set to TlsHandshake (post connect)", socket_id);
        socket_info.set_state(SocketState::TlsHandshake);
        debug!("Socket {}: SSL_connect - Setting state to TLS handshake", socket_id);
    } // Call original function
    let result = original_fn(ssl);

    // If connection successful, update state
    if result > 0 {
        if let Some(socket_id) = get_socket_from_ssl_context(ssl) {
            let socket_info = get_or_create_socket(socket_id, true);
            if socket_info.get_state() == SocketState::TlsHandshake {
                debug!(
                    "[HANDSHAKE] Socket {}: state changing TlsHandshake -> Connected (post connect)",
                    socket_id
                );
                socket_info.set_state(SocketState::Connected);
                debug!("Socket {}: SSL_connect - TLS handshake completed successfully", socket_id);
            }
        }
    }

    result
}

/// Hook for SSL_new to track new SSL objects.
unsafe extern "C" fn hooked_ssl_new(ctx: *mut c_void) -> *mut SSL {
    trace!("SSL_new() called with ctx: {:p}", ctx);

    // Call the original function
    let ssl = {
        let original_fn = *ORIGINAL_SSL_NEW.lock().unwrap();
        match original_fn {
            Some(func) => func(ctx),
            None => {
                error!("Original SSL_new is NULL!");
                return std::ptr::null_mut(); // Return error
            }
        }
    };

    if !ssl.is_null() {
        trace!("SSL_new() created SSL context: {:p}", ssl);
        // We'll register the socket later when we know which socket this SSL context is for
    }

    ssl
}

/// Hook for SSL_free to clean up our mappings.
/// Called whenever an SSL context is destroyed.
/// Properly removes SSL-to-socket and socket-to-SSL mappings.
///
/// # Safety
/// - Calls raw FFI pointers.
/// - Assumes all mutexes are correctly initialized.
unsafe extern "C" fn hooked_ssl_free(ssl: *mut SSL) {
    trace!("hooked_ssl_free(): ssl={:p}", ssl);

    // 1. Remove SSL <-> socket mapping(s)
    {
        // Remove SSL -> socket mapping
        let mut ssl_to_socket = match SSL_TO_SOCKET.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("SSL_TO_SOCKET mutex poisoned in hooked_ssl_free()");
                poisoned.into_inner()
            }
        };

        if let Some(fd) = ssl_to_socket.remove(&(ssl as usize)) {
            trace!("Removed SSL mapping for socket {}", fd);

            // Remove socket -> SSL mapping if present
            let mut socket_to_ssl = match SOCKET_TO_SSL.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    error!("SOCKET_TO_SSL mutex poisoned in hooked_ssl_free()");
                    poisoned.into_inner()
                }
            };
            socket_to_ssl.remove(&fd);
        }
    }

    // 2. Call the original function
    let original_fn = {
        let lock = match ORIGINAL_SSL_FREE.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("ORIGINAL_SSL_FREE mutex poisoned in hooked_ssl_free()");
                poisoned.into_inner()
            }
        };
        *lock
    };

    if let Some(real_ssl_free) = original_fn {
        real_ssl_free(ssl);
    } else {
        error!("Original SSL_free() function pointer not available in hooked_ssl_free()");
    }
}

/// Helper function to find a socket for an SSL pointer
fn find_socket_for_ssl(ssl: *mut SSL) -> Option<u32> {
    let ssl_to_socket = match SSL_TO_SOCKET.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            error!("SSL_TO_SOCKET mutex poisoned in find_socket_for_ssl()");
            poisoned.into_inner()
        }
    };

    ssl_to_socket.get(&ssl_to_id(ssl)).copied()
}

/// Register the association between a socket and an SSL object
fn register_ssl_for_socket(socket_id: u32, ssl: *mut SSL) {
    if ssl.is_null() {
        debug!("Attempted to register null SSL pointer for socket {}", socket_id);
        return;
    }

    let ssl_id = ssl_to_id(ssl);

    // Update mappings
    {
        let mut socket_to_ssl = match SOCKET_TO_SSL.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("SOCKET_TO_SSL mutex poisoned in register_ssl_for_socket()");
                poisoned.into_inner()
            }
        };

        socket_to_ssl.insert(socket_id, SSLWrapper { ssl });
    }

    {
        let mut ssl_to_socket = match SSL_TO_SOCKET.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("SSL_TO_SOCKET mutex poisoned in register_ssl_for_socket()");
                poisoned.into_inner()
            }
        };

        ssl_to_socket.insert(ssl_id, socket_id);
    }

    debug!("Registered SSL {:p} for socket {}", ssl, socket_id);

    // Update socket state
    //let _socket_info = get_or_create_socket(socket_id, false);
    let socket_info = get_or_create_socket(socket_id, true);
    socket_info.set_ssl(true);
}

/// Function to install all SSL hooks
pub unsafe fn install_ssl_hooks(
    ssl_read: SslReadFn,
    ssl_write: SslWriteFn,
    ssl_get_fd: SslGetFdFn,
    ssl_is_init_finished: SslIsInitFinishedProc,
) -> Result<(), String> {
    #[cfg(debug_assertions)]
    info!("install_ssl_hooks: starting SSL hooks installation...");

    #[cfg(debug_assertions)]
    info!("install_ssl_hooks: acquiring SSL_READ_HOOK mutex...");
    let mut ssl_read_hook = SSL_READ_HOOK.lock().unwrap_or_else(handle_poison);
    #[cfg(debug_assertions)]
    info!("install_ssl_hooks: SSL_READ_HOOK mutex acquired");

    #[cfg(debug_assertions)]
    info!("install_ssl_hooks: acquiring SSL_WRITE_HOOK mutex...");
    let mut ssl_write_hook = SSL_WRITE_HOOK.lock().unwrap_or_else(handle_poison);
    #[cfg(debug_assertions)]
    info!("install_ssl_hooks: SSL_WRITE_HOOK mutex acquired");

    #[cfg(debug_assertions)]
    info!("install_ssl_hooks: storing SSL_GET_FD function pointer...");
    *SSL_GET_FD.lock().unwrap_or_else(handle_poison) = Some(ssl_get_fd);
    #[cfg(debug_assertions)]
    info!("install_ssl_hooks: SSL_GET_FD stored at {:?}", ssl_get_fd as *const ());

    #[cfg(debug_assertions)]
    info!("install_ssl_hooks: storing SSL_IS_INIT_FINISHED function pointer...");
    *SSL_IS_INIT_FINISHED.lock().unwrap_or_else(handle_poison) = Some(ssl_is_init_finished);
    debug!(
        "[HANDSHAKE] SSL_is_init_finished loaded at address: {:p}",
        ssl_is_init_finished as *const ()
    );

    #[cfg(debug_assertions)]
    info!("install_ssl_hooks: Creating SSL_read GenericDetour...");
    *ssl_read_hook = Some(
        GenericDetour::new(ssl_read, hooked_ssl_read)
            .map_err(|e| {
                #[cfg(debug_assertions)]
                error!("install_ssl_hooks: failed to create SSL_read GenericDetour: {}", e);
                format!("Failed to create SSL_read hook: {}", e)
            })?,
    );
    #[cfg(debug_assertions)]
    info!("install_ssl_hooks: SSL_read GenericDetour created successfully");

    #[cfg(debug_assertions)]
    info!("install_ssl_hooks: creating SSL_write GenericDetour...");
    *ssl_write_hook = Some(
        GenericDetour::new(ssl_write, hooked_ssl_write)
            .map_err(|e| {
                #[cfg(debug_assertions)]
                error!("install_ssl_hooks: failed to create SSL_write GenericDetour: {}", e);
                format!("Failed to create SSL_write hook: {}", e)
            })?,
    );
    #[cfg(debug_assertions)]
    info!("install_ssl_hooks: SSL_write GenericDetour created successfully");

    #[cfg(debug_assertions)]
    info!("install_ssl_hooks: enabling SSL_read hook...");
    ssl_read_hook
        .as_mut()
        .unwrap()
        .enable()
        .map_err(|e| {
            #[cfg(debug_assertions)]
            error!("install_ssl_hooks: failed to enable SSL_read hook: {}", e);
            format!("Failed to enable SSL_read hook: {}", e)
        })?;
    #[cfg(debug_assertions)]
    info!("install_ssl_hooks: SSL_read hook enabled successfully");

    #[cfg(debug_assertions)]
    info!("install_ssl_hooks: enabling SSL_write hook...");
    ssl_write_hook
        .as_mut()
        .unwrap()
        .enable()
        .map_err(|e| {
            #[cfg(debug_assertions)]
            error!("install_ssl_hooks: failed to enable SSL_write hook: {}", e);
            format!("Failed to enable SSL_write hook: {}", e)
        })?;
    #[cfg(debug_assertions)]
    info!("install_ssl_hooks: SSL_write hook enabled successfully");

    #[cfg(debug_assertions)]
    info!("install_ssl_hooks: SSL hooks installation completed successfully");

    Ok(())
}

/// Install a critical SSL hook - must succeed for SSL functionality to work
unsafe fn install_critical_ssl_hook<F: Copy + retour::Function>(
    original_fn: F,
    hook_fn: F,
    hook_storage: &StdMutex<Option<GenericDetour<F>>>,
    hook_name: &str,
) -> bool {
    match GenericDetour::<F>::new(original_fn, hook_fn) {
        Ok(hook) => {
            if let Err(e) = hook.enable() {
                error!("Failed to enable {hook_name}() hook: {:?}", e);
                return false;
            }
            *hook_storage.lock().unwrap() = Some(hook);
            info!("  - {hook_name}() hook installed");
            true
        }
        Err(e) => {
            error!("Failed to create {hook_name}() hook: {:?}", e);
            false
        }
    }
}

/// Install an optional SSL hook - failure is not critical
unsafe fn install_optional_ssl_hook<F: Copy + retour::Function>(
    original_fn: F,
    hook_fn: F,
    hook_storage: &StdMutex<Option<GenericDetour<F>>>,
    hook_name: &str,
) {
    match GenericDetour::<F>::new(original_fn, hook_fn) {
        Ok(hook) => {
            if let Err(e) = hook.enable() {
                error!("Failed to enable {hook_name}() hook: {:?}", e);
                // Not critical, continue anyway
            } else {
                *hook_storage.lock().unwrap() = Some(hook);
                info!("  - {hook_name}() hook installed");
            }
        }
        Err(e) => {
            error!("Failed to create {hook_name}() hook: {:?}", e);
            // Not critical, continue anyway
        }
    }
}

/// Function to uninstall all SSL hooks
pub fn uninstall_ssl_hooks() {
    info!("Uninstalling SSL hooks...");
    let mut all_hooks_disabled = true;

    // Disable SSL_read hook
    {
        let mut hook_opt = match SSL_READ_HOOK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("SSL_READ_HOOK mutex poisoned during uninstall");
                poisoned.into_inner()
            }
        };

        if let Some(hook) = hook_opt.take() {
            if let Err(e) = unsafe { hook.disable() } {
                error!("Failed to disable SSL_read hook: {:?}", e);
                all_hooks_disabled = false;
            } else {
                info!("SSL_read() hook uninstalled successfully");
            }
        }
    }

    // Disable SSL_write hook
    {
        let mut hook_opt = match SSL_WRITE_HOOK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("SSL_WRITE_HOOK mutex poisoned during uninstall");
                poisoned.into_inner()
            }
        };

        if let Some(hook) = hook_opt.take() {
            if let Err(e) = unsafe { hook.disable() } {
                error!("Failed to disable SSL_write hook: {:?}", e);
                all_hooks_disabled = false;
            } else {
                info!("SSL_write() hook uninstalled successfully");
            }
        }
    }

    // Disable SSL_connect hook
    {
        let mut hook_opt = match SSL_CONNECT_HOOK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("SSL_CONNECT_HOOK mutex poisoned during uninstall");
                poisoned.into_inner()
            }
        };

        if let Some(hook) = hook_opt.take() {
            if let Err(e) = unsafe { hook.disable() } {
                error!("Failed to disable SSL_connect hook: {:?}", e);
                all_hooks_disabled = false;
            } else {
                info!("SSL_connect() hook uninstalled successfully");
            }
        }
    }

    // Disable SSL_new hook
    {
        let mut hook_opt = match SSL_NEW_HOOK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("SSL_NEW_HOOK mutex poisoned during uninstall");
                poisoned.into_inner()
            }
        };

        if let Some(hook) = hook_opt.take() {
            if let Err(e) = unsafe { hook.disable() } {
                error!("Failed to disable SSL_new hook: {:?}", e);
                all_hooks_disabled = false;
            } else {
                info!("SSL_new() hook uninstalled successfully");
            }
        }
    }

    // Disable SSL_free hook
    {
        let mut hook_opt = match SSL_FREE_HOOK.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("SSL_FREE_HOOK mutex poisoned during uninstall");
                poisoned.into_inner()
            }
        };

        if let Some(hook) = hook_opt.take() {
            if let Err(e) = unsafe { hook.disable() } {
                error!("Failed to disable SSL_free hook: {:?}", e);
                all_hooks_disabled = false;
            } else {
                info!("SSL_free() hook uninstalled successfully");
            }
        }
    }

    {
        let mut hook_opt = SSL_SET_FD_HOOK.lock().unwrap();

        if let Some(hook) = hook_opt.take() {
            if let Err(e) = unsafe { hook.disable() } {
                error!("Failed to disable SSL_set_fd hook: {:?}", e);
                all_hooks_disabled = false;
            } else {
                info!("SSL_set_fd() hook uninstalled successfully");
            }
        }
    }

    // Clear our mappings
    {
        let mut socket_to_ssl = match SOCKET_TO_SSL.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("SOCKET_TO_SSL mutex poisoned during uninstall");
                poisoned.into_inner()
            }
        };

        let count = socket_to_ssl.len();
        socket_to_ssl.clear();
        debug!("Cleared {} entries from SOCKET_TO_SSL mapping", count);
    }

    {
        let mut ssl_to_socket = match SSL_TO_SOCKET.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("SSL_TO_SOCKET mutex poisoned during uninstall");
                poisoned.into_inner()
            }
        };

        let count = ssl_to_socket.len();
        ssl_to_socket.clear();
        debug!("Cleared {} entries from SSL_TO_SOCKET mapping", count);
    }

    // Clear original function pointers
    {
        let mut original_fn = ORIGINAL_SSL_READ.lock().unwrap();
        *original_fn = None;
    }
    {
        let mut original_fn = ORIGINAL_SSL_WRITE.lock().unwrap();
        *original_fn = None;
    }
    {
        let mut original_fn = ORIGINAL_SSL_CONNECT.lock().unwrap();
        *original_fn = None;
    }
    {
        let mut original_fn = ORIGINAL_SSL_NEW.lock().unwrap();
        *original_fn = None;
    }
    {
        let mut original_fn = ORIGINAL_SSL_FREE.lock().unwrap();
        *original_fn = None;
    }

    // Update installed flag
    {
        let mut installed = match SSL_HOOKS_INSTALLED.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                error!("SSL_HOOKS_INSTALLED mutex was poisoned! Recovering...");
                poisoned.into_inner()
            }
        };

        *installed = false;
    }

    if all_hooks_disabled {
        info!("All SSL hooks successfully uninstalled");
    } else {
        warn!("Damn, some SSL hooks could not be properly uninstalled !");
    }
}

/// Get the socket ID associated with an SSL context
unsafe fn get_socket_from_ssl_context(ssl: *mut SSL) -> Option<u32> {
    let ssl_id = ssl_to_id(ssl);

    // Lookup in the mapping
    let ssl_to_socket = match SSL_TO_SOCKET.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            error!("SSL_TO_SOCKET mutex poisoned");
            poisoned.into_inner()
        }
    };

    ssl_to_socket.get(&ssl_id).copied()
}
