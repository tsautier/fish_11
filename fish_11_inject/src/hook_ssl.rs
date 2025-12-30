use crate::helpers_inject::handle_poison;
use crate::hook_socket::get_or_create_socket;
use crate::pointer_validation::validate_function_pointer;
use crate::socket::state::SocketState;
use crate::ssl_mapping::SslSocketMapping;
//use fish_11_core::globals::{
//    ENCRYPTION_PREFIX_FISH, ENCRYPTION_PREFIX_MCPS, ENCRYPTION_PREFIX_OK,
    // KEY_EXCHANGE_INIT, KEY_EXCHANGE_PUBKEY removed
//};
use lazy_static::lazy_static;
use log::{debug, error, info, trace, warn};
use retour::GenericDetour;
use std::ffi::{CString, c_int, c_void};
use std::sync::Mutex as StdMutex;
use windows::core::PCSTR;
use windows::Win32::Foundation::FARPROC;
use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress, LoadLibraryA};
use windows::Win32::Networking::WinSock::SOCKET;

// SSL structure (opaque)
#[repr(C)]
pub struct SSL {
    _private: [u8; 0],
}

pub struct SSLWrapper {
    pub ssl: *mut SSL,
}

unsafe impl Send for SSLWrapper {}
unsafe impl Sync for SSLWrapper {}

unsafe impl Send for SSL {}
unsafe impl Sync for SSL {}

pub type SslReadFn = unsafe extern "C" fn(*mut SSL, *mut u8, c_int) -> c_int;
pub type SslWriteFn = unsafe extern "C" fn(*mut SSL, *const u8, c_int) -> c_int;
pub type SslConnectFn = unsafe extern "C" fn(*mut SSL) -> c_int;
pub type SslNewFn = unsafe extern "C" fn(*mut c_void) -> *mut SSL;
pub type SslFreeFn = unsafe extern "C" fn(*mut SSL);
pub type SslGetFdFn = unsafe extern "C" fn(*mut SSL) -> c_int;
pub type SslSetFdFn = unsafe extern "C" fn(*mut SSL, c_int) -> c_int;
pub type SslIsInitFinishedProc = unsafe extern "C" fn(*mut SSL) -> i32;

lazy_static! {
    static ref SSL_IS_INIT_FINISHED: StdMutex<Option<SslIsInitFinishedProc>> = StdMutex::new(None);
}

lazy_static! {
    pub static ref SSL_READ_HOOK: StdMutex<Option<GenericDetour<SslReadFn>>> = StdMutex::new(None);
    pub static ref SSL_WRITE_HOOK: StdMutex<Option<GenericDetour<SslWriteFn>>> = StdMutex::new(None);
    pub static ref SSL_CONNECT_HOOK: StdMutex<Option<GenericDetour<SslConnectFn>>> = StdMutex::new(None);
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

unsafe extern "C" fn hooked_ssl_set_fd(ssl: *mut SSL, fd: c_int) -> c_int {
    static ORIGINAL_SSL_SET_FD: StdMutex<Option<SslSetFdFn>> = StdMutex::new(None);
    trace!("SSL_set_fd() called with ssl: {:p}, fd: {}", ssl, fd);

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

    if result > 0 && !ssl.is_null() {
        SslSocketMapping::associate(ssl, fd as u32);
        let socket_info = get_or_create_socket(fd as u32, true);
        socket_info.set_ssl(true);
        trace!("Socket {} marked as using SSL", fd);
    }

    result
}

pub fn find_ssl_function(function_name: &str) -> FARPROC {
    let ssl_lib_names = [
        "libssl-3.dll\0",
        "libssl-1_1.dll\0",
        "libssl-1_1-x64.dll\0",
        "ssleay32.dll\0",
        "libssl.dll\0",
        "crypt32.dll\0",
        "schannel.dll\0",
    ];

    let function_variants = [
        function_name.to_string(),
        format!("{}@4", function_name),
        format!("{}@8", function_name),
        format!("{}@12", function_name),
        format!("_{}@4", function_name),
        format!("_{}@8", function_name),
        format!("_{}@12", function_name),
        format!("_{}", function_name),
    ];
    let func_name_cstr = |name: &str| -> CString {
        CString::new(name).unwrap_or_else(|_| {
            CString::new("invalid").expect("Failed to create fallback function name")
        })
    };

    for lib_name in &ssl_lib_names {
        unsafe {
            if let Ok(handle) = GetModuleHandleA(PCSTR::from_raw(lib_name.as_ptr())) {
                if !handle.is_invalid() {
                    for variant in &function_variants {
                         let name_c = func_name_cstr(variant);
                         let func_ptr = GetProcAddress(handle, PCSTR::from_raw(name_c.as_ptr() as *const u8));
                         if func_ptr.is_some() {
                            if let Err(e) = validate_function_pointer(func_ptr, Some(handle)) {
                                warn!("validation failed for found ssl function: {}", e);
                                continue;
                            }
                            info!(
                                "Found {} ({}) in {}",
                                function_name,
                                variant,
                                String::from_utf8_lossy(lib_name.strip_suffix("\0").unwrap().as_bytes())
                            );
                            return func_ptr;
                         }
                    }
                }
            }
        }
    }

    for lib_name in &ssl_lib_names {
        unsafe {
            if let Ok(handle) = LoadLibraryA(PCSTR::from_raw(lib_name.as_ptr())) {
                 if !handle.is_invalid() {
                    for variant in &function_variants {
                        let name_c = func_name_cstr(variant);
                        let func_ptr = GetProcAddress(handle, PCSTR::from_raw(name_c.as_ptr() as *const u8));
                        if func_ptr.is_some() {
                           if let Err(e) = validate_function_pointer(func_ptr, Some(handle)) {
                               warn!("validation failed for loaded ssl function: {}", e);
                               continue;
                           }
                           info!(
                               "Loaded {} and found {} ({}) in {}",
                               String::from_utf8_lossy(lib_name.strip_suffix("\0").unwrap().as_bytes()),
                               function_name,
                               variant,
                               String::from_utf8_lossy(lib_name.strip_suffix("\0").unwrap().as_bytes())
                           );
                           return func_ptr;
                        }
                    }
                 }
            }
        }
    }

    warn!("Could not find function {} in any SSL library", function_name);
    None
}

pub unsafe fn store_ssl_mapping(ssl: *mut SSL, socket: SOCKET) {
    if let Some(fd_fn) = *SSL_GET_FD.lock().unwrap_or_else(handle_poison) {
        let fd = fd_fn(ssl);
        SslSocketMapping::associate(ssl, socket.0 as u32);
        debug!("Mapped SSL {:p} to socket {} (fd={})", ssl, socket.0, fd);
    }
}

pub unsafe extern "C" fn hooked_ssl_read(ssl: *mut SSL, buf: *mut u8, num: c_int) -> c_int {
    trace!("[h00k] hooked_ssl_read() called: ssl={:p}, buf={:p}, num={}", ssl, buf, num);

    let ssl_read_guard = match crate::lock_utils::try_lock_timeout(
        &SSL_READ_HOOK,
        crate::lock_utils::DEFAULT_LOCK_TIMEOUT,
    ) {
        Ok(guard) => guard,
        Err(e) => {
            error!("Failed to acquire SSL_READ_HOOK lock: {}", e);
            return -1;
        }
    };
    let original = match ssl_read_guard.as_ref() {
        Some(hook) => hook,
        None => {
            error!("Original SSL_read() function not available!");
            return -1;
        }
    };

    let socket_id = match get_socket_from_ssl_context(ssl) {
        Some(id) => id,
        None => {
            error!("SSL_read called on unknown SSL context {:p}", ssl);
            return original.call(ssl, buf, num);
        }
    };

    let bytes_read = original.call(ssl, buf, num);

    if bytes_read > 0 && !buf.is_null() {
        let data_slice = std::slice::from_raw_parts(buf, bytes_read as usize);

        #[cfg(debug_assertions)]
        {
             if let Ok(text) = std::str::from_utf8(data_slice) {
                // Simplified logging
                trace!("SSL_read data: {}", text);
             }
        }

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
        trace!(
            "[h00k] hooked_ssl_read() decrypted data for socket {} ({} bytes): {:02X?}",
            socket_id,
            bytes_read,
            &data_slice[..std::cmp::min(16, data_slice.len())]
        );
    }

    let ssl_init_fn = match crate::lock_utils::try_lock_timeout(
        &SSL_IS_INIT_FINISHED,
        crate::lock_utils::DEFAULT_LOCK_TIMEOUT,
    ) {
        Ok(guard) => *guard,
        Err(e) => {
            warn!("Failed to acquire SSL_IS_INIT_FINISHED lock: {}", e);
            None
        }
    };
    if let Some(ssl_init_fn) = ssl_init_fn {
        let handshake_status = ssl_init_fn(ssl);
        if handshake_status != 0 {
            let socket_info = get_or_create_socket(socket_id, true);
            if socket_info.get_state() == SocketState::TlsHandshake {
                debug!("[HANDSHAKE] Socket {}: state changing TlsHandshake -> Connected", socket_id);
                socket_info.set_state(SocketState::Connected);
            }
        }
    }

    if bytes_read <= 0 {
        return bytes_read;
    }

    let socket_info = get_or_create_socket(socket_id, true);
    let data_slice = std::slice::from_raw_parts(buf, bytes_read as usize);
    socket_info.write_received_data(data_slice);
    if let Err(e) = socket_info.process_received_lines() {
        error!("Error processing received SSL lines: {:?}", e);
    }

    bytes_read
}

unsafe extern "C" fn hooked_ssl_write(ssl: *mut SSL, buf: *const u8, num: c_int) -> c_int {
    trace!("[h00k] hooked_ssl_write() called: ssl={:p}, buf={:p}, num={}", ssl, buf, num);

    let socket_id = match SslSocketMapping::get_socket(ssl) {
        Some(socket_id) => socket_id,
        None => {
            trace!("SSL_write(): no socket ID found for SSL {:p}", ssl);
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
    };

    trace!("SSL_write: socket {}, {} bytes", socket_id, num);

    if num > 0 && !buf.is_null() {
        let data_slice = std::slice::from_raw_parts(buf, num as usize);

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

        let socket_info = get_or_create_socket(socket_id, true);

        if let Err(e) = socket_info.on_sending(data_slice) {
            error!("Error processing outgoing SSL data: {:?}", e);
        }

        if log::log_enabled!(log::Level::Trace) {
            trace!("SSL_write() data: {:?}", data_slice);
        }
    }

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

    {
        let ssl_is_init_finished_fn = match crate::lock_utils::try_lock_timeout(
            &SSL_IS_INIT_FINISHED,
            crate::lock_utils::DEFAULT_LOCK_TIMEOUT,
        ) {
            Ok(guard) => *guard,
            Err(e) => {
                warn!("Failed to acquire SSL_IS_INIT_FINISHED lock: {}", e);
                None
            }
        };
        if let Some(ssl_is_init_finished_fn) = ssl_is_init_finished_fn {
            let handshake_status = ssl_is_init_finished_fn(ssl);
            if handshake_status != 0 {
                if let Some(handshake_sock_id) = get_socket_from_ssl_context(ssl) {
                    let handshake_info = get_or_create_socket(handshake_sock_id, true);
                    if handshake_info.get_state() == SocketState::TlsHandshake {
                        debug!("[HANDSHAKE] Socket {}: state changing TlsHandshake -> Connected", handshake_sock_id);
                        handshake_info.set_state(SocketState::Connected);
                    }
                }
            }
        }
    }

    result
}

// Retaining hooked_ssl_connect and others as placeholders or used by potential future features
// The current installation only actively uses read/write/get_fd
unsafe extern "C" fn hooked_ssl_connect(ssl: *mut SSL) -> c_int {
    debug!("SSL_connect() called for SSL {:p}", ssl);
    // ... Simplified
    let original_fn: SslConnectFn = {
         if let Some(func) = *ORIGINAL_SSL_CONNECT.lock().unwrap_or_else(handle_poison) {
            func
         } else {
            return -1;
         }
    };
    original_fn(ssl)
}

pub unsafe fn install_ssl_hooks(
    ssl_read: SslReadFn,
    ssl_write: SslWriteFn,
    ssl_get_fd: SslGetFdFn,
    ssl_is_init_finished: SslIsInitFinishedProc,
) -> Result<(), String> {
    let mut ssl_read_hook = SSL_READ_HOOK.lock().unwrap_or_else(handle_poison);
    let mut ssl_write_hook = SSL_WRITE_HOOK.lock().unwrap_or_else(handle_poison);

    *SSL_GET_FD.lock().unwrap_or_else(handle_poison) = Some(ssl_get_fd);
    *SSL_IS_INIT_FINISHED.lock().unwrap_or_else(handle_poison) = Some(ssl_is_init_finished);

    *ssl_read_hook = Some(GenericDetour::new(ssl_read, hooked_ssl_read).map_err(|e| {
        format!("Failed to create SSL_read hook: {}", e)
    })?);

    *ssl_write_hook = Some(GenericDetour::new(ssl_write, hooked_ssl_write).map_err(|e| {
        format!("Failed to create SSL_write hook: {}", e)
    })?);

    ssl_read_hook.as_mut().unwrap().enable().map_err(|e| {
        format!("Failed to enable SSL_read hook: {}", e)
    })?;

    ssl_write_hook.as_mut().unwrap().enable().map_err(|e| {
        format!("Failed to enable SSL_write hook: {}", e)
    })?;

    Ok(())
}

pub fn uninstall_ssl_hooks() {
    info!("Uninstalling SSL hooks...");

    {
        let mut hook_opt = SSL_READ_HOOK.lock().unwrap_or_else(handle_poison);
        if let Some(hook) = hook_opt.take() {
             unsafe {
                 if let Err(e) = hook.disable() {
                     error!("Failed to disable SSL_read hook: {:?}", e);
                 }
             }
        }
    }

    {
        let mut hook_opt = SSL_WRITE_HOOK.lock().unwrap_or_else(handle_poison);
        if let Some(hook) = hook_opt.take() {
             unsafe {
                 if let Err(e) = hook.disable() {
                     error!("Failed to disable SSL_write hook: {:?}", e);
                 }
             }
        }
    }

    {
        let mut hook_opt = SSL_CONNECT_HOOK.lock().unwrap_or_else(handle_poison);
        if let Some(hook) = hook_opt.take() {
             unsafe { let _ = hook.disable(); }
        }
    }
    {
        let mut hook_opt = SSL_NEW_HOOK.lock().unwrap_or_else(handle_poison);
        if let Some(hook) = hook_opt.take() {
            unsafe { let _ = hook.disable(); }
        }
    }
    {
         let mut hook_opt = SSL_FREE_HOOK.lock().unwrap_or_else(handle_poison);
         if let Some(hook) = hook_opt.take() {
            unsafe { let _ = hook.disable(); }
         }
    }

    SslSocketMapping::clear();
    *ORIGINAL_SSL_READ.lock().unwrap_or_else(handle_poison) = None;
    *ORIGINAL_SSL_WRITE.lock().unwrap_or_else(handle_poison) = None;
    *ORIGINAL_SSL_CONNECT.lock().unwrap_or_else(handle_poison) = None;
    *ORIGINAL_SSL_NEW.lock().unwrap_or_else(handle_poison) = None;
    *ORIGINAL_SSL_FREE.lock().unwrap_or_else(handle_poison) = None;
    *SSL_HOOKS_INSTALLED.lock().unwrap_or_else(handle_poison) = false;
}

unsafe fn get_socket_from_ssl_context(ssl: *mut SSL) -> Option<u32> {
    SslSocketMapping::get_socket(ssl)
}
