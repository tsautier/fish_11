use std::fs::OpenOptions;
use std::io;
use std::sync::PoisonError;

use log::{LevelFilter, error, info};
use retour::GenericDetour;
use winapi::shared::minwindef::FARPROC;
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};

use crate::hook_socket::{
    CLOSESOCKET_HOOK, CONNECT_HOOK, ClosesocketFn, ConnectFn, RECV_HOOK, RecvFn, SEND_HOOK, SendFn,
    hooked_closesocket, hooked_connect, hooked_recv, hooked_send, uninstall_socket_hooks,
};
use crate::hook_ssl::{
    SslGetFdFn, SslIsInitFinishedProc, SslReadFn, SslWriteFn, find_ssl_function, install_ssl_hooks,
    uninstall_ssl_hooks,
};
use crate::{LOGGER_INITIALIZED, Ordering};

/// Custom logger that writes with timestamps
struct TimestampLogger {
    file: std::sync::Mutex<std::fs::File>,
    level: LevelFilter,
}

impl TimestampLogger {
    fn new(file: std::fs::File, level: LevelFilter) -> Self {
        Self { file: std::sync::Mutex::new(file), level }
    }
}

impl log::Log for TimestampLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
            let log_message = format!(
                "[{}] {} [{}:{}] {}\n",
                timestamp,
                record.level(),
                record.file().unwrap_or("<unknown>"),
                record.line().unwrap_or(0),
                record.args()
            );

            if let Ok(mut file) = self.file.lock() {
                use std::io::Write;
                let _ = file.write_all(log_message.as_bytes());
                let _ = file.flush();
            }
        }
    }

    fn flush(&self) {
        if let Ok(mut file) = self.file.lock() {
            use std::io::Write;
            let _ = file.flush();
        }
    }
}

/// Initialize the logger
pub fn init_logger() {
    if LOGGER_INITIALIZED.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok()
    {
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("fish11_inject.log")
            .expect("Failed to open log file");

        let logger = TimestampLogger::new(log_file, LevelFilter::Trace);

        if log::set_boxed_logger(Box::new(logger)).is_ok() {
            log::set_max_level(LevelFilter::Trace);
            info!("Ground zero : logger initialized !");
        }
    }
}

/// Function to install all hooks
pub fn install_hooks() -> Result<(), io::Error> {
    info!("Installing Winsock hooks :");

    #[cfg(debug_assertions)]
    info!("install_hooks: Starting hook installation process...");

    unsafe {
        #[cfg(debug_assertions)]
        info!("install_hooks: Resolving Winsock functions...");

        // Dynamically resolve Winsock functions
        let recv_fn = std::mem::transmute::<FARPROC, RecvFn>(get_winsock_function("recv\0"));
        #[cfg(debug_assertions)]
        info!("install_hooks: recv function resolved at {:?}", recv_fn as *const ());

        let send_fn = std::mem::transmute::<FARPROC, SendFn>(get_winsock_function("send\0"));
        #[cfg(debug_assertions)]
        info!("install_hooks: send function resolved at {:?}", send_fn as *const ());

        let connect_fn =
            std::mem::transmute::<FARPROC, ConnectFn>(get_winsock_function("connect\0"));
        #[cfg(debug_assertions)]
        info!("install_hooks: connect function resolved at {:?}", connect_fn as *const ());

        let closesocket_fn =
            std::mem::transmute::<FARPROC, ClosesocketFn>(get_winsock_function("closesocket\0"));
        #[cfg(debug_assertions)]
        info!("install_hooks: closesocket function resolved at {:?}", closesocket_fn as *const ());

        #[cfg(debug_assertions)]
        info!("install_hooks: Installing socket hooks...");

        // Install socket hooks
        install_socket_hook::<RecvFn>("recv", recv_fn, hooked_recv, &RECV_HOOK)?;
        #[cfg(debug_assertions)]
        info!("install_hooks: recv hook installed");

        install_socket_hook::<SendFn>("send", send_fn, hooked_send, &SEND_HOOK)?;
        #[cfg(debug_assertions)]
        info!("install_hooks: send hook installed");

        install_socket_hook::<ConnectFn>("connect", connect_fn, hooked_connect, &CONNECT_HOOK)?;
        #[cfg(debug_assertions)]
        info!("install_hooks: connect hook installed");

        install_socket_hook::<ClosesocketFn>(
            "closesocket",
            closesocket_fn,
            hooked_closesocket,
            &CLOSESOCKET_HOOK,
        )?;
        #[cfg(debug_assertions)]
        info!("install_hooks: closesocket hook installed");

        #[cfg(debug_assertions)]
        info!("install_hooks: Resolving SSL functions...");

        // Install SSL hooks
        let ssl_read = std::mem::transmute::<FARPROC, SslReadFn>(find_ssl_function("SSL_read"));
        #[cfg(debug_assertions)]
        info!("install_hooks: SSL_read resolved at {:?}", ssl_read as *const ());

        let ssl_write = std::mem::transmute::<FARPROC, SslWriteFn>(find_ssl_function("SSL_write"));
        #[cfg(debug_assertions)]
        info!("install_hooks: SSL_write resolved at {:?}", ssl_write as *const ());

        let ssl_get_fd =
            std::mem::transmute::<FARPROC, SslGetFdFn>(find_ssl_function("SSL_get_fd"));
        #[cfg(debug_assertions)]
        info!("install_hooks: SSL_get_fd resolved at {:?}", ssl_get_fd as *const ());

        let ssl_is_init_finished = std::mem::transmute::<FARPROC, SslIsInitFinishedProc>(
            find_ssl_function("SSL_is_init_finished"),
        );
        #[cfg(debug_assertions)]
        info!(
            "install_hooks: SSL_is_init_finished resolved at {:?}",
            ssl_is_init_finished as *const ()
        );

        if ssl_read as usize == 0
            || ssl_write as usize == 0
            || ssl_get_fd as usize == 0
            || ssl_is_init_finished as usize == 0
        {
            error!(
                "One or more required SSL functions could not be found. Skipping SSL hook installation."
            );
            #[cfg(debug_assertions)]
            error!(
                "install_hooks: SSL functions missing - ssl_read={:?}, ssl_write={:?}, ssl_get_fd={:?}, ssl_is_init_finished={:?}",
                ssl_read as *const (),
                ssl_write as *const (),
                ssl_get_fd as *const (),
                ssl_is_init_finished as *const ()
            );
        } else {
            #[cfg(debug_assertions)]
            info!("install_hooks: All SSL functions found, installing SSL hooks...");

            match install_ssl_hooks(ssl_read, ssl_write, ssl_get_fd, ssl_is_init_finished) {
                Ok(_) => {
                    info!("All SSL hooks successfully installed !");
                    #[cfg(debug_assertions)]
                    info!("install_hooks: SSL hooks installation succeeded");
                }
                Err(e) => {
                    error!("Failed to install SSL hooks: {}", e);
                    #[cfg(debug_assertions)]
                    error!("install_hooks: SSL hooks installation failed: {}", e);
                }
            }
        }

        info!("All winsock hooks successfully installed !");
        #[cfg(debug_assertions)]
        info!("install_hooks: Hook installation process completed successfully");

        Ok(())
    }
}

/// Helper function to install a specific socket hook
unsafe fn install_socket_hook<T: Copy + retour::Function>(
    hook_name: &str,
    original_fn: T,
    hook_fn: T,
    hook_storage: &std::sync::Mutex<Option<GenericDetour<T>>>,
) -> Result<(), io::Error> {
    #[cfg(debug_assertions)]
    info!("install_socket_hook: Installing {} hook...", hook_name);

    match GenericDetour::<T>::new(original_fn, hook_fn) {
        Ok(hook) => {
            #[cfg(debug_assertions)]
            info!("install_socket_hook: {} GenericDetour created, enabling...", hook_name);

            hook.enable().map_err(|e| {
                #[cfg(debug_assertions)]
                error!("install_socket_hook: Failed to enable {} hook: {:?}", hook_name, e);

                io::Error::new(
                    io::ErrorKind::Other,
                    format!("  - failed to enable {}() hook: {:?}", hook_name, e),
                )
            })?;

            #[cfg(debug_assertions)]
            info!("install_socket_hook: {} hook enabled, storing in mutex...", hook_name);

            *hook_storage.lock().unwrap() = Some(hook);
            info!("  - {}() hook installed", hook_name);

            #[cfg(debug_assertions)]
            info!("install_socket_hook: {} hook installation complete", hook_name);

            Ok(())
        }
        Err(e) => {
            #[cfg(debug_assertions)]
            error!("install_socket_hook: Failed to create {} GenericDetour: {:?}", hook_name, e);

            Err(io::Error::new(
                io::ErrorKind::Other,
                format!("  - failed to create {}() hook: {:?}", hook_name, e),
            ))
        }
    }
}

/// Cleanup function for all hooks. This must be called at DLL unload
pub fn cleanup_hooks() {
    info!("Cleaning up hooks :");

    // First uninstall SSL hooks
    uninstall_ssl_hooks();
    info!("  * SSL hooks uninstalled");

    // Then uninstall Winsock hooks
    uninstall_socket_hooks();
    info!("  * Socket hooks uninstalled");

    info!("All hooks cleaned up sucessfully !");
}

/// 1. Getting a handle to ws2_32.dll.
/// 2. Retrieving the addresses of connect(), send(), recv(), and closesocket() using GetProcAddress.
unsafe fn get_winsock_function(func_name: &str) -> FARPROC {
    #[cfg(debug_assertions)]
    info!("get_winsock_function: Looking for function '{}'", func_name);

    let ws2_32 = GetModuleHandleA(b"ws2_32.dll\0".as_ptr() as _);
    if ws2_32.is_null() {
        #[cfg(debug_assertions)]
        error!("get_winsock_function: Failed to get ws2_32.dll handle!");

        panic!("Failed to get ws2_32.dll handle");
    }

    #[cfg(debug_assertions)]
    info!("get_winsock_function: ws2_32.dll handle = {:?}", ws2_32);

    let func_addr = GetProcAddress(ws2_32, func_name.as_ptr() as _);

    #[cfg(debug_assertions)]
    info!("get_winsock_function: {} address = {:?}", func_name, func_addr);

    func_addr
}

/// Helper to handle mutex poisoning
pub fn handle_poison<T>(err: PoisonError<T>) -> T {
    error!("Mutex poisoned: {}", err);
    err.into_inner()
}
