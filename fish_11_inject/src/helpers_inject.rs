use std::fs::OpenOptions;
use std::io;
use std::sync::PoisonError;

use log::{error, info};
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

/// Initialize the logger
pub fn init_logger() {
    if LOGGER_INITIALIZED.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_ok()
    {
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open("fish11_inject.log")
            .expect("Failed to open log file");

        // TRACE LEVEL
        // This is the most verbose level, and will log all messages.
        // SECURITY RISK HERE !
        simple_logging::log_to(log_file, log::LevelFilter::Trace);

        info!("Ground zero : logger initialized !");
    }
}

/// Function to install all hooks
pub fn install_hooks() -> Result<(), io::Error> {
    info!("Installing Winsock hooks :");

    unsafe {
        // Dynamically resolve Winsock functions
        let recv_fn = std::mem::transmute::<FARPROC, RecvFn>(get_winsock_function("recv\0"));
        let send_fn = std::mem::transmute::<FARPROC, SendFn>(get_winsock_function("send\0"));
        let connect_fn =
            std::mem::transmute::<FARPROC, ConnectFn>(get_winsock_function("connect\0"));
        let closesocket_fn =
            std::mem::transmute::<FARPROC, ClosesocketFn>(get_winsock_function("closesocket\0"));

        // Install socket hooks
        install_socket_hook::<RecvFn>("recv", recv_fn, hooked_recv, &RECV_HOOK)?;
        install_socket_hook::<SendFn>("send", send_fn, hooked_send, &SEND_HOOK)?;
        install_socket_hook::<ConnectFn>("connect", connect_fn, hooked_connect, &CONNECT_HOOK)?;
        install_socket_hook::<ClosesocketFn>(
            "closesocket",
            closesocket_fn,
            hooked_closesocket,
            &CLOSESOCKET_HOOK,
        )?;

        // Install SSL hooks
        let ssl_read = std::mem::transmute::<FARPROC, SslReadFn>(find_ssl_function("SSL_read"));
        let ssl_write = std::mem::transmute::<FARPROC, SslWriteFn>(find_ssl_function("SSL_write"));
        let ssl_get_fd =
            std::mem::transmute::<FARPROC, SslGetFdFn>(find_ssl_function("SSL_get_fd"));
        let ssl_is_init_finished = std::mem::transmute::<FARPROC, SslIsInitFinishedProc>(
            find_ssl_function("SSL_is_init_finished"),
        );

        if ssl_read as usize == 0
            || ssl_write as usize == 0
            || ssl_get_fd as usize == 0
            || ssl_is_init_finished as usize == 0
        {
            error!(
                "One or more required SSL functions could not be found. Skipping SSL hook installation."
            );
        } else {
            match install_ssl_hooks(ssl_read, ssl_write, ssl_get_fd, ssl_is_init_finished) {
                Ok(_) => info!("All SSL hooks successfully installed !"),
                Err(e) => error!("Failed to install SSL hooks: {}", e),
            }
        }

        info!("All winsock hooks successfully installed !");
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
    match GenericDetour::<T>::new(original_fn, hook_fn) {
        Ok(hook) => {
            hook.enable().map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("  - failed to enable {}() hook: {:?}", hook_name, e),
                )
            })?;
            *hook_storage.lock().unwrap() = Some(hook);
            info!("  - {}() hook installed", hook_name);
            Ok(())
        }
        Err(e) => Err(io::Error::new(
            io::ErrorKind::Other,
            format!("  - failed to create {}() hook: {:?}", hook_name, e),
        )),
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
    let ws2_32 = GetModuleHandleA(b"ws2_32.dll\0".as_ptr() as _);
    if ws2_32.is_null() {
        panic!("Failed to get ws2_32.dll handle");
    }
    GetProcAddress(ws2_32, func_name.as_ptr() as _)
}

/// Helper to handle mutex poisoning
pub fn handle_poison<T>(err: PoisonError<T>) -> T {
    error!("Mutex poisoned: {}", err);
    err.into_inner()
}
