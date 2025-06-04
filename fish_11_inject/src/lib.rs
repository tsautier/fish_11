/*
===============================================================================
  FiSH_11 Inject DLL - lib.rs
===============================================================================
  Main entry point for the FiSH_11 injection DLL for Windows (mIRC).

  Author: etc
  License: GNU GPL v3
  Date: 2025

1. Windows calls DllMain() when the DLL is loaded
2. mIRC calls LoadDll() in dll_interface.rs
===============================================================================
*/

// Here we define all the necessary imports and modules (files)
mod dll_interface;
mod engines;
mod helpers_inject;
mod hook_socket;
mod hook_ssl;
mod socket_info;
mod ssl_detection;
mod ssl_inline_patch;

use std::collections::HashMap;
use std::ffi::{c_int, c_void};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use engines::InjectEngines;
use lazy_static::lazy_static;
use log::{error, info};
use socket_info::SocketInfo;
use windows::Win32::Foundation::{BOOL, HMODULE, TRUE};
use windows::Win32::Networking::WinSock::SOCKET;

use crate::helpers_inject::{cleanup_hooks, init_logger};
use crate::ssl_inline_patch::{install_ssl_inline_patches, uninstall_ssl_inline_patches};

// Global state
lazy_static! {
    static ref ACTIVE_SOCKETS: Mutex<HashMap<u32, Arc<SocketInfo>>> = Mutex::new(HashMap::new());
    static ref DISCARDED_SOCKETS: Mutex<Vec<u32>> = Mutex::new(Vec::new());
    static ref ENGINES: Mutex<Option<Arc<InjectEngines>>> = Mutex::new(None);
    static ref DLL_HANDLE_PTR: Mutex<Option<HMODULE>> = Mutex::new(None);
    static ref MAX_MIRC_RETURN_BYTES: Mutex<usize> = Mutex::new(4096);
    static ref SOCKETS: RwLock<HashMap<SOCKET, Arc<Mutex<SocketInfo>>>> =
        RwLock::new(HashMap::new());
}

// C API version - Engine <-> Inject DLL contract
pub const FISH_INJECT_ENGINE_VERSION: u32 = 1;

// mIRC DLL exports
const _MIRC_RET_CONTINUE: i32 = 0;
const MIRC_RET_DATA_COMMAND: i32 = 1;
const _MIRC_RET_DATA_RETURN: i32 = 2;
const MIRC_HALT: c_int = 0;
#[allow(dead_code)]
const MIRC_CONTINUE: c_int = 1;
#[allow(dead_code)]
const MIRC_COMMAND: c_int = 2;

/// Get build information from VERGEN or use fallbacks
pub const FISH_11_BUILD_DATE: &str = match option_env!("VERGEN_BUILD_DATE") {
    Some(date) => date,
    None => env!("FISH_FALLBACK_DATE"),
};

/// Get build information from VERGEN or use fallbacks
pub const FISH_11_BUILD_TIME: &str = match option_env!("VERGEN_BUILD_TIME") {
    Some(time) => time,
    None => env!("FISH_FALLBACK_TIME"),
};

pub const FISH_11_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Complete version string with all information
pub const FISH_MAIN_VERSION: &str = env!("FISH_MAIN_VERSION");

/// Global flags
static LOADED: AtomicBool = AtomicBool::new(false);
static VERSION_SHOWN: AtomicBool = AtomicBool::new(false);
static LOGGER_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Version constants
pub const FISH_INJECT_VERSION: u32 = 11;

/*
===============================================================================
  DllMain - Windows DLL Entry Point
===============================================================================
  This is the main entry point for the FiSH_11 Inject DLL on Windows systems.

  - Called automatically by the OS when the DLL is loaded or unloaded.
  - Handles initialization (logging, state, hooks) on process attach.
  - Handles cleanup on process detach.
  - Stores the DLL module handle for later use.

  Parameters:
    h_module             - Handle to the DLL module instance.
    ul_reason_for_call   - Reason code for calling this function (attach/detach/etc).
    _                    - Reserved, unused pointer.

  Returns:
    TRUE (1) on success, always (no error handling here).

  Notes:
    - This is where the DLL lifecycle begins and ends.
    - Logging and hook setup/teardown are managed here.
    - See MSDN documentation for DllMain for more details.
===============================================================================
*/
/// Entry point for Windows DLL.
/// WE START HERE !
///
/// This function is called by Windows when the DLL is loaded or unloaded.
#[no_mangle]
#[allow(non_snake_case)]
extern "system" fn DllMain(h_module: HMODULE, ul_reason_for_call: u32, _: *mut c_void) -> BOOL {
    match ul_reason_for_call {
        1 => {
            // DLL_PROCESS_ATTACH
            // Store module handle
            *DLL_HANDLE_PTR.lock().unwrap() = Some(h_module);

            // Initialize logger
            init_logger();

            info!("***");
            info!(
                "FiSH_11 inject v{} (build date: {}, build time: {})",
                FISH_11_VERSION, FISH_11_BUILD_DATE, FISH_11_BUILD_TIME
            );
            info!("***");
            info!("The DLL is loaded successfully. Now it's time to h00k some calls baby !");

            // Install SSL hooks with error handling
            unsafe {
                if let Err(e) = install_ssl_inline_patches() {
                    error!("Failed to install SSL patches: {}", e);
                } else {
                    info!("SSL patches installed successfully");
                }
            }

            // Mark as loaded
            LOADED.store(true, Ordering::SeqCst);

            TRUE
        }
        0 => {
            // DLL_PROCESS_DETACH
            // Cleanup
            if LOADED.swap(false, Ordering::SeqCst) {
                info!("DllMain(): process is detaching. Cleaning up...");

                // Uninstall SSL hooks
                unsafe {
                    if let Err(e) = uninstall_ssl_inline_patches() {
                        error!("Failed to uninstall SSL patches: {}", e);
                    }
                }

                cleanup_hooks();
            }

            TRUE
        }
        _ => TRUE,
    }
}
