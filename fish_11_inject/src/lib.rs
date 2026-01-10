/*
===============================================================================
  FiSH_11 Inject DLL - lib.rs
===============================================================================
  Main entry point for the FiSH_11 injection DLL for Windows (mIRC).

  Author: GuY
  License: GNU GPL-v3
  Date: 2025-2026

1. Windows calls DllMain() when the DLL is loaded
2. mIRC calls LoadDll() in dll_interface.rs
===============================================================================
*/
#![cfg(windows)]
mod buffer_pool;
mod dll_interface;
mod engines;
mod helpers_inject;
mod hook_socket;
mod hook_ssl;
pub mod lock_utils;
mod pointer_validation;
pub mod socket;
mod ssl_detection;
pub mod ssl_mapping;
use crate::helpers_inject::{cleanup_hooks, init_logger};
use buffer_pool::BufferPool;
use dashmap::DashMap;
use engines::InjectEngines;
use fish_11_core::globals::{MIRC_HALT, MIRC_IDENTIFIER};
use lazy_static::lazy_static;
use log::{error, info, warn};
use once_cell::sync::Lazy;
use socket::info::SocketInfo;
use std::ffi::c_void;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use windows::Win32::Foundation::HMODULE;
use windows::Win32::System::Threading::GetCurrentThreadId;

#[derive(Clone, Copy)]
struct SendHMODULE(HMODULE);

unsafe impl Send for SendHMODULE {}
unsafe impl Sync for SendHMODULE {}

/// Global buffer pool for efficient memory management
pub static BUFFER_POOL: Lazy<Arc<BufferPool>> = Lazy::new(|| BufferPool::new());

/// Thread-safe socket tracking using DashMap for better concurrency
pub static ACTIVE_SOCKETS: Lazy<DashMap<u32, Arc<SocketInfo>>> = Lazy::new(DashMap::new);

lazy_static! {
    static ref DISCARDED_SOCKETS: Mutex<Vec<u32>> = Mutex::new(Vec::new());
    static ref ENGINES: Mutex<Option<Arc<InjectEngines>>> = Mutex::new(None);
    static ref DLL_HANDLE_PTR: Mutex<Option<SendHMODULE>> = Mutex::new(None);
    static ref MAX_MIRC_RETURN_BYTES: Mutex<usize> = Mutex::new(4096);
}

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
#[no_mangle]
pub unsafe extern "system" fn DllMain(
    h_module: HMODULE,
    ul_reason_for_call: u32,
    _: *mut c_void,
) -> i32 {
    match ul_reason_for_call {
        1 => {
            // DLL_PROCESS_ATTACH
            #[cfg(debug_assertions)]
            {
                // Initialize logger first so we can log everything
                if !LOGGER_INITIALIZED.load(Ordering::SeqCst) {
                    init_logger();
                }

                info!("=== DllMain : DLL_PROCESS_ATTACH ===");
                info!("DllMain() : h_module = {:?}", h_module);
            }

            // Initialize the engine container so other DLLs can register themselves.
            let engines_initialized = match ENGINES.lock() {
                Ok(mut engines) => {
                    if engines.is_none() {
                        match std::panic::catch_unwind(|| Arc::new(InjectEngines::new())) {
                            Ok(new_engines) => {
                                *engines = Some(new_engines);

                                #[cfg(debug_assertions)]
                                info!(
                                    "DllMain() : InjectEngines container initialized successfully."
                                );
                                true
                            }
                            Err(panic_err) => {
                                error!(
                                    "DllMain() : panic during InjectEngines creation: {:?}",
                                    panic_err
                                );
                                false
                            }
                        }
                    } else {
                        #[cfg(debug_assertions)]
                        info!("DllMain() : InjectEngines is already initialized.");
                        true
                    }
                }
                Err(e) => {
                    error!("DllMain() : failed to lock ENGINES to initialize: {}", e);
                    // Attempt to recover from poisoned lock
                    let mut engines = e.into_inner();

                    if engines.is_none() {
                        *engines = Some(Arc::new(InjectEngines::new()));
                        warn!("DllMain() : InjectEngines initialized after lock recovery.");
                    }
                    true
                }
            };

            // If ENGINES initialization failed, this is a critical error
            if !engines_initialized {
                error!(
                    "DllMain() : critical error - ENGINES initialization failed, DLL may not function properly"
                );
                // Continue loading but log the critical error
                // TODO : in production, we might want to return 0 here ?
            }

            // Store module handle
            #[cfg(debug_assertions)]
            info!("DllMain() : acquiring DLL_HANDLE_PTR lock...");

            match DLL_HANDLE_PTR.lock() {
                Ok(mut handle) => {
                    *handle = Some(SendHMODULE(h_module));

                    #[cfg(debug_assertions)]
                    info!("DllMain() : module handle stored successfully");
                }
                Err(e) => {
                    error!("DllMain() : failed to lock DLL_HANDLE_PTR: {}", e);
                    return 0; // Return FALSE
                }
            }

            #[cfg(debug_assertions)]
            info!("DllMain() : initializing logger (if not already done)...");

            init_logger();

            #[cfg(debug_assertions)]
            info!("***");
            #[cfg(debug_assertions)]
            info!(
                "FiSH_11 inject v{} (build date : {}, build time : {} Z)",
                fish_11_core::globals::CRATE_VERSION,
                fish_11_core::globals::BUILD_DATE.as_str(),
                fish_11_core::globals::BUILD_TIME.as_str()
            );
            #[cfg(debug_assertions)]
            info!("***");
            #[cfg(debug_assertions)]
            info!("The DLL is loaded successfully. Now it's time to h00k some calls bayby !");

            #[cfg(debug_assertions)]
            info!("DllMain() : and how about to install SSL patches ?");

            #[cfg(debug_assertions)]
            info!("DllMain() : setting LOADED flag to true...");

            // Mark as loaded
            LOADED.store(true, Ordering::SeqCst);

            #[cfg(debug_assertions)]
            info!("=== DllMain() : DLL_PROCESS_ATTACH completed successfully ===");

            1
        }
        0 => {
            // DLL_PROCESS_DETACH
            #[cfg(debug_assertions)]
            info!("=== DllMain() : DLL_PROCESS_DETACH ===");

            // Cleanup
            if LOADED.swap(false, Ordering::SeqCst) {
                #[cfg(debug_assertions)]
                info!("DllMain() : process is detaching. Cleaning up...");

                #[cfg(debug_assertions)]
                info!("DllMain() : uninstalling SSL patches...");

                #[cfg(debug_assertions)]
                info!("DllMain : cleaning up hooks...");

                cleanup_hooks();

                #[cfg(debug_assertions)]
                info!("DllMain() : cleanup complete");
            } else {
                #[cfg(debug_assertions)]
                info!("DllMain() : DLL was not loaded, skipping cleanup");
            }

            #[cfg(debug_assertions)]
            info!("=== DllMain() : DLL_PROCESS_DETACH completed ===");

            1
        }
        2 => {
            // DLL_THREAD_ATTACH
            #[cfg(debug_assertions)]
            {
                let thread_id = GetCurrentThreadId();

                #[cfg(debug_assertions)]
                info!(
                    "DllMain() : DLL_THREAD_ATTACH - a new thread is being created (Thread ID: {}).",
                    thread_id
                );
            }
            1
        }
        3 => {
            // DLL_THREAD_DETACH
            #[cfg(debug_assertions)]
            {
                let thread_id = GetCurrentThreadId();
                info!(
                    "DllMain() : DLL_THREAD_DETACH - a thread is exiting cleanly (Thread ID: {}).",
                    thread_id
                );
            }
            1
        }
        _ => {
            #[cfg(debug_assertions)]
            info!("DllMain() : unknown reason code: {}", ul_reason_for_call);
            1
        }
    }
}
