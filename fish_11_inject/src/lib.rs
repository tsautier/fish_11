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
use buffer_pool::BufferPool;
use dashmap::DashMap;
use engines::InjectEngines;
use fish_11_core::globals::{MIRC_HALT, MIRC_IDENTIFIER};
use once_cell::sync::Lazy;
use socket::info::SocketInfo;
use std::ffi::c_void;
use std::ptr::null_mut;
use std::sync::atomic::{AtomicBool, AtomicPtr};
use std::sync::{Arc, Mutex};
use windows::Win32::Foundation::HMODULE;

/// Global buffer pool for efficient memory management
pub static BUFFER_POOL: Lazy<Arc<BufferPool>> = Lazy::new(|| BufferPool::new());

/// Thread-safe socket tracking using DashMap for better concurrency
pub static ACTIVE_SOCKETS: Lazy<DashMap<u32, Arc<SocketInfo>>> = Lazy::new(DashMap::new);

pub(crate) static DISCARDED_SOCKETS: Lazy<Mutex<Vec<u32>>> = Lazy::new(|| Mutex::new(Vec::new()));
pub(crate) static ENGINES: Lazy<Mutex<Option<Arc<InjectEngines>>>> =
    Lazy::new(|| Mutex::new(None));
pub(crate) static DLL_HANDLE: AtomicPtr<c_void> = AtomicPtr::new(null_mut());
pub(crate) static MAX_MIRC_RETURN_BYTES: Lazy<Mutex<usize>> = Lazy::new(|| Mutex::new(4096));

/// Global flags
pub(crate) static LOADED: AtomicBool = AtomicBool::new(false);
static VERSION_SHOWN: AtomicBool = AtomicBool::new(false);

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
            DLL_HANDLE.store(h_module.0, std::sync::atomic::Ordering::Release);
            1
        }
        0 => {
            DLL_HANDLE.store(null_mut(), std::sync::atomic::Ordering::Release);
            LOADED.store(false, std::sync::atomic::Ordering::Release);
            1
        }
        2 | 3 | _ => 1,
    }
}
