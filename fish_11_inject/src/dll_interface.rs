use std::ffi::{CString, c_char};
use std::sync::atomic::Ordering;

use fish_11_core::buffer_utils::write_cstring_to_buffer;
use log::{debug, error, info, warn};
use winapi::shared::minwindef::BOOL;
use windows::Win32::Foundation::{HMODULE, HWND};
use windows::Win32::UI::WindowsAndMessaging::{MB_ICONEXCLAMATION, MB_OK, MessageBoxW};

use crate::helpers_inject::install_hooks;
use crate::{
    ACTIVE_SOCKETS, DISCARDED_SOCKETS, DLL_HANDLE_PTR, ENGINES, LOADED, MAX_MIRC_RETURN_BYTES, MIRC_COMMAND, MIRC_HALT,
    MIRC_RET_DATA_COMMAND, VERSION_SHOWN, c_int, cleanup_hooks,
};
use fish_11_core::globals::{BUILD_DATE, BUILD_TIME, BUILD_VERSION};

#[repr(C)]
pub struct LOADINFO {
    pub m_unicode: i32,
    pub m_version: i32,
    pub m_hwnd: HWND,
    pub m_filename: *mut i8,
    pub m_keep: i32,
    pub m_bytes: u32,
}

#[no_mangle]
#[allow(non_snake_case)]
/// Entry point for mIRC to load the DLL
/// This function is called by mIRC, under this name.
///
/// So this is the second entry point after DllMain().
pub extern "stdcall" fn LoadDll(loadinfo: *mut LOADINFO) -> c_int {
    #[cfg(debug_assertions)]
    info!("=== LoadDll: function called ===");

    // Safety check
    if loadinfo.is_null() {
        error!("LoadDll() called with NULL loadinfo!");
        #[cfg(debug_assertions)]
        error!("LoadDll: loadinfo pointer is NULL - aborting");
        return MIRC_HALT; // Indicate failure
    }

    #[cfg(debug_assertions)]
    info!("LoadDll: loadinfo pointer is valid: {:?}", loadinfo);

    let li = unsafe { &mut *loadinfo };

    #[cfg(debug_assertions)]
    info!(
        "LoadDll: LOADINFO fields - version: {}, unicode: {}, m_bytes: {}",
        li.m_version, li.m_unicode, li.m_bytes
    );

    #[cfg(debug_assertions)]
    info!("LoadDll: acquiring MAX_MIRC_RETURN_BYTES lock...");

    // Store max return bytes (corrected type usage)
    let mut max_bytes_guard = match MAX_MIRC_RETURN_BYTES.lock() {
        Ok(guard) => {
            #[cfg(debug_assertions)]
            info!("LoadDll: MAX_MIRC_RETURN_BYTES lock acquired");
            guard
        }
        Err(e) => {
            error!("LoadDll: failed to lock MAX_MIRC_RETURN_BYTES: {}", e);
            return MIRC_HALT;
        }
    };

    // m_bytes is u32, MAX_MIRC_RETURN_BYTES is Mutex<usize>
    *max_bytes_guard = li.m_bytes as usize;

    // copy value for logging after drop
    let max_len = *max_bytes_guard;
    drop(max_bytes_guard); // Release lock

    #[cfg(debug_assertions)]
    info!("LoadDll: MAX_MIRC_RETURN_BYTES set to {}", max_len);

    info!(
        "=== LoadDll() called. mIRC version: {}, Unicode: {}, MaxBytes: {} === ",
        li.m_version, li.m_unicode, max_len
    );

    // Check minimum mIRC version if needed
    if li.m_version < 700 {
        warn!(
            "br0, your mIRC version {} is quite old, compatibility not guaranteed !",
            li.m_version
        );

        #[cfg(debug_assertions)]
        info!("LoadDll: Displaying version warning MessageBox...");

        unsafe {
            MessageBoxW(
                Some(li.m_hwnd),
                windows::core::w!("Warning: this FiSH_11 version may require mIRC 7.0 or newer."),
                windows::core::w!("FiSH_11 injection warning"),
                MB_ICONEXCLAMATION | MB_OK,
            );
        }

        #[cfg(debug_assertions)]
        info!("LoadDll: MessageBox closed");
    }

    // Setup hooks via install_hooks()
    info!("Setting up socket hooks...");

    #[cfg(debug_assertions)]
    info!("LoadDll: Calling install_hooks()...");

    if let Err(e) = install_hooks() {
        error!("Failed to set up Winsock hooks: {}", e);

        #[cfg(debug_assertions)]
        error!("LoadDll: install_hooks() failed with error: {}", e);

        unsafe {
            MessageBoxW(
                Some(li.m_hwnd),
                windows::core::w!(
                    "FiSH_11 inject error: failed to install necessary Winsock hooks. DLL will unload now."
                ),
                windows::core::w!("FiSH_11 Inject error"),
                MB_ICONEXCLAMATION | MB_OK,
            );
        }
        li.m_keep = 0; // Tell mIRC to unload us

        #[cfg(debug_assertions)]
        error!("LoadDll: returning MIRC_HALT due to hook installation failure");

        return MIRC_HALT; // Indicate failure
    }

    #[cfg(debug_assertions)]
    info!("LoadDll: install_hooks() completed successfully");

    #[cfg(debug_assertions)]
    info!("LoadDll: installing SSL inline patches...");

    #[cfg(debug_assertions)]
    info!("LoadDll: SSL inline patches installation completed");

    #[cfg(debug_assertions)]
    info!("LoadDll: checking VERSION_SHOWN flag...");

    // Show version info once if not already shown
    if !VERSION_SHOWN.swap(true, Ordering::Relaxed) {
        #[cfg(debug_assertions)]
        info!("LoadDll: first load, preparing version message...");

        // Prepare version string as a command
        let version_cmd =
            format!("/echo -ts *** FiSH_11 inject v{} loaded successfully. ***", BUILD_VERSION);
        if let Ok(c_cmd) = CString::new(version_cmd) {
            let current_max_len = *MAX_MIRC_RETURN_BYTES.lock().unwrap();
            if c_cmd.as_bytes_with_nul().len() <= current_max_len {
                unsafe {
                    write_cstring_to_buffer(li.m_filename, current_max_len, &c_cmd);
                }
                info!("Success message written to mIRC buffer: {}", c_cmd.to_str().unwrap());
                li.m_keep = 1;
                return MIRC_COMMAND;
            } else {
                warn!("Version info command too long for mIRC buffer.");
                #[cfg(debug_assertions)]
                warn!(
                    "LoadDll: version command too long (len: {} > max: {})",
                    c_cmd.as_bytes_with_nul().len(),
                    current_max_len
                );
            }
        } else {
            #[cfg(debug_assertions)]
            error!("LoadDll: failed to create CString for version command");
        }
    } else {
        #[cfg(debug_assertions)]
        info!("LoadDll: VERSION_SHOWN already true, skipping version message");
    }

    info!("=== LoadDll() finished successfully ===");

    #[cfg(debug_assertions)]
    info!("LoadDll: setting m_keep = 1 to keep DLL loaded");

    // Tell mIRC to keep the DLL loaded
    li.m_keep = 1;

    #[cfg(debug_assertions)]
    info!("=== LoadDll: returning MIRC_HALT (success) ===");

    MIRC_HALT // Return 0 for success
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn UnloadDll(action: c_int) -> c_int {
    info!("UnloadDll() called with action: {}", action); // 0=Script unload, 1=mIRC exit, 2=DLL crash unload

    // Perform cleanup regardless of action type
    cleanup_hooks();

    // Clear global state carefully
    *ENGINES.lock().unwrap() = None;
    *DLL_HANDLE_PTR.lock().unwrap() = None;
    LOADED.store(false, Ordering::SeqCst);
    VERSION_SHOWN.store(false, Ordering::Relaxed);
    // HOOKS_INSTALLED should be false after cleanup_hooks

    info!("UnloadDll() finished cleanup.");
    MIRC_HALT // Return 0 for success
}

// Debug info function
#[no_mangle]
pub extern "C" fn FiSH11_InjectDebugInfo(
    _hwnd: HWND,
    _hinst: HMODULE,
    data: *mut i8,
    _parms: *mut i8,
    _show: i32,
    _nopause: i32,
) -> i32 {
    let max_bytes = *MAX_MIRC_RETURN_BYTES.lock().unwrap();

    // Collect socket statistics
    let sockets = ACTIVE_SOCKETS.lock().unwrap();

    let num_sockets = sockets.len();

    //let discarded = DISCARDED_SOCKETS.load(Ordering::Relaxed);
    let discarded = DISCARDED_SOCKETS.lock().unwrap().len();

    // Get statistics from all sockets
    let mut stats = String::new();
    for (_, socket) in sockets.iter() {
        stats.push_str(&socket.get_stats());
        stats.push(' ');

        // Limit size to avoid buffer issues
        if stats.len() > 700 {
            stats.truncate(700);
            stats.push_str("...");
            break;
        }
    }

    // Get engine list
    let engines = ENGINES.lock().unwrap();
    let engine_list = if let Some(ref engines_ref) = *engines {
        engines_ref.get_engine_list()
    } else {
        String::from("no engines")
    };

    let command = format!(
        "/echo -a *** Sockets: Active {} - Discarded {} - {} - Engines: {}",
        num_sockets,
        discarded,
        if stats.is_empty() { "none" } else { &stats },
        engine_list
    );

    let c_command = CString::new(command).expect("Failed to create command string");

    #[cfg(debug_assertions)]
    {
        debug!("[DLL_INTERFACE DEBUG] FiSH11_InjectDebugInfo: preparing command buffer");
        debug!(
            "[DLL_INTERFACE DEBUG] command length: {} bytes (max_bytes: {})",
            c_command.as_bytes().len(),
            max_bytes
        );
        debug!(
            "[DLL_INTERFACE DEBUG] command preview: {:?}",
            c_command.to_str().unwrap_or("<invalid UTF-8>")
        );
    }

    unsafe {
        // Copy to output buffer safely
        let src = c_command.as_ptr();
        let src_len = c_command.as_bytes().len();
        std::ptr::copy_nonoverlapping(src, data, std::cmp::min(src_len, max_bytes as usize - 1));

        // Null terminate
        *data.add(std::cmp::min(src_len, max_bytes as usize - 1)) = 0;

        #[cfg(debug_assertions)]
        {
            let copied_len = std::cmp::min(src_len, max_bytes as usize - 1);
            debug!(
                "[DLL_INTERFACE DEBUG] copied {} bytes to mIRC data buffer, null-terminated",
                copied_len
            );
        }
    }

    // Return as mIRC command to execute
    MIRC_RET_DATA_COMMAND
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn FiSH11_InjectVersion(
    _m_wnd: *mut HWND,
    _a_wnd: *mut HWND,
    data: *mut c_char,
    _parms: *mut c_char,
    _show: *mut BOOL,
    _nopause: *mut BOOL,
) -> c_int {
    // Return raw version info (script handles display formatting)
    let version_info = format!(
        "FiSH injection dll version {}. *** Compiled on {} at {} *** Written by [GuY], licensed under the GPL-v3",
        BUILD_VERSION, BUILD_DATE, BUILD_TIME
    );

    let data_str = match CString::new(version_info) {
        Ok(s) => s,
        Err(e) => {
            error!("FiSH11_InjectVersion: failed to create CString: {}", e);
            return MIRC_HALT;
        }
    };

    #[cfg(debug_assertions)]
    {
        debug!("[DLL_INTERFACE DEBUG] FiSH11_InjectVersion: preparing version data buffer");
        debug!("[DLL_INTERFACE DEBUG] data length: {} bytes", data_str.as_bytes_with_nul().len());
        debug!(
            "[DLL_INTERFACE DEBUG] data preview: {:?}",
            data_str.to_str().unwrap_or("<invalid UTF-8>")
        );
    }

    unsafe {
        if !data.is_null() {
            let max_bytes = *MAX_MIRC_RETURN_BYTES.lock().unwrap();
            let src = data_str.as_ptr();
            let src_len = data_str.as_bytes_with_nul().len();
            let copy_len = std::cmp::min(src_len, max_bytes as usize - 1);

            #[cfg(debug_assertions)]
            {
                debug!(
                    "[DLL_INTERFACE DEBUG] MAX_MIRC_RETURN_BYTES: {}, src_len: {}, copy_len: {}",
                    max_bytes, src_len, copy_len
                );
            }

            std::ptr::copy_nonoverlapping(src, data, copy_len);
            *data.add(copy_len) = 0;

            #[cfg(debug_assertions)]
            {
                debug!(
                    "[DLL_INTERFACE DEBUG] copied {} bytes to mIRC data buffer, null-terminated",
                    copy_len
                );
            }

            info!("FiSH11_Inject: returned version info (len {})", copy_len);
        } else {
            error!("FiSH11_Inject: data buffer pointer is null");
            return MIRC_HALT;
        }
    }

    MIRC_COMMAND
}
