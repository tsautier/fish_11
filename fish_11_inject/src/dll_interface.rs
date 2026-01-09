use std::ffi::{CString, c_char, c_int};
use std::sync::atomic::Ordering;

// use fish_11_core::buffer_utils::write_cstring_to_buffer; // Removed as mIRC LoadDll doesn't support returned data
use fish_11_core::globals::{
    BUILD_DATE, BUILD_NUMBER, BUILD_TIME, BUILD_VERSION, MIRC_RETURN_DATA_COMMAND,
};
use log::{debug, error, info, warn};
use windows::Win32::Foundation::{HMODULE, HWND};
use windows::Win32::UI::WindowsAndMessaging::{MB_ICONEXCLAMATION, MB_OK, MessageBoxW};

use crate::helpers_inject::install_hooks;
use crate::{
    ACTIVE_SOCKETS, DISCARDED_SOCKETS, DLL_HANDLE_PTR, ENGINES, LOADED, MAX_MIRC_RETURN_BYTES,
    MIRC_COMMAND, MIRC_HALT, MIRC_IDENTIFIER, VERSION_SHOWN, cleanup_hooks,
};

#[repr(C)]
pub struct LOADINFO {
    pub m_version: u32, // mVersion (DWORD)
    pub m_hwnd: HWND,   // mHwnd (HWND)
    pub m_keep: i32,    // mKeep (BOOL)
    pub m_unicode: i32, // mUnicode (BOOL)
    pub m_beta: u32,    // mBeta (DWORD)
    pub m_bytes: u32,   // mBytes (DWORD)
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
        error!("LoadDll() : loadinfo pointer is NULL - aborting");
        return MIRC_HALT; // Indicate failure
    }

    #[cfg(debug_assertions)]
    info!("LoadDll() : loadinfo pointer is valid: {:?}", loadinfo);

    let li = unsafe { &mut *loadinfo };

    #[cfg(debug_assertions)]
    info!(
        "LoadDll() : LOADINFO fields - version: {}, unicode: {}, m_bytes: {}",
        li.m_version, li.m_unicode, li.m_bytes
    );

    #[cfg(debug_assertions)]
    info!("LoadDll() : acquiring MAX_MIRC_RETURN_BYTES lock...");

    // Store max return bytes (corrected type usage)
    let mut max_bytes_guard = match MAX_MIRC_RETURN_BYTES.lock() {
        Ok(guard) => {
            #[cfg(debug_assertions)]
            info!("LoadDll() : MAX_MIRC_RETURN_BYTES lock acquired");
            guard
        }
        Err(e) => {
            error!("LoadDll() : failed to lock MAX_MIRC_RETURN_BYTES: {}", e);
            return MIRC_HALT;
        }
    };

    // m_bytes is u32, MAX_MIRC_RETURN_BYTES is Mutex<usize>
    *max_bytes_guard = li.m_bytes as usize;

    // copy value for logging after drop
    let max_len = *max_bytes_guard;
    drop(max_bytes_guard); // Release lock

    #[cfg(debug_assertions)]
    info!("LoadDll() : MAX_MIRC_RETURN_BYTES set to {}", max_len);

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
        info!("LoadDll() : displaying version warning MessageBox...");

        unsafe {
            MessageBoxW(
                Some(li.m_hwnd),
                windows::core::w!("Warning: this FiSH_11 version may require mIRC 7.0 or newer."),
                windows::core::w!("FiSH_11 injection warning"),
                MB_ICONEXCLAMATION | MB_OK,
            );
        }

        #[cfg(debug_assertions)]
        info!("LoadDll() : MessageBox closed");
    }

    // Setup hooks via install_hooks()
    info!("Setting up socket hooks...");

    #[cfg(debug_assertions)]
    info!("LoadDll() : Calling install_hooks()...");

    if let Err(e) = install_hooks() {
        error!("Failed to set up Winsock hooks: {}", e);

        #[cfg(debug_assertions)]
        error!("LoadDll() : install_hooks() failed with error: {}", e);

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
        error!("LoadDll() : returning MIRC_HALT due to hook installation failure");

        return MIRC_HALT; // Indicate failure
    }

    #[cfg(debug_assertions)]
    info!("LoadDll() : install_hooks() completed successfully");

    #[cfg(debug_assertions)]
    info!("LoadDll() : checking VERSION_SHOWN flag...");

    // Show version info once if not already shown
    if !VERSION_SHOWN.swap(true, Ordering::Relaxed) {
        #[cfg(debug_assertions)]
        info!("LoadDll() : first load, preparing version message...");

        // Prepare version string as a command
        let version_cmd = format!("*** FiSH_11 inject v{} loaded successfully. ***", BUILD_VERSION);

        // Removed logic attempting to write to m_filename as mIRC LOADINFO does not have a filename/data buffer.
        // We rely on scripts calling FiSH11_InjectVersion explicitly or debug info.
        info!("Version info: {}", version_cmd);
    } else {
        #[cfg(debug_assertions)]
        info!("LoadDll() : VERSION_SHOWN already true, skipping version message");
    }

    info!("=== LoadDll() finished successfully ===");

    #[cfg(debug_assertions)]
    info!("LoadDll() : setting m_keep = 1 to keep DLL loaded");

    // Tell mIRC to keep the DLL loaded
    li.m_keep = 1;

    #[cfg(debug_assertions)]
    info!("=== LoadDll() : returning MIRC_HALT (success) ===");

    MIRC_HALT // Return 0 for success
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn UnloadDll(action: c_int) -> c_int {
    info!("UnloadDll() called with action: {}", action); // 0=Script unload, 1=Not being used for 10 mins, 2=mIRC exit

    if action == 1 {
        // mIRC is asking if we should stay loaded when not used for 10 minutes
        // We return 0 to keep the DLL loaded (same behavior as FiSH-10)
        info!("UnloadDll() : action=1, keeping DLL loaded to maintain socket hooks");
        return 0; // Return 0 to keep DLL loaded
    } else {
        // Perform cleanup on explicit unload (0) or mIRC exit (2)
        info!("UnloadDll() : performing cleanup for action={}", action);
        cleanup_hooks();

        // Clear global state carefully
        match ENGINES.lock() {
            Ok(mut engines) => {
                *engines = None;
            }
            Err(e) => {
                error!("UnloadDll() : failed to lock ENGINES for cleanup: {}", e);
                // Attempt to recover from poisoned lock
                let mut engines = e.into_inner();
                *engines = None;
            }
        }

        match DLL_HANDLE_PTR.lock() {
            Ok(mut handle) => {
                *handle = None;
            }
            Err(e) => {
                error!("UnloadDll() : failed to lock DLL_HANDLE_PTR for cleanup: {}", e);
                // Attempt to recover
                drop(e.into_inner());
            }
        }
        LOADED.store(false, Ordering::SeqCst);
        VERSION_SHOWN.store(false, Ordering::Relaxed);
        // HOOKS_INSTALLED should be false after cleanup_hooks

        info!("UnloadDll() : finished cleanup.");
    }

    MIRC_HALT // Return 0 for success when actually unloading
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

    // Collect socket statistics (DashMap - thread-safe iteration)
    let num_sockets = ACTIVE_SOCKETS.len();

    //let discarded = DISCARDED_SOCKETS.load(Ordering::Relaxed);
    let discarded = DISCARDED_SOCKETS.lock().unwrap().len();

    // Get statistics from all sockets (DashMap iter is thread-safe)
    let mut stats = String::new();
    for entry in ACTIVE_SOCKETS.iter() {
        stats.push_str(&entry.value().get_stats());
        stats.push(' ');

        // Limit size to avoid buffer issues
        if stats.len() > 700 {
            stats.truncate(700);
            stats.push_str("...");
            break;
        }
    }

    // Get engine list
    let engine_list = match ENGINES.lock() {
        Ok(engines) => {
            if let Some(ref engines_ref) = *engines {
                engines_ref.get_engine_list()
            } else {
                String::from("no engines")
            }
        }
        Err(e) => {
            error!("FiSH11_InjectDebugInfo() : failed to lock ENGINES: {}", e);
            // Attempt to recover from poisoned lock
            let engines = e.into_inner();
            if let Some(ref engines_ref) = *engines {
                engines_ref.get_engine_list()
            } else {
                String::from("no engines (recovered from poisoned lock)")
            }
        }
    };

    let command = format!(
        "*** FiSH11_InjectDebugInfo() : Sockets : Active {} - Discarded {} - {} - Engines: {}",
        num_sockets,
        discarded,
        if stats.is_empty() { "none" } else { &stats },
        engine_list
    );

    let c_command = CString::new(command).expect("Failed to create command string");

    #[cfg(debug_assertions)]
    {
        debug!("[DLL_INTERFACE DEBUG] FiSH11_InjectDebugInfo() : preparing command buffer");
        debug!(
            "[DLL_INTERFACE DEBUG] FiSH11_InjectDebugInfo() : command length: {} bytes (max_bytes: {})",
            c_command.as_bytes().len(),
            max_bytes
        );
        debug!(
            "[DLL_INTERFACE DEBUG] FiSH11_InjectDebugInfo() : command preview: {:?}",
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
                "[DLL_INTERFACE DEBUG] FiSH11_InjectDebugInfo() : copied {} bytes to mIRC data buffer, null-terminated.",
                copied_len
            );
        }
    }

    // Return as mIRC command to execute
    MIRC_RETURN_DATA_COMMAND
}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn FiSH11_InjectVersion(
    _m_wnd: *mut HWND,
    _a_wnd: *mut HWND,
    data: *mut c_char,
    _parms: *mut c_char,
    _show: *mut c_int,
    _nopause: *mut c_int,
) -> c_int {
    // Return raw version info (script handles display formatting)
    let version_info = format!(
        "FiSH injection dll version {} (build {}). *** Compiled on {} at {} *** Written by [GuY], licensed under the GPL-v3 or above.",
        BUILD_VERSION,
        BUILD_NUMBER.as_str(),
        BUILD_DATE.as_str(),
        BUILD_TIME.as_str()
    );

    let data_str = match CString::new(version_info) {
        Ok(s) => s,
        Err(e) => {
            error!("FiSH11_InjectVersion() : failed to create CString: {}", e);
            return MIRC_HALT;
        }
    };

    #[cfg(debug_assertions)]
    {
        debug!("[DLL_INTERFACE DEBUG] FiSH11_InjectVersion() : preparing version data buffer");
        debug!(
            "[DLL_INTERFACE DEBUG] FiSH11_InjectVersion() : data length: {} bytes",
            data_str.as_bytes_with_nul().len()
        );
        debug!(
            "[DLL_INTERFACE DEBUG] FiSH11_InjectVersion() : data preview : {:?}",
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
                    "[DLL_INTERFACE DEBUG] FiSH11_InjectVersion() : MAX_MIRC_RETURN_BYTES : {}, src_len: {}, copy_len: {}",
                    max_bytes, src_len, copy_len
                );
            }

            std::ptr::copy_nonoverlapping(src, data, copy_len);
            *data.add(copy_len) = 0;

            #[cfg(debug_assertions)]
            {
                debug!(
                    "[DLL_INTERFACE DEBUG] FiSH11_InjectVersion() : copied {} bytes to mIRC data buffer, null-terminated.",
                    copy_len
                );
            }

            info!("FiSH11_InjectVersion() : returned version info (len {})", copy_len);
        } else {
            error!("FiSH11_InjectVersion() : data buffer pointer is null.");
            return MIRC_HALT;
        }
    }

    MIRC_IDENTIFIER
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_loadinfo_struct_size() {
        // Just verify that our LOADINFO struct has the expected fields
        let load_info = LOADINFO {
            m_unicode: 0,
            m_version: 700,
            m_hwnd: HWND::default(),
            m_keep: 0,
            m_bytes: 4096,
            m_beta: 0,
        };

        // Test that we can create a LOADINFO struct (compile-time check)
        assert_eq!(load_info.m_version, 700);
        assert_eq!(load_info.m_bytes, 4096);
    }
}
