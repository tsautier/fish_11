use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::dll_interface::{
    CString, MIRC_HALT, MIRC_IDENTIFIER, c_char, c_int, get_buffer_size, ptr,
};

/// This function avoids complex string manipulation and focuses on safely
/// returning a valid path to the caller. It provides:
///   1. Comprehensive panic handling to prevent crashes
///   2. Simplified string handling to avoid UTF-8 conversion issues
///   3. Fallback mechanisms for various error scenarios
///   4. Detailed logging for diagnostic purposes
#[no_mangle]
#[allow(non_snake_case)]
pub extern "stdcall" fn FiSH11_GetConfigPath(
    _m_wnd: HWND,
    _a_wnd: HWND,
    data: *mut c_char,
    _parms: *mut c_char,
    _show: BOOL,
    _nopause: BOOL,
) -> c_int {
    // Log function entry with structured logging
    crate::logging::log_function_entry("FiSH11_GetConfigPath", Some("SAFE VERSION"));

    // Create a unique trace ID to help track this call through logs
    let trace_id = format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    );

    // Get buffer size for safety checks
    let buffer_size = get_buffer_size();

    // Log startup info
    log::info!("FiSH11_GetConfigPath[{}]: Starting with buffer size {}", trace_id, buffer_size);

    // Null pointer check
    if data.is_null() {
        log::error!("FiSH11_GetConfigPath[{}]: Data pointer is null", trace_id);
        return MIRC_HALT;
    }

    // Use a panic handler to prevent any crashes
    let result = std::panic::catch_unwind(|| {
        // First try to get the config path through the normal method
        log::debug!("FiSH11_GetConfigPath[{}]: Attempting to get config path", trace_id);
        match std::panic::catch_unwind(|| crate::config::get_config_path()) {
            Ok(path_result) => {
                match path_result {
                    Ok(path) => {
                        // Successfully got the path
                        log::info!(
                            "FiSH11_GetConfigPath[{}]: Got path: {}",
                            trace_id,
                            path.display()
                        );

                        // Use a hardcoded safe string that's guaranteed to fit and convert correctly
                        // This avoids all the potential UTF-8 and string manipulation issues
                        let path_str = path.to_string_lossy();
                        log::info!(
                            "FiSH11_GetConfigPath[{}]: Path as string: {}",
                            trace_id,
                            path_str
                        );

                        // Create a CString with extra safety
                        let c_str = match CString::new(path_str.as_bytes()) {
                            Ok(s) => s,
                            Err(_) => {
                                log::error!(
                                    "FiSH11_GetConfigPath[{}]: Failed to create CString from path",
                                    trace_id
                                );
                                // Fall back to a known-good string
                                CString::new("fish_11.ini (Error: Invalid characters in path)")
                                    .unwrap()
                            }
                        };
                        // Safely write to the buffer
                        let bytes = c_str.as_bytes_with_nul();
                        let copy_len = bytes.len().min(buffer_size - 1);

                        log::debug!(
                            "FiSH11_GetConfigPath[{}]: Preparing to write {} bytes to buffer",
                            trace_id,
                            copy_len
                        );

                        unsafe {
                            // Clear buffer first
                            ptr::write_bytes(data as *mut u8, 0, buffer_size);
                            // Copy the data
                            ptr::copy_nonoverlapping(bytes.as_ptr(), data as *mut u8, copy_len);
                            // Ensure null termination
                            *data.add(copy_len - 1) = 0;
                        }

                        log::info!(
                            "FiSH11_GetConfigPath[{}]: Successfully returned path",
                            trace_id
                        );
                    }
                    Err(e) => {
                        log::error!(
                            "FiSH11_GetConfigPath[{}]: Error getting config path: {:?}",
                            trace_id,
                            e
                        ); // Create a simple fallback message
                        let fallback = CString::new("Error: Could not determine config path")
                            .expect("Failed to create config path error message");
                        let bytes = fallback.as_bytes_with_nul();
                        let copy_len = bytes.len().min(buffer_size - 1);

                        log::debug!(
                            "FiSH11_GetConfigPath[{}]: Writing error message to buffer (length {})",
                            trace_id,
                            copy_len
                        );

                        unsafe {
                            // Clear buffer
                            ptr::write_bytes(data as *mut u8, 0, buffer_size);
                            // Copy fallback message
                            ptr::copy_nonoverlapping(bytes.as_ptr(), data as *mut u8, copy_len);
                            // Ensure null termination
                            *data.add(copy_len - 1) = 0;
                        }
                    }
                }
            }
            Err(e) => {
                log::error!(
                    "FiSH11_GetConfigPath[{}]: Panic in get_config_path: {:?}",
                    trace_id,
                    e
                );

                // Get panic info if possible
                let panic_message = if let Some(s) = e.downcast_ref::<&str>() {
                    format!("Panic message: {}", s)
                } else if let Some(s) = e.downcast_ref::<String>() {
                    format!("Panic message: {}", s)
                } else {
                    "Unknown panic type".to_string()
                };
                log::error!("FiSH11_GetConfigPath[{}]: {}", trace_id, panic_message);
                // Create an error message
                let error_msg = CString::new("Error: Internal error while getting config path")
                    .expect("Failed to create internal error message");
                let bytes = error_msg.as_bytes_with_nul();
                let copy_len = bytes.len().min(buffer_size - 1);

                log::debug!(
                    "FiSH11_GetConfigPath[{}]: Writing panic error message to buffer (length {})",
                    trace_id,
                    copy_len
                );

                unsafe {
                    // Clear buffer
                    ptr::write_bytes(data as *mut u8, 0, buffer_size);
                    // Copy error message
                    ptr::copy_nonoverlapping(bytes.as_ptr(), data as *mut u8, copy_len);
                    // Ensure null termination
                    *data.add(copy_len - 1) = 0;

                    // Log first few bytes for verification
                    if copy_len > 0 {
                        let preview_len = copy_len.min(16);
                        let preview: Vec<u8> =
                            std::slice::from_raw_parts(data as *const u8, preview_len).to_vec();
                        log::debug!(
                            "FiSH11_GetConfigPath[{}]: First {} bytes: {:02X?}",
                            trace_id,
                            preview_len,
                            preview
                        );
                    }
                }
            }
        }
    });
    // Handle any panics in our function
    if result.is_err() {
        log::error!("FiSH11_GetConfigPath[{}]: Panic in outer function handler", trace_id); // Create fallback message for worst-case scenario
        let panic_msg = CString::new("Critical error in config path retrieval")
            .expect("Failed to create panic message");

        unsafe {
            // Write the message as safely as possible
            if !data.is_null() {
                ptr::write_bytes(data as *mut u8, 0, buffer_size);
                let bytes = panic_msg.as_bytes_with_nul();
                let safe_len = bytes.len().min(buffer_size - 1);
                ptr::copy_nonoverlapping(bytes.as_ptr(), data as *mut u8, safe_len);
                *data.add(safe_len - 1) = 0;

                // Log what we wrote
                log::debug!(
                    "FiSH11_GetConfigPath[{}]: Wrote fallback error message to buffer",
                    trace_id
                );
            }
        }
    }

    log::info!("FiSH11_GetConfigPath[{}]: Function completed successfully", trace_id);
    crate::logging::log_function_exit("FiSH11_GetConfigPath", Some(MIRC_IDENTIFIER));
    MIRC_IDENTIFIER
}
