use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::buffer_utils::write_string_to_buffer;
use crate::dll_function_utils::{DllFunctionContext, DllResult, dll_function_wrapper};
use crate::dll_interface::{c_char, c_int};

/// Lists all stored encryption keys in a formatted output for mIRC
///
/// This function retrieves all stored keys from the configuration file and formats them
/// into a series of mIRC /echo commands that display:
/// - The initialization time of the configuration
/// - Each stored key with its associated nickname, network (if available), and creation date
/// - Proper formatting with separators for readability
#[no_mangle]
#[allow(non_snake_case)]
pub extern "stdcall" fn FiSH11_FileListKeys(
    _m_wnd: HWND,
    _a_wnd: HWND,
    data: *mut c_char,
    _parms: *mut c_char,
    _show: BOOL,
    _nopause: BOOL,
) -> c_int {
    dll_function_wrapper(data, "FiSH11_FileListKeys", |data, ctx| {
        fish11_filelistkeys_impl(data, ctx)
    })
}

fn fish11_filelistkeys_impl(data: *mut c_char, ctx: &DllFunctionContext) -> DllResult<()> {
    // Validate input pointer
    if data.is_null() {
        return Err(crate::buffer_utils::BufferError::NullPointer.into());
    }

    // Use a conservative buffer size to prevent crashes
    let safe_buffer_size = ctx.buffer_size.min(4096); // Cap at 4KB for safety
    if safe_buffer_size < 100 {
        ctx.log_error("Buffer size too small for key listing");
        let error_msg = "Buffer too small for key listing";
        unsafe {
            crate::buffer_utils::write_string_to_buffer(data, safe_buffer_size, error_msg)?;
        }
        return Ok(());
    }

    ctx.log_info(&format!("Starting key listing with buffer size: {}", safe_buffer_size));

    match crate::config::list_keys() {
        Ok(keys) => {
            ctx.log_info(&format!("Retrieved {} keys", keys.len()));
            if keys.is_empty() {
                let message = "FiSH: No keys stored.";
                unsafe {
                    write_string_to_buffer(data, safe_buffer_size, message)?;
                }
                return Ok(());
            }

            // For mIRC compatibility, we'll format the output differently
            // Instead of returning /echo commands, return formatted text that mIRC script will handle
            let mut output = String::new();
            output.push_str("FiSH Keys:");

            // Add startup time if available
            if let Ok(startup_time) = crate::config::get_startup_time_formatted() {
                output.push_str(&format!("\nFiSH: configuration initialized: {}", startup_time));
            }

            output.push_str("\n------------------------");

            let mut keys_added = 0;
            let mut truncated = false;

            // Calculate safe output size - leave room for footer and safety margin
            let footer_size = 200;
            let max_content_size = safe_buffer_size.saturating_sub(footer_size);

            for (nickname, network, _key_type, date) in &keys {
                let net_display =
                    if network.is_empty() || network == "default" { "default" } else { network };
                let key_info = if let Some(date_str) = date {
                    format!("\nKey: {} | Network: {} | Added: {}", nickname, net_display, date_str)
                } else {
                    format!("\nKey: {} | Network: {}", nickname, net_display)
                };

                // Check if adding this line would exceed buffer
                if output.len() + key_info.len() > max_content_size {
                    truncated = true;
                    break;
                }

                output.push_str(&key_info);
                keys_added += 1;
            }

            // Add footer
            output.push_str("\n------------------------");
            output.push_str(&format!("\nDisplayed: {} of {} keys", keys_added, keys.len()));

            if truncated {
                output.push_str("\n(Output truncated due to buffer size)");
            }
            unsafe {
                write_string_to_buffer(data, safe_buffer_size, &output)?;
            }
        }
        Err(e) => {
            ctx.log_error(&format!("Failed to list keys: {}", e));
            let error_message = format!("FiSH Error: Failed to retrieve keys ({})", e);
            unsafe {
                write_string_to_buffer(data, safe_buffer_size, &error_message)?;
            }
        }
    }

    Ok(())
}
