use std::ffi::c_char;
use std::os::raw::c_int;

use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::buffer_utils::write_string_to_buffer;
use crate::config;
use crate::dll_function_utils::{
    DllFunctionContext, DllResult, dll_function_wrapper, extract_input_string,
};

/// Retrieves and displays a single key entry from stored keys list by index
#[no_mangle]
#[allow(non_snake_case)]
pub extern "stdcall" fn FiSH11_FileListKeysItem(
    _m_wnd: HWND,
    _a_wnd: HWND,
    data: *mut c_char,
    _parms: *mut c_char,
    _show: BOOL,
    _nopause: BOOL,
) -> c_int {
    dll_function_wrapper(data, "FiSH11_FileListKeysItem", |data, ctx| {
        file_list_keys_item_impl(data, ctx)
    })
}

/// Implementation for retrieving a single key entry by index
fn file_list_keys_item_impl(data: *mut c_char, ctx: &DllFunctionContext) -> DllResult<()> {
    let input = extract_input_string(data, ctx)?;

    // Parse index (default to 0 if not provided)
    let index = match input.trim().parse::<usize>() {
        Ok(i) => {
            ctx.log_info(&format!("Requested key at index: {}", i));
            i
        }
        Err(_) => {
            ctx.log_info("Invalid index provided, defaulting to 0");
            0
        }
    };

    // Get the keys
    match config::list_keys() {
        Ok(keys) => {
            // Convert to a vector for indexing
            let keys_vec: Vec<(String, String, Option<String>, Option<String>)> = keys;

            ctx.log_info(&format!("Retrieved {} keys from storage", keys_vec.len()));

            // Check if we're done
            if index >= keys_vec.len() {
                ctx.log_info(&format!(
                    "Reached end of keys list (requested index {} is beyond size {})",
                    index,
                    keys_vec.len()
                ));

                let done_msg = "=== End of keys list ===";
                unsafe {
                    write_string_to_buffer(data, ctx.buffer_size, done_msg)?;
                }
            } else {
                // Display current key and prepare for next
                let (nickname, network, _key_type, date) = &keys_vec[index];
                let net_display =
                    if network.is_empty() || network == "default" { "default" } else { network };

                ctx.log_info(&format!(
                    "Returning key info for nickname '{}' at index {}",
                    nickname, index
                ));
                ctx.log_debug(&format!("Key details - Network: {}, Date: {:?}", net_display, date));

                // Format the message with date if available
                let key_msg = if let Some(date_str) = date {
                    format!("  {} ({}) [Added: {}]", nickname, net_display, date_str)
                } else {
                    format!("  {} ({})", nickname, net_display)
                };

                unsafe {
                    write_string_to_buffer(data, ctx.buffer_size, &key_msg)?;
                }
            }
        }
        Err(e) => {
            ctx.log_error(&format!("Error listing keys: {}", e));

            let error_msg = format!("Error listing keys: {}", e);
            unsafe {
                write_string_to_buffer(data, ctx.buffer_size, &error_msg)?;
            }
        }
    }

    Ok(())
}
