//! File deletion function for FiSH 11

use std::ffi::c_char;
use std::os::raw::c_int;

use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::buffer_utils::write_string_to_buffer;
use crate::config;
use crate::dll_function_utils::{
    DllFunctionContext, DllResult, dll_function_wrapper, extract_input_string,
};
use crate::utils::normalize_nick;

/// Deletes an encryption key for a specific nickname from storage
///
/// This function removes a stored encryption key along with its associated metadata,
/// providing detailed feedback about what was deleted. It first gathers information
/// about the key before deletion to create an informative success message.
#[no_mangle]
#[allow(non_snake_case)]
pub extern "stdcall" fn FiSH11_FileDelKey(
    _m_wnd: HWND,
    _a_wnd: HWND,
    data: *mut c_char,
    _parms: *mut c_char,
    _show: BOOL,
    _nopause: BOOL,
) -> c_int {
    dll_function_wrapper(data, "FiSH11_FileDelKey", |data, ctx| file_del_key_impl(data, ctx))
}

/// Implementation for deleting encryption keys from storage
fn file_del_key_impl(data: *mut c_char, ctx: &DllFunctionContext) -> DllResult<()> {
    let input = extract_input_string(data, ctx)?;
    let nickname = normalize_nick(input.trim());

    ctx.log_info(&format!("Key deletion requested for nickname: {}", nickname));

    // First, gather information about what we're deleting for a more informative message
    let mut extra_info = String::new(); // Try to get key info before deleting
    if let Ok(keys) = config::list_keys() {
        for (key_name, network, _key_type, date) in keys {
            if key_name == nickname {
                if !network.is_empty() && network != "default" {
                    extra_info.push_str(&format!(" (network: {})", network));
                    ctx.log_info(&format!("Found key for {} on network: {}", nickname, network));
                }

                if let Some(date_str) = date {
                    extra_info.push_str(&format!(", added: {}", date_str));
                    ctx.log_info(&format!("Key was added on: {}", date_str));
                }

                break;
            }
        }
    }

    // Delete key using default function
    match config::delete_key_default(&nickname) {
        Ok(_) => {
            let message = if extra_info.is_empty() {
                format!("Key deleted for {}", nickname)
            } else {
                format!("Key deleted for {}{}", nickname, extra_info)
            };

            ctx.log_info(&message);
            unsafe {
                write_string_to_buffer(data, ctx.buffer_size, &message)?;
            }
        }
        Err(e) => {
            let error_msg = format!("Error deleting key: {}", e);
            ctx.log_error(&format!("Error deleting key for {}: {}", nickname, e));

            unsafe {
                write_string_to_buffer(data, ctx.buffer_size, &error_msg)?;
            }
        }
    }

    Ok(())
}
