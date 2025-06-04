use std::ffi::c_char;
use std::os::raw::c_int;

use base64::Engine;
use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

// Use our new helper modules
use crate::buffer_utils::{EchoStyle, write_echo_command_to_buffer};
use crate::config;
use crate::dll_function_utils::{
    DllError, DllFunctionContext, DllResult, dll_function_wrapper, extract_input_string,
};

/// Manually sets an encryption key for a specified nickname
///
/// This function allows direct configuration of a 256-bit encryption key for a nickname,
/// provided as a base64-encoded string. The key will be used for all future encrypted
/// communications with the specified nickname.
///
/// REFACTORED VERSION - Now uses helper modules for safety and consistency
#[no_mangle]
#[allow(non_snake_case)]
pub extern "stdcall" fn FiSH11_SetKey(
    _m_wnd: HWND,
    _a_wnd: HWND,
    data: *mut c_char,
    _parms: *mut c_char,
    _show: BOOL,
    _nopause: BOOL,
) -> c_int {
    dll_function_wrapper(data, "FiSH11_SetKey", |data, ctx| set_key_impl(data, ctx))
}

/// Clean implementation focused on key setting business logic
fn set_key_impl(data: *mut c_char, ctx: &DllFunctionContext) -> DllResult<()> {
    // Extract input safely using helper
    let input = extract_input_string(data, ctx)?;

    // Parse input parameters
    let parts: Vec<&str> = input.splitn(2, ' ').collect();

    if parts.len() < 2 {
        ctx.log_error("Invalid input format - missing nickname or key");
        return Err(DllError::InvalidInput(
            "Usage: /dll fish_11.dll FiSH11_SetKey <nickname> <base64_key>".to_string(),
        ));
    }

    let nickname = parts[0].trim();
    let base64_key = parts[1].trim();

    ctx.log_debug(&format!("Setting key for nickname: {}", nickname));

    // Decode the base64 key
    let key_bytes = base64::engine::general_purpose::STANDARD.decode(base64_key).map_err(|_| {
        ctx.log_error("Invalid base64 key provided");
        DllError::InvalidInput("Invalid base64 key".to_string())
    })?;

    // Ensure it's the right length (256 bits = 32 bytes)
    if key_bytes.len() != 32 {
        ctx.log_error(&format!("Invalid key length: {} bytes (expected 32)", key_bytes.len()));
        return Err(DllError::InvalidInput(format!(
            "Key must be 32 bytes (got {})",
            key_bytes.len()
        )));
    }

    // Convert to array
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_bytes);

    ctx.log_debug("Key decoded successfully, storing...");
    // Store the key with overwrite enabled
    match config::set_key(nickname, &key, None, true) {
        Ok(_) => {
            let success_msg = format!("Key {} updated successfully", nickname);
            unsafe {
                write_echo_command_to_buffer(
                    data,
                    ctx.buffer_size,
                    &success_msg,
                    EchoStyle::Timestamp,
                )?;
            }
            ctx.log_info(&format!("Successfully set key for {}", nickname));
        }
        Err(e) => {
            let error_msg_content = match e {
                crate::error::FishError::DuplicateEntry(nick) => {
                    format!("Key for {} already exists and was updated", nick)
                }
                _ => format!("Error setting key: {}", e),
            };

            ctx.log_warn(&format!("Key setting issue: {}", error_msg_content));
            unsafe {
                write_echo_command_to_buffer(
                    data,
                    ctx.buffer_size,
                    &error_msg_content,
                    EchoStyle::Timestamp,
                )?;
            }
        }
    }

    Ok(())
}
