use std::ffi::c_char;
use std::os::raw::c_int;

use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::config;
// Use our new helper modules for clean implementation
use crate::dll_function_utils::{
    DllError, DllFunctionContext, DllResult, dll_function_wrapper, extract_input_string,
};
use crate::utils::{base64_encode, normalize_nick};

/// Retrieves and displays the encryption key for a specified nickname
///
/// This function looks up the stored encryption key for a given nickname and returns it
/// in base64-encoded format. The key can be used for manual encryption/decryption or
/// for key sharing purposes.
///
/// REFACTORED VERSION - Now uses helper modules for safety and consistency
#[no_mangle]
#[allow(non_snake_case)]
pub extern "stdcall" fn FiSH11_FileGetKey(
    _m_wnd: HWND,
    _a_wnd: HWND,
    data: *mut c_char,
    _parms: *mut c_char,
    _show: BOOL,
    _nopause: BOOL,
) -> c_int {
    dll_function_wrapper(data, "FiSH11_FileGetKey", |data, ctx| file_get_key_impl(data, ctx))
}

/// Clean implementation focused on key retrieval business logic
fn file_get_key_impl(data: *mut c_char, ctx: &DllFunctionContext) -> DllResult<()> {
    // Extract input safely using helper
    let input = extract_input_string(data, ctx)?;

    if input.trim().is_empty() {
        ctx.log_error("Invalid input format - missing nickname");
        return Err(DllError::InvalidInput(
            "Usage: /dll fish_11.dll FiSH11_FileGetKey <nickname>".to_string(),
        ));
    }

    let nickname = normalize_nick(input.trim());
    ctx.log_debug(&format!("Retrieving key for nickname: {}", nickname)); // Look up the key

    match config::get_key_default(&nickname) {
        Ok(key) => {
            ctx.log_debug("Key found, encoding as base64");
            let base64_key = base64_encode(&key);
            let result = format!("/echo -ts Key for {}: {}", nickname, base64_key);

            unsafe {
                crate::buffer_utils::write_string_to_buffer(data, ctx.buffer_size, &result)?;
            }

            ctx.log_info(&format!("Successfully retrieved key for {}", nickname));
        }
        Err(e) => {
            ctx.log_warn(&format!("Key lookup failed for {}: {}", nickname, e));

            // Instead of calling exchange function recursively, just inform user
            ctx.log_debug(&format!(
                "No key found for {} - user should initiate key exchange",
                nickname
            ));
            let error_msg = format!(
                "/echo -ts No key found for {}. Use: /dll fish_11.dll FiSH11_ExchangeKey {}",
                nickname, nickname
            );

            unsafe {
                crate::buffer_utils::write_string_to_buffer(data, ctx.buffer_size, &error_msg)?;
            }
        }
    }

    Ok(())
}
