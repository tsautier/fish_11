use std::ffi::c_char;
use std::os::raw::c_int;

use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::buffer_utils::write_string_to_buffer;
use crate::config;
use crate::dll_function_utils::{
    DllError, DllFunctionContext, DllResult, dll_function_wrapper, extract_input_string,
};

/// Generates and stores a cryptographically secure random key for a nickname
///
/// This function creates a new 256-bit encryption key using the system's cryptographic
/// random number generator and associates it with the specified nickname. The key can
/// optionally be tagged with a network identifier for organizational purposes.

#[no_mangle]
#[allow(non_snake_case)]
pub extern "stdcall" fn FiSH11_GenKey(
    _m_wnd: HWND,
    _a_wnd: HWND,
    data: *mut c_char,
    _parms: *mut c_char,
    _show: BOOL,
    _nopause: BOOL,
) -> c_int {
    dll_function_wrapper(data, "FiSH11_GenKey", |data, ctx| gen_key_impl(data, ctx))
}

/// Clean implementation focused on key generation business logic
fn gen_key_impl(data: *mut c_char, ctx: &DllFunctionContext) -> DllResult<()> {
    // Extract input safely using helper
    let input = extract_input_string(data, ctx)?;

    // Parse input parameters
    let parts: Vec<&str> = input.splitn(2, ' ').collect();

    if parts.is_empty() || parts[0].is_empty() {
        ctx.log_error("Invalid input format - missing nickname");
        return Err(DllError::InvalidInput(
            "Usage: /dll fish_11.dll FiSH11_GenKey <nickname> [network]".to_string(),
        ));
    }

    let nickname = parts[0].trim();
    let network = parts.get(1).map(|s| s.trim());

    ctx.log_debug(&format!("Generating key for nickname: {} (network: {:?})", nickname, network)); // Generate a cryptographically secure random key using OsRng
    let mut key = [0u8; 32];
    let random_bytes = crate::utils::generate_random_bytes(32);
    key.copy_from_slice(&random_bytes);

    ctx.log_debug("Random key generated successfully, storing...");

    // Store the key with duplicate protection (overwrite=false for safety)
    match config::set_key(nickname, &key, network, false) {
        Ok(_) => {
            let success_msg = format!("Random key generated for {}", nickname);
            unsafe {
                write_string_to_buffer(data, ctx.buffer_size, &success_msg)?;
            }
            ctx.log_info(&format!("Successfully generated and stored key for {}", nickname));
        }
        Err(e) => {
            let error_msg_content = match e {
                crate::error::FishError::DuplicateEntry(nick) => {
                    format!("Key for {} already exists. Use /fish_setkey11 to update.", nick)
                }
                _ => format!("Error setting key: {}", e),
            };

            ctx.log_warn(&format!("Key generation issue: {}", error_msg_content));
            unsafe {
                write_string_to_buffer(data, ctx.buffer_size, &error_msg_content)?;
            }
        }
    }

    Ok(())
}
