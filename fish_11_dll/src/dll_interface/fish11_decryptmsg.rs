use std::ffi::c_char;
use std::os::raw::c_int;

use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

// Use our new helper modules
use crate::buffer_utils::write_string_to_buffer;
use crate::dll_function_utils::{
    DllError, DllFunctionContext, DllResult, dll_function_wrapper, extract_input_string,
};
use crate::{config, crypto};

/// Decrypts a message using the stored key for a specific nickname
///
/// This function handles the decryption of messages encrypted with the ChaCha20-Poly1305
/// algorithm, using the key associated with the specified nickname. It automatically
/// handles the FiSH message prefix and performs authentication checks.
///
/// REFACTORED VERSION - Now uses helper modules for safety and consistency
#[no_mangle]
#[allow(non_snake_case)]
pub extern "stdcall" fn FiSH11_DecryptMsg(
    _m_wnd: HWND,
    _a_wnd: HWND,
    data: *mut c_char,
    _parms: *mut c_char,
    _show: BOOL,
    _nopause: BOOL,
) -> c_int {
    dll_function_wrapper(data, "FiSH11_DecryptMsg", |data, ctx| decrypt_msg_impl(data, ctx))
}

/// Clean implementation focused on decryption business logic
fn decrypt_msg_impl(data: *mut c_char, ctx: &DllFunctionContext) -> DllResult<()> {
    // Extract input safely using helper
    let input = extract_input_string(data, ctx)?;

    // Parse input parameters
    let parts: Vec<&str> = input.splitn(2, ' ').collect();

    if parts.len() < 2 {
        ctx.log_error("Invalid input format - missing nickname or encrypted message");
        return Err(DllError::InvalidInput(
            "Usage: /dll fish_11.dll FiSH11_DecryptMsg <nickname> <encrypted_message>".to_string(),
        ));
    }

    let nickname = parts[0].trim();
    let mut encrypted = parts[1].trim();

    ctx.log_debug(&format!("Decrypting message for nickname: {}", nickname));

    // Strip the "+FiSH " prefix if present, 6 characters long
    if encrypted.starts_with("+FiSH ") {
        encrypted = &encrypted[6..];
        ctx.log_debug("Stripped +FiSH prefix from encrypted message");
    } // Get the decryption key for this nickname
    let key = config::get_key_default(nickname).map_err(|e| {
        ctx.log_error(&format!("No key found for {}: {}", nickname, e));
        DllError::ProcessingError(format!("No key found for {}: {}", nickname, e))
    })?;

    ctx.log_debug("Successfully retrieved decryption key");

    // Decrypt the message using our crypto module
    let key_array: &[u8; 32] = key.as_slice().try_into().map_err(|_| {
        ctx.log_error("Invalid key size - expected 32 bytes");
        DllError::ProcessingError("Invalid key size - expected 32 bytes".to_string())
    })?;
    let decrypted = crypto::decrypt_message(key_array, encrypted).map_err(|e| {
        ctx.log_error(&format!("Decryption failed: {}", e));
        DllError::ProcessingError(format!("Decryption error: {}", e))
    })?;

    // Write decrypted result to buffer
    unsafe {
        write_string_to_buffer(data, ctx.buffer_size, &decrypted)?;
    }

    ctx.log_info(&format!("Successfully decrypted message for {}", nickname));

    Ok(())
}
