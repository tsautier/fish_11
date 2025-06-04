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

/// Encrypts a message for a specific nickname using ChaCha20-Poly1305 authenticated encryption
///
/// This function handles the complete encryption workflow, including:
/// - Retrieving the appropriate encryption key
/// - Generating a secure random nonce
/// - Performing authenticated encryption
/// - Formatting the output with FiSH protocol prefix
///
/// REFACTORED VERSION - Now uses helper modules for safety and consistency
#[no_mangle]
#[allow(non_snake_case)]
pub extern "stdcall" fn FiSH11_EncryptMsg(
    _m_wnd: HWND,
    _a_wnd: HWND,
    data: *mut c_char,
    _parms: *mut c_char,
    _show: BOOL,
    _nopause: BOOL,
) -> c_int {
    dll_function_wrapper(data, "FiSH11_EncryptMsg", |data, ctx| encrypt_msg_impl(data, ctx))
}

/// Clean implementation focused on encryption business logic
fn encrypt_msg_impl(data: *mut c_char, ctx: &DllFunctionContext) -> DllResult<()> {
    // Extract input safely using helper
    let input = extract_input_string(data, ctx)?;

    // Parse input parameters
    let parts: Vec<&str> = input.splitn(2, ' ').collect();

    if parts.len() < 2 {
        ctx.log_error("Invalid input format - missing nickname or message");
        return Err(DllError::InvalidInput(
            "Usage: /dll fish_11.dll FiSH11_EncryptMsg <nickname> <message>".to_string(),
        ));
    }

    let nickname = parts[0].trim();
    let message = parts[1];

    ctx.log_debug(&format!("Encrypting message for nickname: {}", nickname)); // Get the encryption key for this nickname
    let key = config::get_key_default(nickname).map_err(|e| {
        ctx.log_error(&format!("No key found for {}: {}", nickname, e));
        DllError::ProcessingError(format!("No key found for {}: {}", nickname, e))
    })?;

    ctx.log_debug("Successfully retrieved encryption key");

    // Encrypt the message using our crypto module
    let key_array: [u8; 32] = key.try_into().map_err(|_| {
        ctx.log_error("Invalid key size - expected 32 bytes");
        DllError::ProcessingError("Invalid key size - expected 32 bytes".to_string())
    })?;
    let encrypted = crypto::encrypt_message(&key_array, message, Some(nickname)).map_err(|e| {
        ctx.log_error(&format!("Encryption failed: {}", e));
        DllError::ProcessingError(format!("Encryption error: {}", e))
    })?;
    // Format with FiSH protocol prefix and write to buffer
    let result = format!("+FiSH {}", encrypted);
    unsafe {
        write_string_to_buffer(data, ctx.buffer_size, &result)?;
    }

    ctx.log_info(&format!("Successfully encrypted message for {}", nickname));

    Ok(())
}
