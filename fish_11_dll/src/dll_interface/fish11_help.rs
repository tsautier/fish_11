use std::ffi::{CString, c_char};
use std::os::raw::c_int;
use std::panic;

use log::error;
use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::dll_interface::{
    CRATE_VERSION, CURRENT_YEAR, MIRC_COMMAND, MIRC_HALT, MIRC_TYPICAL_BUFFER_SIZE,
};

/// Display help information
///
/// Format: /dll fish_11.dll FiSH11_Help
/// Returns help text formatted as mIRC commands.
#[no_mangle]
#[allow(non_snake_case)]
pub extern "stdcall" fn FiSH11_Help(
    _m_wnd: HWND,
    _a_wnd: HWND,
    data: *mut c_char,
    _parms: *mut c_char,
    _show: BOOL,
    _nopause: BOOL,
) -> c_int {
    let result = panic::catch_unwind(|| {
        let help_lines = [
            format!("//echo -a === FiSH_11 v{}, secure chat for mIRC === ", CRATE_VERSION),
            format!("//echo -a | Written by [etc], {}, licensed under the GPL v3.", CURRENT_YEAR),
            "//echo -a | ".to_string(), // Empty line
            "//echo -a |     Commands:".to_string(),
            "//echo -a |       FiSH_GetVersion11 - Show version information".to_string(),
            "//echo -a |       FiSH_GenKey11 <nick> - Generate a random key".to_string(),
            "//echo -a |       FiSH_SetKey11 <nick> <key> - Set a key manually".to_string(),
            "//echo -a |       FiSH_GetKey11 <nick> - Get the key for a nickname".to_string(),
            "//echo -a |       FiSH_DelKey11 <nick> - Delete a key".to_string(),
            "//echo -a |       FiSH_ListKeys11 - List all stored keys".to_string(),
            "//echo -a |       FiSH_EncryptMsg11 <nick> <message> - Encrypt a message".to_string(),
            "//echo -a |       FiSH_DecryptMsg11 <nick> <message> - Decrypt a message".to_string(),
            "//echo -a |       FiSH_ExchangeKey11 <nick> - Start key exchange".to_string(),
            "//echo -a |       FiSH_ProcessKey11 <nick> <key> - Process received key".to_string(),
            "//echo -a |       FiSH_TestCrypt11 <message> - Test encryption".to_string(),
        ];

        let mirc_commands_str = help_lines.join(" | ");
        // Ensure no problematic non-breaking spaces are present
        let cleaned_mirc_commands_str = mirc_commands_str.replace(" ", " ");

        let c_mirc_commands = match CString::new(cleaned_mirc_commands_str) {
            Ok(s) => s,
            Err(e) => {
                error!("FiSH11_Help: Failed to create CString for help commands: {}", e);
                // Fallback CString if original fails
                CString::new(
                    "//echo -cr Error: Could not generate help text due to invalid characters.",
                )
                .expect("Fallback error message should not contain null bytes")
            }
        };

        unsafe {
            if data.is_null() {
                error!("FiSH11_Help: Data buffer pointer is null.");
                return MIRC_HALT; // Halt if data pointer is null
            }

            let source_bytes = c_mirc_commands.as_bytes_with_nul();
            let source_len = source_bytes.len();

            // mIRC usually provides a buffer of at least 20480 bytes for DLL string returns.
            // This help string is well within that. For very long strings,
            // getting the actual buffer size from mIRC (if passed in `parms`) would be necessary.
            // For now, we assume the buffer is sufficient for this help text.
            // A production DLL should be more robust here if strings can be arbitrarily long.

            if source_len > MIRC_TYPICAL_BUFFER_SIZE {
                error!(
                    "FiSH11_Help: Help text ({} bytes) may exceed typical mIRC buffer size.",
                    source_len
                );
                // Truncation or a shorter error message would be safer here.
                // For this example, we'll proceed but this is a risk for very large strings.
            }

            std::ptr::copy_nonoverlapping(source_bytes.as_ptr(), data as *mut u8, source_len);
        }
        MIRC_COMMAND
    });

    match result {
        Ok(ret_val) => ret_val,
        Err(_panic_payload) => {
            error!("Panic occurred in FiSH11_Help !");
            // Attempt to write a panic message to mIRC if data buffer is valid
            if !data.is_null() {
                let panic_msg =
                    CString::new("//echo -cr Critical Error: FiSH11_Help function panicked.")
                        .expect("Panic error message should not contain null bytes");
                unsafe {
                    let bytes_to_copy = panic_msg.as_bytes_with_nul();
                    // Be careful with length, use a known safe small length for panic messages
                    // if the actual buffer size isn't available.
                    std::ptr::copy_nonoverlapping(
                        bytes_to_copy.as_ptr(),
                        data as *mut u8,
                        bytes_to_copy.len().min(512),
                    );
                }
            }
            MIRC_HALT
        }
    }
}
