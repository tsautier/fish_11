use std::ffi::c_char;
use std::os::raw::c_int;

use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::dll_function;
use crate::dll_interface::{CRATE_VERSION, CURRENT_YEAR};
use crate::unified_error::{DllError, DllResult};

/// Displays help information about the DLL, including version and available commands.
///
/// The output is a series of mIRC `/echo` commands joined by `|`.
dll_function!(FiSH11_Help, _data, {
    let help_lines = [
        format!(
            "//echo -a === FiSH_11 v{}, secure chat for mIRC === ",
            CRATE_VERSION
        ),
        format!(
            "//echo -a | Written by [GuY], {}, licensed under the GPL v3.",
            CURRENT_YEAR
        ),
        "//echo -a | ".to_string(), // Empty line
        "//echo -a |     Commands:".to_string(),
        "//echo -a |       FiSH11_GetVersion - Show version information".to_string(),
        "//echo -a |       FiSH11_GenKey <nick> - Generate a random key".to_string(),
        "//echo -a |       FiSH11_SetKey <nick> <key> - Set a key manually".to_string(),
        "//echo -a |       FiSH11_FileGetKey <nick> - Get the key for a nickname".to_string(),
        "//echo -a |       FiSH11_FileDelKey <nick> - Delete a key".to_string(),
        "//echo -a |       FiSH11_FileListKeys - List all stored keys".to_string(),
        "//echo -a |       FiSH11_EncryptMsg <nick> <message> - Encrypt a message".to_string(),
        "//echo -a |       FiSH11_DecryptMsg <nick> <message> - Decrypt a message".to_string(),
        "//echo -a |       FiSH11_ExchangeKey <nick> - Start key exchange".to_string(),
        "//echo -a |       FiSH11_ProcessPublicKey <nick> <key> - Process received key".to_string(),
        "//echo -a |       FiSH11_TestCrypt <message> - Test encryption".to_string(),
    ];

    let mirc_commands_str = help_lines.join(" | ");

    Ok(mirc_commands_str)
});