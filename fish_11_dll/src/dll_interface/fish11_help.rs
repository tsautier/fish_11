use std::ffi::c_char;
use std::os::raw::c_int;

use crate::dll_function_identifier;
use crate::dll_interface::{CRATE_VERSION, CURRENT_YEAR};
use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;

/// Displays help information about the DLL, including version and available commands.
///
/// The output is a plain help text with one line per entry.
dll_function_identifier!(FiSH11_Help, _data, {
    let help_lines = [
        format!("=== FiSH_11 v{} - secure chat for IRC ===", CRATE_VERSION),
        format!("Written by [GuY], {} - licensed under the GPL v3 or above.", CURRENT_YEAR),
        "".to_string(), // Empty line
        "Commands:".to_string(),
        "  FiSH11_CoreVersion : show version information".to_string(),
        "  FiSH11_GenKey <nick> : generate a random key".to_string(),
        "  FiSH11_SetKey <nick> <key> : set a key manually".to_string(),
        "  FiSH11_FileGetKey <nick> : get the key for a nickname".to_string(),
        "  FiSH11_FileDelKey <nick> : delete a key".to_string(),
        "  FiSH11_FileListKeys : list all stored keys".to_string(),
        "  FiSH11_EncryptMsg <nick> <message> : encrypt a message".to_string(),
        "  FiSH11_DecryptMsg <nick> <message> : decrypt a message".to_string(),
        "  FiSH11_ExchangeKey <nick> : start key exchange".to_string(),
        "  FiSH11_ProcessPublicKey <nick> <key> : process received key".to_string(),
        "  FiSH11_TestCrypt <message> : test encryption".to_string(),
    ];

    // Return as CRLF-separated plain lines so the mIRC helper can display them safely
    Ok(help_lines.join("\r\n"))
});
