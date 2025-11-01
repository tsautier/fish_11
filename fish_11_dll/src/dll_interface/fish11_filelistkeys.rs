use std::ffi::c_char;
use std::os::raw::c_int;

use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::config;
use crate::dll_function;
use crate::dll_interface::{MIRC_COMMAND, MIRC_HALT};
use crate::unified_error::{DllError, DllResult};

dll_function!(FiSH11_FileListKeys, _data, {
    log::info!("Starting key listing");

    let keys = config::list_keys()?;

    if keys.is_empty() {
        return Ok("/echo -ts FiSH: No keys stored.".to_string());
    }

    // We will build a multi-line response for mIRC to process.
    // mIRC can handle multiple commands separated by `|`.
    let mut commands = Vec::new();
    commands.push("echo -ts --- FiSH Keys ---".to_string());

    for (nickname, network, _key_type, date) in keys {
        let net_display = if network.is_empty() || network == "default" {
            "default"
        } else {
            &network
        };

        let key_info = if let Some(date_str) = date {
            format!(
                "Key: {:<20} | Network: {:<15} | Added: {}",
                nickname,
                net_display,
                date_str
            )
        } else {
            format!("Key: {:<20} | Network: {:<15}", nickname, net_display)
        };
        commands.push(format!("echo -ts {}", key_info));
    }

    commands.push("echo -ts -------------------".to_string());

    // Join all echo commands with `|` to be executed sequentially by mIRC.
    Ok(commands.join(" | "))
});