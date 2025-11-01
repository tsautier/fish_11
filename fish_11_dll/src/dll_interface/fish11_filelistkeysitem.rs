use std::ffi::c_char;
use std::os::raw::c_int;

use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::config;
use crate::dll_function;
use crate::unified_error::{DllError, DllResult};

/// Retrieves and displays a single key entry from the stored keys list by index.
dll_function!(FiSH11_FileListKeysItem, data, {
    let input = unsafe { crate::buffer_utils::parse_buffer_input(data)? };

    let index = input.trim().parse::<usize>().unwrap_or(0);
    log::info!("Requesting key at index: {}", index);

    let keys = config::list_keys()?;

    if index >= keys.len() {
        log::info!("Reached end of keys list.");
        return Ok("=== End of keys list ===".to_string());
    }

    let (nickname, network, _key_type, date) = &keys[index];
    let net_display = if network.is_empty() || network == "default" {
        "default"
    } else {
        network
    };

    let key_msg = if let Some(date_str) = date {
        format!("  {} ({}) [Added: {}]", nickname, net_display, date_str)
    } else {
        format!("  {} ({})", nickname, net_display)
    };

    log::debug!("Returning key info for index {}: {}", index, key_msg);

    Ok(key_msg)
});