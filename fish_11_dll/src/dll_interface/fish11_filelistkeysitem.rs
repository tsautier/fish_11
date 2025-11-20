use std::ffi::c_char;
use std::os::raw::c_int;

use crate::platform_types::BOOL;
use crate::platform_types::HWND;

use crate::buffer_utils;
use crate::config;
use crate::dll_function_identifier;
use crate::log_debug;
use crate::unified_error::DllError;

dll_function_identifier!(FiSH11_FileListKeysItem, data, {
    // Parse input to get the index
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };

    // Parse index (default to 0 if not provided or invalid)
    let index = input.trim().parse::<usize>().unwrap_or_else(|_| {
        log_debug!("Invalid index provided, defaulting to 0");
        0
    });

    log::info!("Requested key at index: {}", index);

    // Get the keys
    let keys = config::list_keys()?;
    let keys_vec: Vec<(String, String, Option<String>, Option<String>)> = keys;

    log::info!("Retrieved {} keys from storage", keys_vec.len());

    // Check if we're done
    if index >= keys_vec.len() {
        log::info!(
            "Reached end of keys list (requested index {} is beyond size {})",
            index,
            keys_vec.len()
        );
        return Ok("=== End of keys list ===".to_string());
    }

    // Display current key
    let (nickname, network, _key_type, date) = &keys_vec[index];
    let net_display = if network.is_empty() || network == "default" { "default" } else { network };

    log::info!("Returning key info for nickname '{}' at index {}", nickname, index);
    log_debug!("Key details - Network: {}, Date: {:?}", net_display, date);

    // Format the message with date if available (plain text, no /echo)
    let key_msg = if let Some(date_str) = date {
        format!("   {} ({}) [Added: {}]", nickname, net_display, date_str)
    } else {
        format!("   {} ({})", nickname, net_display)
    };

    Ok(key_msg)
});
