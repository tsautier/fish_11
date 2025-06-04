use std::ffi::c_char;
use std::os::raw::c_int;
use std::time::Duration;

use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::config;
use crate::dll_interface::function_template::{FunctionConfig, execute_dll_function};

/// Function to get a boolean value from the config file
#[no_mangle]
#[allow(non_snake_case)]
pub extern "stdcall" fn INI_GetBool(
    _m_wnd: HWND,
    _a_wnd: HWND,
    data: *mut c_char,
    _parms: *mut c_char,
    _show: BOOL,
    _nopause: BOOL,
) -> c_int {
    let config = FunctionConfig {
        name: "INI_GetBool",
        timeout: Duration::from_secs(2),
        validate_input: true,
        log_entry_exit: false, // Reduce logging for frequent operations
    };

    execute_dll_function(data, config, |input, _trace_id| {
        // Parse key and default value
        let parts: Vec<&str> = input.splitn(2, ' ').collect();
        let (key, default) = match parts.as_slice() {
            [key] => (key.trim(), false),
            [key, default] => (key.trim(), default.trim().parse::<i32>().unwrap_or(0) != 0),
            _ => return Err("Invalid parameter format".to_string()),
        };

        // Get configuration
        let config = config::get_fish11_config().map_err(|e| format!("Config error: {}", e))?;

        // Map key to config value
        let value = match key.to_lowercase().as_str() {
            "process_incoming" => config.process_incoming,
            "process_outgoing" => config.process_outgoing,
            "encrypt_notice" => config.encrypt_notice,
            "encrypt_action" => config.encrypt_action,
            "no_fish10_legacy" => config.no_fish10_legacy,
            _ => default,
        };

        Ok(if value { "1" } else { "0" })
    })
}

/// Function to get a string value from the config file
#[no_mangle]
#[allow(non_snake_case)]
pub extern "stdcall" fn INI_GetString(
    _m_wnd: HWND,
    _a_wnd: HWND,
    data: *mut c_char,
    _parms: *mut c_char,
    _show: BOOL,
    _nopause: BOOL,
) -> c_int {
    let config = FunctionConfig {
        name: "INI_GetString",
        timeout: Duration::from_secs(2),
        validate_input: true,
        log_entry_exit: false,
    };

    execute_dll_function(data, config, |input, _trace_id| {
        // Split into key and optional default
        let parts: Vec<&str> = input.splitn(2, ' ').collect();
        let key = parts.get(0).map_or("", |s| s.trim());
        let default = parts.get(1).map_or("", |s| s.trim());

        // Try to read from config
        let config_result = match config::get_fish11_config() {
            Ok(config) => match key {
                "plain_prefix" => config.plain_prefix.clone(),
                "mark_encrypted" => config.mark_encrypted.clone(),
                _ => default.to_string(),
            },
            Err(_) => default.to_string(),
        };

        Ok(config_result)
    })
}

/// Function to get an integer value from the config file
#[no_mangle]
#[allow(non_snake_case)]
pub extern "stdcall" fn INI_GetInt(
    _m_wnd: HWND,
    _a_wnd: HWND,
    data: *mut c_char,
    _parms: *mut c_char,
    _show: BOOL,
    _nopause: BOOL,
) -> c_int {
    let config = FunctionConfig {
        name: "INI_GetInt",
        timeout: Duration::from_secs(2),
        validate_input: true,
        log_entry_exit: false,
    };

    execute_dll_function(data, config, |input, _trace_id| {
        // Split into key and optional default
        let parts: Vec<&str> = input.splitn(2, ' ').collect();
        let key = parts.get(0).map_or("", |s| s.trim());
        let default = parts.get(1).map_or(0, |s| s.trim().parse::<i32>().unwrap_or(0));

        // Try to read from config
        let config_result = match config::get_fish11_config() {
            Ok(config) => match key {
                "mark_position" => config.mark_position as i32,
                _ => default,
            },
            Err(_) => default,
        };

        Ok(config_result.to_string())
    })
}
