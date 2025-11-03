use std::ffi::c_char;
use std::os::raw::c_int;

use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::config;
use crate::dll_function_identifier;
use crate::unified_error::DllError;

/// Gets a boolean value from the config file.
/// Input: <key> [default_value]
dll_function_identifier!(INI_GetBool, data, {
    let input = unsafe { crate::buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.splitn(2, ' ').collect();

    let key = parts.get(0).map_or("", |k| k.trim());
    if key.is_empty() {
        return Err(DllError::MissingParameter("key".to_string()));
    }

    let default = parts.get(1).map_or(false, |d| d.trim().parse::<i32>().unwrap_or(0) != 0);

    let config = config::get_fish11_config()?;

    let value = match key.to_lowercase().as_str() {
        "process_incoming" => config.process_incoming,
        "process_outgoing" => config.process_outgoing,
        "encrypt_notice" => config.encrypt_notice,
        "encrypt_action" => config.encrypt_action,
        "no_fish10_legacy" => config.no_fish10_legacy,
        _ => default,
    };

    Ok(if value { "1" } else { "0" }.to_string())
});

/// Gets a string value from the config file.
/// Input: <key> [default_value]
dll_function_identifier!(INI_GetString, data, {
    let input = unsafe { crate::buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.splitn(2, ' ').collect();

    let key = parts.get(0).map_or("", |k| k.trim());
    if key.is_empty() {
        return Err(DllError::MissingParameter("key".to_string()));
    }

    let default = parts.get(1).map_or("", |d| d.trim());

    let value = match config::get_fish11_config() {
        Ok(config) => match key.to_lowercase().as_str() {
            "plain_prefix" => config.plain_prefix,
            "mark_encrypted" => config.mark_encrypted,
            _ => default.to_string(),
        },
        Err(_) => default.to_string(),
    };

    Ok(value)
});

/// Gets an integer value from the config file.
/// Input: <key> [default_value]
dll_function_identifier!(INI_GetInt, data, {
    let input = unsafe { crate::buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.splitn(2, ' ').collect();

    let key = parts.get(0).map_or("", |k| k.trim());
    if key.is_empty() {
        return Err(DllError::MissingParameter("key".to_string()));
    }

    let default = parts.get(1).map_or(0, |d| d.trim().parse::<i32>().unwrap_or(0));

    let value = match config::get_fish11_config() {
        Ok(config) => match key.to_lowercase().as_str() {
            "mark_position" => config.mark_position as i32,
            _ => default,
        },
        Err(_) => default,
    };

    Ok(value.to_string())
});

#[cfg(test)]
mod tests {

    use crate::config::Fish11Section;
    use crate::config::settings::*;

    fn setup_config() {
        let config = Fish11Section {
            process_incoming: true,
            process_outgoing: false,
            plain_prefix: "plain:".to_string(),
            encrypt_notice: true,
            encrypt_action: false,
            mark_position: 42,
            mark_encrypted: "[ENCRYPTED]".to_string(),
            no_fish10_legacy: true,
        };
        update_fish11_config(config).unwrap();
    }

    #[test]
    fn test_should_process_incoming() {
        setup_config();
        assert_eq!(should_process_incoming().unwrap(), true);
    }

    #[test]
    fn test_should_process_outgoing() {
        setup_config();
        assert_eq!(should_process_outgoing().unwrap(), false);
    }

    #[test]
    fn test_get_plain_prefix() {
        setup_config();
        assert_eq!(get_plain_prefix().unwrap(), "plain:");
    }

    #[test]
    fn test_get_encryption_mark() {
        setup_config();
        let (pos, mark) = get_encryption_mark().unwrap();
        assert_eq!(pos, 42);
        assert_eq!(mark, "[ENCRYPTED]");
    }
}
