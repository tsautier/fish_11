use std::ffi::c_char;
use std::os::raw::c_int;

use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;
use crate::{config, dll_function_identifier, log_debug};

/// Gets a boolean value from the config file.
/// Input: <key> [default_value]
dll_function_identifier!(INI_GetBool, data, {
    let input = unsafe { crate::buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.splitn(2, ' ').collect();

    let key = parts.get(0).map_or("", |k| k.trim());
    if key.is_empty() {
        return Err(DllError::MissingParameter("key".to_string()));
    }

    let default = parts.get(1).map_or(false, |s| {
        let s = s.trim();
        if s.is_empty() {
            return false;
        }
        // Handle common boolean strings first
        if s.eq_ignore_ascii_case("true") {
            return true;
        }
        if s.eq_ignore_ascii_case("false") {
            return false;
        }
        // Fallback to integer parsing for 1/0
        match s.parse::<i32>() {
            Ok(v) => v != 0,
            Err(_) => {
                log_debug!("INI_GetBool: could not parse default value '{}' as bool or int, defaulting to false.", s);
                false
            }
        }
    });

    let config = config::get_fish11_config()?;

    let value = match key.to_lowercase().as_str() {
        "process_incoming" => config.process_incoming,
        "process_outgoing" => config.process_outgoing,
        "encrypt_notice" => config.encrypt_notice,
        "encrypt_action" => config.encrypt_action,
        "no_fish10_legacy" => config.no_fish10_legacy,
        "fish_prefix" => config.fish_prefix,
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

    let default = parts.get(1).map_or("".to_string(), |d| d.trim().to_string());

    let config = config::get_fish11_config()?;

    let value = match key.to_lowercase().as_str() {
        "plain_prefix" => config.plain_prefix,
        "mark_encrypted" => config.mark_encrypted,
        "encryption_prefix" => config.encryption_prefix,
        _ => default,
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

    let default = parts.get(1).map_or(0, |s| {
        let s = s.trim();
        if s.is_empty() {
            return 0;
        }
        match s.parse::<i32>() {
            Ok(v) => v,
            Err(_) => {
                log_debug!(
                    "INI_GetInt: could not parse default value '{}' as int, defaulting to 0.",
                    s
                );
                0
            }
        }
    });

    let config = config::get_fish11_config()?;

    let value = match key.to_lowercase().as_str() {
        "mark_position" => config.mark_position as i32,
        _ => default,
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
            nickname: "".to_string(),
            key_ttl: Some(0),
            encryption_prefix: "+FiSH".to_string(),
            fish_prefix: false,
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
