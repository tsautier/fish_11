use crate::buffer_utils;
use crate::config;
use crate::crypto;
use crate::dll_function_identifier;
use crate::unified_error::{DllError, DllResult};
use base64::{Engine as _, engine::general_purpose};
use std::ffi::{c_char, c_int};
use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

dll_function_identifier!(FiSH11_ProcessChannelKey, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let args: Vec<&str> = input.splitn(3, ' ').collect();

    if args.len() < 3 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "Usage: <#channel> <coordinator_nick> <base64_wrapped_key>".to_string(),
        });
    }

    let channel_name = args[0];
    let coordinator_nick = args[1];
    let b64_wrapped_key = args[2];

    let shared_key_vec = config::get_key(coordinator_nick, None)?;
    let shared_key: [u8; 32] = shared_key_vec.as_slice().try_into().map_err(|_| {
        DllError::ConfigError(format!("Invalid key length for coordinator {}", coordinator_nick))
    })?;

    let wrapped_key_bytes = general_purpose::STANDARD.decode(b64_wrapped_key)?;
    let wrapped_key_str = String::from_utf8(wrapped_key_bytes)?;

    let channel_key = crypto::unwrap_key(&wrapped_key_str, &shared_key)?;

    config::set_channel_key(channel_name, &channel_key)?;

    Ok(format!("/echo -ts Key for channel {} successfully processed.", channel_name))
});
