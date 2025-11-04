use crate::buffer_utils;
use crate::config;
use crate::crypto;
use crate::dll_function_identifier;
use crate::unified_error::{DllError, DllResult};
use base64::{engine::general_purpose, Engine as _};
use std::ffi::{c_char, c_int};
use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

dll_function_identifier!(FiSH11_InitChannelKey, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let args: Vec<&str> = input.split_whitespace().collect();

    if args.len() < 2 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "Usage: <#channel> <nick1> [nick2] ...".to_string(),
        });
    }

    let channel_name = args[0];
    let members = &args[1..];
    let self_nick = config::get_fish11_config()?.nickname;

    // 1. Generate and save new channel key
    let channel_key = crypto::generate_symmetric_key();
    config::set_channel_key(channel_name, &channel_key)?;

    let mut commands = Vec::new();

    // 2. Wrap key for each member and create NOTICE commands
    for member_nick in members {
        let shared_key_vec = config::get_key(member_nick, None)?;
        let shared_key: [u8; 32] = shared_key_vec.as_slice().try_into().map_err(|_|
            DllError::ConfigError(format!("Invalid key length for member {}", member_nick))
        )?;

        let wrapped_key = crypto::wrap_key(&channel_key, &shared_key)?;
        let b64_wrapped_key = general_purpose::STANDARD.encode(wrapped_key.as_bytes());

        let command = format!(
            "/notice {} :!FCEP-KEY {} {} {}",
            member_nick, channel_name, self_nick, b64_wrapped_key
        );
        commands.push(command);
    }

    // 3. Return all commands concatenated for mIRC to execute
    Ok(commands.join(" | "))
});