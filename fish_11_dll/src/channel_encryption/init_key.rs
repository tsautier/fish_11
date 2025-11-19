use crate::buffer_utils;
use crate::config;
use crate::crypto;
use crate::dll_function_identifier;
use crate::platform_types::BOOL;
use crate::platform_types::HWND;
use crate::unified_error::DllError;
use std::ffi::{c_char, c_int};

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

    // Get the coordinator's own nickname from config
    let self_nick = config::get_fish11_config()?.nickname;

    if self_nick.is_empty() {
        return Err(DllError::ConfigError(
            "Nickname not set in configuration. Please set your nickname in the FiSH11 configuration."
                .to_string(),
        ));
    }

    // 1. Generate a fresh random 32-byte channel key
    let channel_key = crypto::generate_symmetric_key()?;

    // 2. Store the channel key locally and initialize the ratchet state
    config::set_channel_key(channel_name, &channel_key)?;
    config::init_ratchet_state(channel_name, channel_key)?;

    let mut commands = Vec::new();
    let mut failed_members = Vec::new();

    // 3. Wrap the key for each member and create NOTICE commands
    for member_nick in members {
        // Skip self (coordinator doesn't need to send to themselves)
        if *member_nick == self_nick {
            continue;
        }

        // Retrieve the pre-shared key with this member
        let shared_key_vec = match config::get_key(member_nick, None) {
            Ok(key) => key,
            Err(_) => {
                // Collect failed members instead of failing immediately
                failed_members.push(*member_nick);
                continue;
            }
        };

        let shared_key: [u8; 32] = shared_key_vec.as_slice().try_into().map_err(|_| {
            DllError::ConfigError(format!("Invalid key length for member {}", member_nick))
        })?;

        // Encrypt (wrap) the channel key using the member's pre-shared key
        let wrapped_key = crypto::wrap_key(&channel_key, &shared_key)?;

        // Create the NOTICE command for this member
        // Format: /notice <nick> :+FiSH-CEP-KEY <channel> <coordinator> <wrapped_key_b64>
        let command = format!(
            "/notice {} :+FiSH-CEP-KEY {} {} {}",
            member_nick, channel_name, self_nick, wrapped_key
        );
        commands.push(command);
    }

    // Check if any members failed
    if !failed_members.is_empty() {
        let failed_list = failed_members.join(", ");
        return Err(DllError::ConfigError(format!(
            "Missing pre-shared keys for: {}. Please establish keys with these users first using /fish11_X25519_INIT",
            failed_list
        )));
    }

    // Check if we have any valid recipients
    if commands.is_empty() {
        return Err(DllError::InvalidInput {
            param: "members".to_string(),
            reason: "No valid recipients (all members either lack pre-shared keys or are yourself)"
                .to_string(),
        });
    }

    // 4. Return all commands concatenated for mIRC to execute
    // Add a confirmation echo at the end
    commands.push(format!(
        "[KEY] Channel key for {} generated and distributed to {} member(s)",
        channel_name,
        commands.len()
    ));

    Ok(commands.join(" | "))
});
