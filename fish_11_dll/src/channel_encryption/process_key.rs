use crate::buffer_utils;
use crate::config;
use crate::crypto;
use crate::dll_function_identifier;
use crate::unified_error::DllError;
use base64::{Engine as _, engine::general_purpose};
use std::ffi::{c_char, c_int};
use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

dll_function_identifier!(FiSH11_ProcessChannelKey, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let args: Vec<&str> = input.splitn(4, ' ').collect();

    if args.len() < 4 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason:
                "Usage: <#channel> <coordinator_nick> <actual_sender_nick> <base64_wrapped_key>"
                    .to_string(),
        });
    }

    let channel_name = args[0];
    let coordinator_nick = args[1];
    let actual_sender = args[2];
    let b64_wrapped_key = args[3];

    // SECURITY: Verify sender authenticity
    // The actual_sender is provided by the IRC layer (from the :nick!user@host prefix)
    // and must match the claimed coordinator_nick to prevent impersonation attacks.
    if coordinator_nick != actual_sender {
        return Err(DllError::InvalidInput {
            param: "sender".to_string(),
            reason: format!(
                "SECURITY: FCEP-KEY sender mismatch - claims to be '{}' but actually from '{}' (REJECTED)",
                coordinator_nick, actual_sender
            ),
        });
    }

    // Retrieve the pre-shared symmetric key with the coordinator
    let shared_key_vec = config::get_key(coordinator_nick, None)?;
    let shared_key: [u8; 32] = shared_key_vec.as_slice().try_into().map_err(|_| {
        DllError::ConfigError(format!("Invalid key length for coordinator {}", coordinator_nick))
    })?;

    // Decode the base64-encoded wrapped key
    let wrapped_key_bytes =
        general_purpose::STANDARD.decode(b64_wrapped_key).map_err(|e| DllError::InvalidInput {
            param: "wrapped_key".to_string(),
            reason: format!("Invalid base64: {}", e),
        })?;

    // Note: The wrapped_key_bytes are already in binary format (nonce + ciphertext + tag)
    // We need to re-encode them as base64 string for the unwrap_key function which expects &str
    let wrapped_key_b64 = general_purpose::STANDARD.encode(&wrapped_key_bytes);

    // Unwrap (decrypt) the channel key using the shared key
    let channel_key = crypto::unwrap_key(&wrapped_key_b64, &shared_key)?;

    // Store the channel key for this channel
    config::set_channel_key(channel_name, &channel_key)?;

    // Initialize the ratchet state with this new key
    config::init_ratchet_state(channel_name, channel_key)?;

    Ok(format!(
        "/echo -ats Channel key for {} successfully received from {}",
        channel_name, coordinator_nick
    ))
});
