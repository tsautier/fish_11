use std::ffi::{c_char, c_int};

// Note: base64 imports removed as we now pass the base64 string directly
// to unwrap_key() without intermediate decoding/encoding

use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;
use crate::{buffer_utils, config, crypto, dll_function_identifier};

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
                "SECURITY: +FiSH-CEP-KEY sender mismatch - claims to be '{}' but actually from '{}' (REJECTED)",
                coordinator_nick, actual_sender
            ),
        });
    }

    // Retrieve the pre-shared symmetric key with the coordinator
    let shared_key_vec = config::get_key(coordinator_nick, None)?;
    let shared_key: [u8; 32] = shared_key_vec.as_slice().try_into().map_err(|_| {
        DllError::ConfigError(format!("Invalid key length for coordinator {}", coordinator_nick))
    })?;

    // OPTIMIZATION: Pass the base64-encoded wrapped key directly to unwrap_key
    // The unwrap_key function internally handles the base64 decoding, so we avoid
    // the redundant decode-encode cycle that was previously done here.
    // This improves performance and reduces potential encoding/decoding mismatches.

    // IMPORTANT: b64_wrapped_key should contain ONLY the base64 part (without +FiSH prefix)
    // If the input includes the prefix, we need to extract just the base64 portion
    let wrapped_key_only = if b64_wrapped_key.starts_with("+FiSH ") {
        // Extract the part after "+FiSH " (6 characters)
        &b64_wrapped_key[6..]
    } else {
        b64_wrapped_key
    };

    // Unwrap (decrypt) the channel key using the shared key
    let channel_key = crypto::unwrap_key(wrapped_key_only, &shared_key)?;

    // Store the channel key for this channel
    config::set_channel_key(channel_name, &channel_key)?;

    // Initialize the ratchet state with this new key
    config::init_ratchet_state(channel_name, channel_key)?;

    Ok(format!("Channel key for {} successfully received from {}", channel_name, coordinator_nick))
});
