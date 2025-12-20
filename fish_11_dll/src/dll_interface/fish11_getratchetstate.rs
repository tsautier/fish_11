use std::ffi::c_char;
use std::os::raw::c_int;

use crate::config::with_config;
use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;
use crate::{buffer_utils, dll_function_identifier, log_debug, log_info, log_warn};

/// Gets ratchet state information for a channel
///
/// Input: <channel>
///
/// Output: Returns a formatted string with ratchet state information or an error message
dll_function_identifier!(FiSH11_GetRatchetState, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.split_whitespace().collect();

    if parts.is_empty() {
        return Err(DllError::InvalidInput {
            param: "channel".to_string(),
            reason: "Channel name is required".to_string(),
        });
    }

    let channel = parts[0];
    log_debug!("FiSH11_GetRatchetState: retrieving ratchet state for channel '{}'", channel);

    let result = with_config(|config| {
        let channel_name = channel.to_lowercase();

        // Get ratchet state if it exists
        let ratchet_info = if let Some(state) = config.channel_ratchet_states.get(&channel_name) {
            format!(
                "Ratchet state for '{}': epoch={}, key_length={}",
                channel_name,
                state.epoch,
                state.current_key.len()
            )
        } else {
            format!("No ratchet state found for channel '{}'", channel_name)
        };

        // Get nonce cache info if it exists
        let nonce_cache_info = if let Some(cache) = config.channel_nonce_caches.get(&channel_name) {
            format!("Nonce cache: {} entries", cache.recent_nonces.len())
        } else {
            "No nonce cache found".to_string()
        };

        Ok(format!("{} | {}", ratchet_info, nonce_cache_info))
    });

    match result {
        Ok(info) => {
            log_info!("FiSH11_GetRatchetState: retrieved state for channel '{}'", channel);
            Ok(info)
        }
        Err(e) => {
            log_warn!(
                "FiSH11_GetRatchetState: error retrieving state for channel '{}': {}",
                channel,
                e
            );
            Err(e.into())
        }
    }
});
