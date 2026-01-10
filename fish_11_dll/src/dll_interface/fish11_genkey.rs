use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;
use crate::utils::{self, normalize_nick};
use crate::{buffer_utils, config, dll_function_identifier, log_debug};
use std::ffi::c_char;
use std::os::raw::c_int;

dll_function_identifier!(FiSH11_GenKey, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };

    let parts: Vec<&str> = input.splitn(2, ' ').collect();
    let target_raw = parts.get(0).unwrap_or(&"").trim();

    // Normalize target to strip STATUSMSG prefixes (@#chan, +#chan, etc.)
    let normalized_target = crate::utils::normalize_target(target_raw);
    let nickname = normalize_nick(normalized_target);

    if nickname.is_empty() {
        return Err(DllError::MissingParameter("nickname".to_string()));
    }

    let network = parts.get(1).map(|s| s.trim());

    #[cfg(debug_assertions)]
    log_debug!(
        "Generating key for nickname/channel: {} (network: {:?}, original: {})",
        nickname,
        network,
        target_raw
    );

    // 1. Generate a cryptographically secure random key.
    let mut key = [0u8; 32];
    let random_bytes = utils::generate_random_bytes(32);

    key.copy_from_slice(&random_bytes);

    // 2. Store the key, with overwrite disabled to prevent accidental data loss.
    // This will return a `DllError::DuplicateEntry` if the key already exists.
    config::set_key(&nickname, &key, network, false, false)?;

    Ok(format!("New key pair generated successfully for {}", nickname))
});
