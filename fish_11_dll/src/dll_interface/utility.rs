use std::ffi::{c_char};
use std::os::raw::c_int;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use sha2::{Digest, Sha256};
use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::dll_function;
use crate::unified_error::{DllError, DllResult};
use crate::{buffer_utils, config, utils::normalize_nick};

/// Displays the version information of the FiSH_11 DLL.
dll_function!(FiSH11_GetVersion, _data, {
    let version_info = format!(
        "/echo -ts {} - Licensed under the GPL v3.",
        crate::FISH_MAIN_VERSION
    );
    Ok(version_info)
});

/// Generates a key fingerprint for the specified nickname.
///
/// The fingerprint can be used to verify key authenticity through a separate channel.
dll_function!(FiSH11_GetKeyFingerprint, data, {
    let nickname = normalize_nick(&(unsafe { buffer_utils::parse_buffer_input(data)? }));

    if nickname.is_empty() {
        return Err(DllError::MissingParameter("nickname".to_string()));
    }

    log::debug!("Generating fingerprint for: {}", nickname);

    // 1. Get the key for the nickname.
    let key = config::get_key_default(&nickname)?;

    // 2. Generate fingerprint using SHA-256.
    let mut hasher = Sha256::new();
    hasher.update(&key);
    let hash = hasher.finalize();

    // 3. Take first 16 bytes of the hash and encode as base64.
    let fp_base64 = BASE64.encode(&hash[0..16]);

    // 4. Format with spaces for readability (groups of 4 chars).
    let mut formatted_fp = String::with_capacity(24);
    for (i, c) in fp_base64.chars().take(16).enumerate() {
        if i > 0 && i % 4 == 0 {
            formatted_fp.push(' ');
        }
        formatted_fp.push(c);
    }

    log::info!("Successfully generated fingerprint for {}", nickname);

    // 5. Format the response message.
    Ok(format!(
        "/echo -ts Key fingerprint for {}: {}",
        nickname,
        formatted_fp
    ))
});