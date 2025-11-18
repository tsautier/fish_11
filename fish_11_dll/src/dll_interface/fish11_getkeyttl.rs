//! Retrieves the Time-To-Live (TTL) for an encryption key.
//!
//! `FiSH11_GetKeyTTL` checks the remaining lifetime of a key that was established
//! through a key exchange. Exchange keys have a 24-hour TTL from their creation time.
//!
//! # Returns
//!
//! - A string containing the number of seconds remaining until expiration (e.g., "43200")
//! - `"EXPIRED"` if the key has passed its 24-hour lifetime
//! - `"NO_TTL"` if the key exists but is not an exchange key (manually set keys don't expire)
//! - An error if the nickname is invalid or missing
//!
//! # When to Use
//!
//! Use this function to:
//! - Check if a key from a key exchange is still valid before encrypting/decrypting
//! - Display key expiration status to users in the UI
//! - Determine if a new key exchange is needed

use std::ffi::c_char;
use std::os::raw::c_int;

use crate::platform_types::{BOOL, HWND};
use crate::{
    buffer_utils, config, config::key_management::get_key_ttl, dll_function_identifier, log_debug,
    unified_error::DllError, utils::normalize_nick,
};

dll_function_identifier!(FiSH11_GetKeyTTL, data, {
    // 1. Parse input: <nickname>
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let nickname = normalize_nick(input.trim());

    if nickname.is_empty() {
        return Err(DllError::MissingParameter("nickname".to_string()));
    }

    log_debug!("Getting key TTL for nickname: {}", nickname);

    // 2. Get the TTL from the config.
    match get_key_ttl(&nickname, None)? {
        Some(ttl) => {
            if ttl > 0 {
                Ok(ttl.to_string())
            } else {
                Ok("EXPIRED".to_string())
            }
        }
        None => Ok("NO_TTL".to_string()),
    }
});
