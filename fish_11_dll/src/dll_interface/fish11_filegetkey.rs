use std::ffi::c_char;
use std::os::raw::c_int;

use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::buffer_utils;
use crate::config;
use crate::dll_function;
use crate::dll_interface::{MIRC_COMMAND, MIRC_HALT};
use crate::unified_error::{DllError, DllResult};
use crate::utils::{base64_encode, normalize_nick};

dll_function!(FiSH11_FileGetKey, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };

    let nickname = normalize_nick(input.trim());
    if nickname.is_empty() {
        return Err(DllError::MissingParameter("nickname".to_string()));
    }

    log::debug!("Retrieving key for nickname: {}", nickname);

    // The `?` operator will automatically convert the error from `config::get_key_default`
    // into our `DllError` type, thanks to the `From<FishError>` implementation.
    let key = config::get_key_default(&nickname)?;

    log::debug!("Key found, encoding as base64");
    let base64_key = base64_encode(&key);

    Ok(format!("/echo -ts Key for {}: {}", nickname, base64_key))
});