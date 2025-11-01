use std::ffi::c_char;
use std::os::raw::c_int;

use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::buffer_utils;
use crate::config;
use crate::dll_function;
use crate::dll_interface::{MIRC_COMMAND, MIRC_HALT};
use crate::unified_error::{DllError, DllResult};
use crate::utils::normalize_nick;

dll_function!(FiSH11_FileDelKey, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };

    let nickname = normalize_nick(input.trim());
    if nickname.is_empty() {
        return Err(DllError::MissingParameter("nickname".to_string()));
    }

    log::info!("Key deletion requested for nickname: {}", nickname);

    // The `?` operator handles any errors during deletion.
    config::delete_key_default(&nickname)?;

    let message = format!("/echo -ts Key deleted for {}", nickname);
    log::info!("{}", message);

    Ok(message)
});