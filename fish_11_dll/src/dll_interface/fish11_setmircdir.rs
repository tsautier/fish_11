use std::ffi::c_char;
use std::os::raw::c_int;

use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::buffer_utils;
use crate::dll_function;
use crate::dll_interface::{MIRC_COMMAND, MIRC_HALT};
use crate::unified_error::{DllError, DllResult};

dll_function!(FiSH11_SetMircDir, data, {
    // unsafe is required here because we are dereferencing a raw pointer from C.
    let mirc_dir = unsafe { buffer_utils::parse_buffer_input(data)? };

    if mirc_dir.is_empty() {
        return Err(DllError::MissingParameter(
            "mIRC directory path".to_string(),
        ));
    }

    log::info!("Setting MIRCDIR to: {}", mirc_dir);

    std::env::set_var("MIRCDIR", &mirc_dir);

    log::info!("MIRCDIR environment variable set successfully");

    Ok(format!(
        "/echo -ts FiSH_11 mIRC directory set to: {}",
        mirc_dir
    ))
});