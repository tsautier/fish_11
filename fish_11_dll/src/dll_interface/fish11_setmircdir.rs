use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;
use crate::{buffer_utils, dll_function_identifier};
use std::ffi::c_char;
use std::os::raw::c_int;

dll_function_identifier!(FiSH11_SetMircDir, data, {
    // unsafe is required here because we are dereferencing a raw pointer from C.
    let mirc_dir = unsafe { buffer_utils::parse_buffer_input(data)? };

    if mirc_dir.is_empty() {
        return Err(DllError::MissingParameter("mIRC directory path".to_string()));
    }

    log::info!("Setting MIRCDIR to: {}", mirc_dir);

    std::env::set_var("MIRCDIR", &mirc_dir);

    log::info!("MIRCDIR environment variable set successfully");

    Ok(format!("FiSH_11 mIRC directory set to: {}", mirc_dir))
});
