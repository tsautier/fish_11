use crate::dll_function_identifier;
use crate::log_debug;
use crate::unified_error::DllError;
use fish_11_core::globals::{BUILD_DATE, BUILD_TIME, BUILD_VERSION};

use crate::platform_types::{BOOL, HWND};

use std::ffi::c_char;
use std::os::raw::c_int;

dll_function_identifier!(FiSH11_CoreVersion, _data, {
    // Return raw version info for script to display
    let version_info = format!(
        "FiSH_11 core dll version {} *** Compiled {} at {} *** Written by [GuY], licensed under the GPL-v3",
        BUILD_VERSION, BUILD_DATE, BUILD_TIME
    );

    log_debug!("FiSH11_GetVersion called, returning: {}", version_info);

    Ok(version_info)
});
