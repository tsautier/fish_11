use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;
use crate::{dll_function_identifier, log_debug};
use fish_11_core::globals::{BUILD_DATE, BUILD_NUMBER, BUILD_TIME, BUILD_VERSION};
use std::ffi::c_char;
use std::os::raw::c_int;

dll_function_identifier!(FiSH11_GetVersion, _data, {
    let build_type = if cfg!(debug_assertions) { "DEBUG" } else { "RELEASE" };

    // Return raw version info for script to display
    let version_info = format!(
        "FiSH_11 core dll version {} (build {}) *** Compiled {} at {}Z *** Written by [GuY], licensed under the GPL-v3|{}",
        BUILD_VERSION,
        BUILD_NUMBER.as_str(),
        BUILD_DATE.as_str(),
        BUILD_TIME.as_str(),
        build_type
    );

    #[cfg(debug_assertions)]
    log_debug!("FiSH11_GetVersion called, returning: {}", version_info);

    Ok(version_info)
});
