use std::ffi::c_char;
use std::os::raw::c_int;

use crate::config;
use crate::dll_function_identifier;
use crate::dll_interface::CStr;
use crate::dll_interface::ptr;
use crate::platform_types::BOOL;
use crate::platform_types::HWND;
use crate::unified_error::DllError;

dll_function_identifier!(FiSH11_GetConfigPath, _data, {
    let config_path = config::get_config_path()?;
    Ok(config_path.to_string_lossy().to_string())
});

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fish11_getconfigpath_normal() {
        let _ = crate::logging::init_logger(log::LevelFilter::Debug);
        let mut buffer: [c_char; 260] = [0; 260];
        let result = unsafe {
            FiSH11_GetConfigPath(
                ptr::null_mut(),
                ptr::null_mut(),
                buffer.as_mut_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };
        assert_eq!(result, crate::dll_interface::MIRC_IDENTIFIER);
        let c_str = unsafe { CStr::from_ptr(buffer.as_ptr()) };
        let path_str = c_str.to_str().unwrap();
        assert!(path_str.contains("fish_11.ini"));
    }
}
