use std::ffi::{c_char, CStr};
use std::os::raw::c_int;
use std::ptr;

use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::config;
use crate::dll_function;
use crate::dll_interface::{MIRC_COMMAND, MIRC_HALT, MIRC_IDENTIFIER};
use crate::unified_error::{DllError, DllResult};

dll_function!(FiSH11_GetConfigPath, _data, {
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
                0,
                0,
            )
        };
        assert_eq!(result, MIRC_COMMAND);
        let c_str = unsafe { CStr::from_ptr(buffer.as_ptr()) };
        let path_str = c_str.to_str().unwrap();
        assert!(path_str.contains("fish_11.ini"));
    }
}