#[cfg(test)]
mod tests {
    use std::ffi::CString;
    use std::os::raw::c_char;
    use std::ptr;

    use crate::config::{self, Fish11Section};
    use crate::dll_interface::{MIRC_HALT, ini_types::*};
    use crate::platform_types::HWND;
    use std::os::raw::c_int;

    // Helper to set up a clean config for each test
    fn setup_test_config() {
        let mut config = config::CONFIG.lock();
        *config = config::FishConfig::new();
        config.fish11 = Fish11Section {
            nickname: "testnick".to_string(),
            process_incoming: true,
            process_outgoing: false,
            plain_prefix: "test_prefix ".to_string(),
            encrypt_notice: true,
            encrypt_action: false,
            mark_position: 5,
            mark_encrypted: "[encrypted]".to_string(),
            default_fish_pattern: "".to_string(),
            encryption_prefix: "".to_string(),
            fish_prefix: false,
            no_fish10_legacy: true,
            key_ttl: Some(0),
        };
    }

    // Helper to call the DLL functions
    fn call_dll_function(
        func: extern "system" fn(
            hwnd: *mut HWND,
            a: *mut HWND,
            data: *mut c_char,
            parms: *mut c_char,
            result: *mut c_int,
            show: *mut c_int,
        ) -> c_int,
        input: &str,
    ) -> (c_int, String) {
        let mut buffer: [c_char; 1024] = [0; 1024];
        let c_input = CString::new(input).unwrap();

        // Copy input to buffer
        unsafe {
            ptr::copy_nonoverlapping(
                c_input.as_ptr(),
                buffer.as_mut_ptr(),
                c_input.as_bytes().len(),
            );
        }

        let result_code = unsafe {
            func(
                ptr::null_mut(),
                ptr::null_mut(),
                buffer.as_mut_ptr(),
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null_mut(),
            )
        };

        let result_str = if result_code != MIRC_HALT {
            unsafe { std::ffi::CStr::from_ptr(buffer.as_ptr()).to_string_lossy().into_owned() }
        } else {
            "".to_string()
        };

        (result_code, result_str)
    }

    // INI_GetBool Tests
    #[test]
    fn test_ini_getbool_process_incoming_true() {
        setup_test_config();
        let (_, result) = call_dll_function(INI_GetBool as _, "process_incoming");
        assert_eq!(result, "1");
    }

    #[test]
    fn test_ini_getbool_process_outgoing_false() {
        setup_test_config();
        let (_, result) = call_dll_function(INI_GetBool as _, "process_outgoing");
        assert_eq!(result, "0");
    }

    #[test]
    fn test_ini_getbool_unknown_key_with_default_true() {
        setup_test_config();
        let (_, result) = call_dll_function(INI_GetBool as _, "unknown_key 1");
        assert_eq!(result, "1");
    }

    #[test]
    fn test_ini_getbool_unknown_key_with_default_false() {
        setup_test_config();
        let (_, result) = call_dll_function(INI_GetBool as _, "unknown_key 0");
        assert_eq!(result, "0");
    }

    #[test]
    fn test_ini_getbool_empty_input() {
        setup_test_config();
        let (result_code, msg) = call_dll_function(INI_GetBool as _, "");
        // Should return error message (MIRC_COMMAND with raw error text)
        assert_eq!(result_code, crate::dll_interface::MIRC_COMMAND);
        // Empty input results in "invalid input" or "null pointer" error
        assert!(
            msg.to_lowercase().contains("invalid")
                || msg.to_lowercase().contains("null")
                || msg.to_lowercase().contains("missing")
        );
    }

    // INI_GetString Tests
    #[test]
    fn test_ini_getstring_plain_prefix() {
        setup_test_config();
        let (_, result) = call_dll_function(INI_GetString as _, "plain_prefix");
        assert_eq!(result, "test_prefix ");
    }

    #[test]
    fn test_ini_getstring_mark_encrypted() {
        setup_test_config();
        let (_, result) = call_dll_function(INI_GetString as _, "mark_encrypted");
        assert_eq!(result, "[encrypted]");
    }

    #[test]
    fn test_ini_getstring_unknown_key_with_default() {
        setup_test_config();
        let (_, result) = call_dll_function(INI_GetString as _, "unknown_key my_default");
        assert_eq!(result, "my_default");
    }

    #[test]
    fn test_ini_getstring_unknown_key_no_default() {
        setup_test_config();
        let (_, result) = call_dll_function(INI_GetString as _, "unknown_key");
        assert_eq!(result, "");
    }

    // INI_GetInt Tests
    #[test]
    fn test_ini_getint_mark_position() {
        setup_test_config();
        let (_, result) = call_dll_function(INI_GetInt as _, "mark_position");
        assert_eq!(result, "5");
    }

    #[test]
    fn test_ini_getint_unknown_key_with_default() {
        setup_test_config();
        let (_, result) = call_dll_function(INI_GetInt as _, "unknown_key 123");
        assert_eq!(result, "123");
    }

    #[test]
    fn test_ini_getint_unknown_key_no_default() {
        setup_test_config();
        let (_, result) = call_dll_function(INI_GetInt as _, "unknown_key");
        assert_eq!(result, "0");
    }
}
