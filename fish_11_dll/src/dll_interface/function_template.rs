//! Template for DLL interface functions to reduce boilerplate

use std::ffi::c_char;
use std::os::raw::c_int;
use std::time::{Duration, Instant};

use crate::buffer_utils;
use crate::dll_function_utils::generate_trace_id;
use crate::dll_interface::{MIRC_HALT, get_buffer_size};

/// Configuration for DLL function execution
pub struct FunctionConfig {
    pub name: &'static str,
    pub timeout: Duration,
    pub validate_input: bool,
    pub log_entry_exit: bool,
}

impl Default for FunctionConfig {
    fn default() -> Self {
        Self {
            name: "Unknown",
            timeout: Duration::from_secs(5),
            validate_input: true,
            log_entry_exit: true,
        }
    }
}

/// Execute a DLL function with common boilerplate handling
pub fn execute_dll_function<F, R>(data: *mut c_char, config: FunctionConfig, handler: F) -> c_int
where
    F: FnOnce(&str, &str) -> Result<R, String> + std::panic::UnwindSafe,
    R: AsRef<str>,
{
    let trace_id = generate_trace_id();

    if config.log_entry_exit {
        crate::logging::log_function_entry::<&str>(config.name, None);
    }

    // Validate buffer and data pointer
    let buffer_size = get_buffer_size() as usize;
    if buffer_size <= 1 || data.is_null() {
        if config.log_entry_exit {
            crate::logging::log_function_exit::<i32>(config.name, Some(MIRC_HALT));
        }
        return MIRC_HALT;
    }

    // Use panic handler to prevent crashes
    let result = std::panic::catch_unwind(|| {
        let start_time = Instant::now();

        // Parse input
        let input = unsafe {
            match buffer_utils::parse_buffer_input(data) {
                Ok(input) => input,
                Err(e) => {
                    return buffer_utils::write_error_message(data, e);
                }
            }
        };

        // Check timeout before processing
        if start_time.elapsed() > config.timeout {
            return unsafe { buffer_utils::write_error_message(data, "function timed out") };
        }

        // Execute the actual function logic
        match handler(&input, &trace_id) {
            Ok(result) => unsafe { buffer_utils::write_result(data, result.as_ref()) },
            Err(error) => unsafe { buffer_utils::write_error_message(data, &error) },
        }
    });

    let return_code = match result {
        Ok(code) => code,
        Err(_) => {
            // Handle panic
            unsafe { buffer_utils::write_error_message(data, "internal error occurred") }
        }
    };

    if config.log_entry_exit {
        crate::logging::log_function_exit::<i32>(config.name, Some(return_code));
    }

    return_code
}

/// Macro to create a DLL function with reduced boilerplate
#[macro_export]
macro_rules! create_dll_function {
    ($name:ident, $config:expr, $handler:expr) => {
        #[no_mangle]
        #[allow(non_snake_case)]
        pub extern "stdcall" fn $name(
            _m_wnd: HWND,
            _a_wnd: HWND,
            data: *mut c_char,
            _parms: *mut c_char,
            _show: BOOL,
            _nopause: BOOL,
        ) -> c_int {
            $crate::dll_interface::function_template::execute_dll_function(data, $config, $handler)
        }
    };
}
