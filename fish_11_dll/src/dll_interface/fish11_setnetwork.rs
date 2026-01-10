use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;
use crate::{buffer_utils, dll_function_identifier};
use std::ffi::c_char;
use std::os::raw::c_int;

dll_function_identifier!(FiSH11_SetNetwork, data, {
    // Parse input: <network_name>
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let network_name = input.trim();

    if network_name.is_empty() {
        return Err(DllError::MissingParameter("network_name".to_string()));
    }

    // Store the current network globally
    crate::set_current_network(network_name);

    Ok(format!("Network set to: {}", network_name))
});
