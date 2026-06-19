//! FiSH 10 Legacy Delete Key Function
//!
//! This function allows removing legacy Blowfish keys for compatibility
//! with FiSH 10 encryption.

use crate::platform_types::{BOOL, HWND, c_char, c_int};
use crate::unified_error::DllError;
use crate::{buffer_utils, dll_function_identifier, legacy, log_debug, log_info};

dll_function_identifier!(FiSH10_DelKey, data, {
    // Parse input: <target>
    let input_str = unsafe { buffer_utils::parse_buffer_input(data)? };
    let target = crate::utils::normalize_target_lowercase(&input_str);

    #[cfg(debug_assertions)]
    log_debug!("FiSH10: deleting legacy key for '{}'", target);

    // Remove the key from the legacy key store
    legacy::fish10_key_management::remove_legacy_key(&target)?;

    log_info!("FiSH10: successfully removed legacy key for '{}'", target);

    Ok(format!("legacy key deleted for {}", target))
});
