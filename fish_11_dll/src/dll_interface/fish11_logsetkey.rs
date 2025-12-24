use crate::dll_interface::dll_error::DllError;
use crate::platform_types::PCSTR;
use fish_11_core::globals::LOGGING_KEY;
use fish_11_core::master_key::derivation::{derive_master_key, derive_logs_kek};
use std::ffi::CStr;

#[no_mangle]
pub extern "C" fn FiSH11_LogSetKey(key: PCSTR) -> i32 {
    if key.is_null() {
        return DllError::new("key pointer is null").log_and_return_error_code();
    }

    let key_str = unsafe { CStr::from_ptr(key) };
    let key_r = match key_str.to_str() {
        Ok(s) => s,
        Err(_) => {
            return DllError::new("Failed to convert key to string").log_and_return_error_code();
        }
    };

    // Derive a secure logging key using proper KDF (Argon2id + HKDF)
    // First, derive master key from password
    let (master_key, _salt) = match derive_master_key(key_r) {
        Ok(result) => result,
        Err(e) => {
            return DllError::new(&format!("Failed to derive master key: {}", e))
                .log_and_return_error_code();
        }
    };
    
    // Then derive logging KEK from master key
    let key_bytes = derive_logs_kek(&master_key);

    // Store the key in the global variable
    {
        let mut key_guard = match LOGGING_KEY.lock() {
            Ok(g) => g,
            Err(_) => {
                return DllError::new("Failed to acquire logging key lock")
                    .log_and_return_error_code();
            }
        };
        *key_guard = Some(key_bytes);
    }

    log::info!(
        "FiSH11_LogSetKey: in-memory log encryption key has been set for the current session."
    );
    0 // Success
}
