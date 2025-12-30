use crate::dll_interface::dll_error::DllError;
use crate::platform_types::PCSTR;
use fish_11_core::globals::{LOGGING_KEY, MASTER_KEY};
use fish_11_core::master_key::derivation::derive_logs_kek;

#[no_mangle]
pub extern "C" fn FiSH11_LogSetKey(_key: PCSTR) -> i32 {
    // Get the master key from memory
    let master_key = {
        let key_guard = match MASTER_KEY.lock() {
            Ok(g) => g,
            Err(_) => {
                return DllError::new("Failed to acquire master key lock")
                    .log_and_return_error_code();
            }
        };

        match key_guard.as_ref() {
            Some(key) => *key,
            None => {
                return DllError::new("Master key is not set. Please unlock master key first.")
                    .log_and_return_error_code();
            }
        }
    };

    // Derive logging key from master key using HKDF
    let logging_key = derive_logs_kek(&master_key);

    // Store the derived logging key in the global variable
    {
        let mut logging_key_guard = match LOGGING_KEY.lock() {
            Ok(g) => g,
            Err(_) => {
                return DllError::new("Failed to acquire logging key lock")
                    .log_and_return_error_code();
            }
        };
        *logging_key_guard = Some(logging_key);
    }

    log::info!(
        "FiSH11_LogSetKey: in-memory log encryption key has been derived from master key and set for the current session."
    );
    0 // Success
}
