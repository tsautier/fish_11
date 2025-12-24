use crate::dll_interface::dll_error::DllError;
use crate::platform_types::PCSTR;
use fish_11_core::globals::LOGGING_KEY;
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

    // Derive a 32-byte key from the input using a simple method
    // In a real implementation, we'd use a proper KDF like Argon2 or PBKDF2
    use sha2::Digest;
    let mut hasher = sha2::Sha256::new();
    hasher.update(key_r.as_bytes());
    let hash = hasher.finalize();

    // Convert to fixed-size array
    let key_bytes: [u8; 32] = hash.into();

    // Store the key in the global variable
    {
        let mut key_guard = match LOGGING_KEY.lock() {
            Ok(g) => g,
            Err(_) => return DllError::new("Failed to acquire logging key lock").log_and_return_error_code(),
        };
        *key_guard = Some(key_bytes);
    }

    log::info!("FiSH11_LogSetKey: in-memory log encryption key has been set for the current session.");
    0 // Success
}
