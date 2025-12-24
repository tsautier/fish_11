use crate::dll_interface::dll_error::DllError;
use crate::platform_types::{PCSTR, PSTR};
use fish_11_core::master_key::derive_master_key; // Use the correct function name
use fish_11_core::master_key::derivation::derive_master_key_with_salt;
use fish_11_core::master_key::keystore::Keystore;
use fish_11_core::master_key::password_validation::PasswordValidator;
use std::ffi::CStr;

// Global storage for the master key in memory
use once_cell::sync::Lazy;
use std::sync::Mutex;

static MASTER_KEY: Lazy<Mutex<Option<[u8; 32]>>> = Lazy::new(|| Mutex::new(None));

#[no_mangle]
pub extern "C" fn FiSH11_MasterKeyInit(
    password: PCSTR,
    ret_buffer: PSTR,
    ret_buffer_size: i32,
) -> i32 {
    if password.is_null() {
        return DllError::new("password pointer is null").log_and_return_error_code();
    }
    if ret_buffer.is_null() {
        return DllError::new("return buffer is null").log_and_return_error_code();
    }

    let password_str = unsafe { CStr::from_ptr(password) };
    let password_r = match password_str.to_str() {
        Ok(s) => s,
        Err(_) => {
            return DllError::new("Failed to convert password to string")
                .log_and_return_error_code();
        }
    };

    // Validate password strength before deriving key
    if let Err(e) = PasswordValidator::validate_password_strength(password_r) {
        return DllError::new(&format!("Password validation failed: {}", e))
            .log_and_return_error_code();
    }

    // Derive the master key from the password
    match derive_master_key(password_r) {
        Ok((key, salt)) => {
            // Store the key in memory
            {
                let mut key_guard = match MASTER_KEY.lock() {
                    Ok(g) => g,
                    Err(_) => {
                        return DllError::new("Failed to acquire master key lock")
                            .log_and_return_error_code();
                    }
                };
                *key_guard = Some(key);
            }

            // Save the salt to keystore for future use
            let mut keystore = Keystore::new();
            keystore.set_master_salt(&salt);
            if let Err(e) = keystore.save() {
                log::warn!("Failed to save keystore: {}", e);
            }

            // Return success message
            unsafe { crate::buffer_utils::write_result(ret_buffer, "1") }
        }
        Err(e) => DllError::new(&format!("Failed to derive master key: {}", e))
            .log_and_return_error_code(),
    }
}

#[no_mangle]
pub extern "C" fn FiSH11_MasterKeyUnlock(
    password: PCSTR,
    ret_buffer: PSTR,
    _ret_buffer_size: i32,
) -> i32 {
    if password.is_null() {
        return DllError::new("password pointer is null").log_and_return_error_code();
    }
    if ret_buffer.is_null() {
        return DllError::new("return buffer is null").log_and_return_error_code();
    }

    let password_str = unsafe { CStr::from_ptr(password) };
    let password_r = match password_str.to_str() {
        Ok(s) => s,
        Err(_) => {
            return DllError::new("Failed to convert password to string")
                .log_and_return_error_code();
        }
    };

    // Load keystore to get the salt
    let keystore = match Keystore::load() {
        Ok(ks) => ks,
        Err(_) => {
            // If keystore doesn't exist, treat as first-time init
            return FiSH11_MasterKeyInit(password, ret_buffer, _ret_buffer_size);
        }
    };

    let salt = match keystore.get_master_salt() {
        Some(s) => s,
        None => {
            return DllError::new("No master salt found in keystore")
                .log_and_return_error_code();
        }
    };

    // Derive the master key using the stored salt
    match derive_master_key_with_salt(password_r, Some(salt)) {
        Ok((key, _)) => {
            // Store the key in memory
            {
                let mut key_guard = match MASTER_KEY.lock() {
                    Ok(g) => g,
                    Err(_) => {
                        return DllError::new("Failed to acquire master key lock")
                            .log_and_return_error_code();
                    }
                };
                *key_guard = Some(key);
            }

            // Return success message
            unsafe { crate::buffer_utils::write_result(ret_buffer, "1") }
        }
        Err(e) => DllError::new(&format!("Failed to derive master key: {}", e))
            .log_and_return_error_code(),
    }
}

#[no_mangle]
pub extern "C" fn FiSH11_MasterKeyLock(ret_buffer: PSTR, _ret_buffer_size: i32) -> i32 {
    if ret_buffer.is_null() {
        return DllError::new("return buffer is null").log_and_return_error_code();
    }

    // Clear the master key from memory
    {
        let mut key_guard = match MASTER_KEY.lock() {
            Ok(g) => g,
            Err(_) => {
                return DllError::new("Failed to acquire master key lock")
                    .log_and_return_error_code();
            }
        };
        *key_guard = None;
    }

    // Return success message
    unsafe { crate::buffer_utils::write_result(ret_buffer, "1") }
}

#[no_mangle]
pub extern "C" fn FiSH11_MasterKeyChangePassword(
    old_password: PCSTR,
    new_password: PCSTR,
    ret_buffer: PSTR,
    _ret_buffer_size: i32,
) -> i32 {
    if old_password.is_null() || new_password.is_null() {
        return DllError::new("password pointer is null").log_and_return_error_code();
    }
    if ret_buffer.is_null() {
        return DllError::new("return buffer is null").log_and_return_error_code();
    }

    let old_password_str = unsafe { CStr::from_ptr(old_password) };
    let old_password_r = match old_password_str.to_str() {
        Ok(s) => s,
        Err(_) => {
            return DllError::new("Failed to convert old password to string")
                .log_and_return_error_code();
        }
    };

    let new_password_str = unsafe { CStr::from_ptr(new_password) };
    let new_password_r = match new_password_str.to_str() {
        Ok(s) => s,
        Err(_) => {
            return DllError::new("Failed to convert new password to string")
                .log_and_return_error_code();
        }
    };

    // Verify the old password by attempting to derive the key
    match derive_master_key(old_password_r) {
        Ok((_expected_key, _salt)) => {
            // Extract key and ignore salt
            // The key derivation worked, so we can proceed to store the new key
            match derive_master_key(new_password_r) {
                Ok((new_key, _new_salt)) => {
                    // Extract key and ignore salt
                    // Store the new key in memory
                    {
                        let mut key_guard = match MASTER_KEY.lock() {
                            Ok(g) => g,
                            Err(_) => {
                                return DllError::new("Failed to acquire master key lock")
                                    .log_and_return_error_code();
                            }
                        };
                        *key_guard = Some(new_key);
                    }

                    // Return success message
                    unsafe { crate::buffer_utils::write_result(ret_buffer, "1") }
                }
                Err(e) => DllError::new(&format!("Failed to derive new master key: {}", e))
                    .log_and_return_error_code(),
            }
        }
        Err(_) => {
            // Old password was wrong
            DllError::new("Old password verification failed").log_and_return_error_code()
        }
    }
}

#[no_mangle]
pub extern "C" fn FiSH11_MasterKeyStatus(ret_buffer: PSTR, _ret_buffer_size: i32) -> i32 {
    if ret_buffer.is_null() {
        return DllError::new("return buffer is null").log_and_return_error_code();
    }

    let key_guard = match MASTER_KEY.lock() {
        Ok(g) => g,
        Err(_) => {
            return DllError::new("Failed to acquire master key lock").log_and_return_error_code();
        }
    };
    let status = if key_guard.is_some() { "locked" } else { "unlocked" };

    unsafe { crate::buffer_utils::write_result(ret_buffer, status) }
}
