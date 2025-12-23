use crate::dll_interface::dll_error::DllError;
use crate::platform_types::{PCSTR, PSTR};
use crate::utils::copy_to_return_buffer;
use chacha20poly1305::{aead::{Aead, KeyInit, OsRng}, ChaCha20Poly1305, Nonce};
use fish_11_core::globals::LOGGING_KEY;
use std::ffi::CStr;

fn encrypt_log_message(key: &[u8], plaintext: &str) -> Result<String, DllError> {
    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| DllError::new("Invalid key length for ChaCha20-Poly1305"))?;

    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| DllError::new("Encryption failed"))?;

    // Concatenate nonce + ciphertext and encode as base64
    let mut result = nonce.to_vec();
    result.extend_from_slice(&ciphertext);

    Ok(base64::encode(&result))
}

#[no_mangle]
pub extern "C" fn FiSH11_LogEncrypt(plaintext: PCSTR, ret_buffer: PSTR, ret_buffer_size: i32) -> i32 {
    if plaintext.is_null() {
        return DllError::new("plaintext pointer is null").log_and_return_error_code();
    }
    if ret_buffer.is_null() {
        return DllError::new("return buffer is null").log_and_return_error_code();
    }

    let plaintext_str = unsafe { CStr::from_ptr(plaintext) };
    let plaintext_r = match plaintext_str.to_str() {
        Ok(s) => s,
        Err(_) => {
            return DllError::new("Failed to convert plaintext to string")
                .log_and_return_error_code()
        }
    };

    let key_guard = LOGGING_KEY.lock();
    if let Some(key) = key_guard.as_ref() {
        match encrypt_log_message(key, plaintext_r) {
            Ok(encrypted_text) => {
                copy_to_return_buffer(&encrypted_text, ret_buffer, ret_buffer_size)
            }
            Err(e) => e.log_and_return_error_code(),
        }
    } else {
        DllError::new("Logging key not set. Use FiSH11_LogSetKey first.")
            .log_and_return_error_code()
    }
}
