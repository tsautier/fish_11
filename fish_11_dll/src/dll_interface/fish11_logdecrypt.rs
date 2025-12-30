use crate::dll_interface::dll_error::DllError;
// use buffer_utils for writing results into caller buffer
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use fish_11_core::globals::LOGGING_KEY;
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use std::ffi::CStr;
use std::os::raw::c_char;

fn decrypt_log_message(key: &[u8], base64_ciphertext: &str) -> Result<String, DllError> {
    let decoded =
        STANDARD.decode(base64_ciphertext).map_err(|_| DllError::new("Invalid base64 encoding"))?;

    if decoded.len() < 12 {
        return Err(DllError::new("Ciphertext too short"));
    }

    // Extract nonce (first 12 bytes) and ciphertext
    let (nonce_bytes, ciphertext) = decoded.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| DllError::new("Invalid key length for ChaCha20-Poly1305"))?;

    let plaintext_bytes =
        cipher.decrypt(nonce, ciphertext).map_err(|_| DllError::new("Decryption failed"))?;

    String::from_utf8(plaintext_bytes)
        .map_err(|_| DllError::new("Decrypted data is not valid UTF-8"))
}

#[no_mangle]
pub extern "C" fn FiSH11_LogDecrypt(
    ciphertext: *const c_char,
    ret_buffer: *mut c_char,
    ret_buffer_size: i32,
) -> i32 {
    if ciphertext.is_null() {
        return DllError::new("ciphertext pointer is null").log_and_return_error_code();
    }
    if ret_buffer.is_null() {
        return DllError::new("return buffer is null").log_and_return_error_code();
    }

    let ciphertext_str = unsafe { CStr::from_ptr(ciphertext) };
    let ciphertext_r = match ciphertext_str.to_str() {
        Ok(s) => s,
        Err(_) => {
            return DllError::new("Failed to convert ciphertext to string")
                .log_and_return_error_code();
        }
    };

    let key_guard = match LOGGING_KEY.lock() {
        Ok(g) => g,
        Err(_) => {
            return DllError::new("Failed to acquire logging key lock").log_and_return_error_code();
        }
    };

    if let Some(key) = key_guard.as_ref() {
        match decrypt_log_message(key, ciphertext_r) {
            Ok(decrypted_text) => unsafe {
                crate::buffer_utils::write_result(ret_buffer, &decrypted_text)
            },
            Err(e) => e.log_and_return_error_code(),
        }
    } else {
        DllError::new("Logging key not set. Use FiSH11_LogSetKey first.")
            .log_and_return_error_code()
    }
}
