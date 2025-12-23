use crate::dll_interface::dll_error::DllError;
use crate::platform_types::{PCSTR, PSTR};
use crate::utils::copy_to_return_buffer;
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use fish_11_core::globals::LOGGING_KEY;
use std::ffi::CStr;

fn decrypt_log_message(key: &[u8], base64_ciphertext: &str) -> Result<String, DllError> {
    let decoded =
        base64::decode(base64_ciphertext).map_err(|_| DllError::new("Invalid base64 encoding"))?;

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
    ciphertext: PCSTR,
    ret_buffer: PSTR,
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

    let key_guard = LOGGING_KEY.lock();
    if let Some(key) = key_guard.as_ref() {
        match decrypt_log_message(key, ciphertext_r) {
            Ok(decrypted_text) => {
                copy_to_return_buffer(&decrypted_text, ret_buffer, ret_buffer_size)
            }
            Err(e) => e.log_and_return_error_code(),
        }
    } else {
        DllError::new("Logging key not set. Use FiSH11_LogSetKey first.")
            .log_and_return_error_code()
    }
}
