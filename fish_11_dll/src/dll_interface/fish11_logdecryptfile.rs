use crate::dll_interface::dll_error::DllError;
use crate::platform_types::{PCSTR, PSTR};
use crate::utils::copy_to_return_buffer;
use chacha20poly1305::{aead::{Aead, KeyInit}, ChaCha20Poly1305, Nonce};
use fish_11_core::globals::LOGGING_KEY;
use std::ffi::CStr;
use std::fs::File;
use std::io::{BufRead, BufReader};

fn decrypt_log_line(key: &[u8], base64_ciphertext: &str) -> Result<String, DllError> {
    let decoded = base64::decode(base64_ciphertext)
        .map_err(|_| DllError::new("Invalid base64 encoding"))?;

    if decoded.len() < 12 {
        return Err(DllError::new("Ciphertext too short"));
    }

    // Extract nonce (first 12 bytes) and ciphertext
    let (nonce_bytes, ciphertext) = decoded.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(key)
        .map_err(|_| DllError::new("Invalid key length for ChaCha20-Poly1305"))?;

    let plaintext_bytes = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| DllError::new("Decryption failed"))?;

    String::from_utf8(plaintext_bytes)
        .map_err(|_| DllError::new("Decrypted data is not valid UTF-8"))
}

#[no_mangle]
pub extern "C" fn FiSH11_LogDecryptFile(filepath: PCSTR, ret_buffer: PSTR, ret_buffer_size: i32) -> i32 {
    if filepath.is_null() {
        return DllError::new("filepath pointer is null").log_and_return_error_code();
    }
    if ret_buffer.is_null() {
        return DllError::new("return buffer is null").log_and_return_error_code();
    }

    let filepath_str = unsafe { CStr::from_ptr(filepath) };
    let filepath_r = match filepath_str.to_str() {
        Ok(s) => s,
        Err(_) => {
            return DllError::new("Failed to convert filepath to string")
                .log_and_return_error_code()
        }
    };

    let key_guard = LOGGING_KEY.lock();
    if let Some(key) = key_guard.as_ref() {
        // Open the file and read line by line
        let file = match File::open(filepath_r) {
            Ok(f) => f,
            Err(_) => {
                return DllError::new("Failed to open file").log_and_return_error_code();
            }
        };

        let reader = BufReader::new(file);

        // Read all lines and decrypt them
        let mut decrypted_lines = Vec::new();
        for line_result in reader.lines() {
            match line_result {
                Ok(line) => {
                    if !line.trim().is_empty() {
                        match decrypt_log_line(key, &line) {
                            Ok(decrypted_line) => {
                                decrypted_lines.push(decrypted_line);
                            }
                            Err(e) => {
                                fish_11_core::log_error_with_context!("FiSH11_LogDecryptFile", "Failed to decrypt line: {}", e);
                                // Continue processing other lines
                            }
                        }
                    }
                }
                Err(e) => {
                    fish_11_core::log_error_with_context!("FiSH11_LogDecryptFile", "Failed to read line from file: {}", e);
                    return DllError::new("Failed to read file").log_and_return_error_code();
                }
            }
        }

        // Join all decrypted lines and return them
        let result = decrypted_lines.join("\n");
        copy_to_return_buffer(&result, ret_buffer, ret_buffer_size)
    } else {
        DllError::new("Logging key not set. Use FiSH11_LogSetKey first.")
            .log_and_return_error_code()
    }
}