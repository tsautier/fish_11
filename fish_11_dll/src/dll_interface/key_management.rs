use std::ffi::{CStr, CString, c_char};
use std::os::raw::c_int;
use std::{ptr, str};

use log::{error, info};
use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::dll_interface::{MIRC_COMMAND, MIRC_HALT, get_buffer_size};
use crate::{config, crypto};

/// Processes a received public key to establish a shared secret for encrypted communication
///
/// This function completes the Diffie-Hellman key exchange by:
/// 1. Extracting the peer's public key from the formatted string
/// 2. Retrieving our own keypair from storage
/// 3. Computing a shared secret using Curve25519
/// 4. Storing the derived key for future encrypted communication
#[no_mangle]
#[allow(non_snake_case)]
pub extern "stdcall" fn FiSH11_ProcessPublicKey(
    _m_wnd: HWND,
    _a_wnd: HWND,
    data: *mut c_char,
    _parms: *mut c_char,
    _show: BOOL,
    _nopause: BOOL,
) -> c_int {
    let buffer_size = get_buffer_size();

    // Read input parameters
    let input = unsafe {
        if data.is_null() {
            error!("/echo -ts Data buffer pointer is null");
            return MIRC_HALT;
        }
        match CStr::from_ptr(data).to_str() {
            Ok(s) => s.to_owned(),
            Err(e) => {
                error!("/echo -ts Invalid ANSI input: {}", e);
                return MIRC_HALT;
            }
        }
    };

    let parts: Vec<&str> = input.splitn(2, ' ').collect();

    if parts.len() < 2 {
        let error_msg = CString::new(
            "Usage: /dll fish_11.dll FiSH11_ProcessPublicKey <nickname> <received_key>",
        )
        .expect("Error message should not contain null bytes");

        unsafe {
            ptr::write_bytes(data as *mut u8, 0, buffer_size);

            let bytes = error_msg.as_bytes_with_nul();
            let copy_len = bytes.len().min(buffer_size - 1);
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), data as *mut u8, copy_len);
            *data.add(copy_len) = 0;
        }

        return MIRC_COMMAND;
    }

    let nickname = parts[0].trim();
    let received_pubkey_str = parts[1].trim();

    // Extract the received public key
    let their_public_key = match crypto::extract_public_key(received_pubkey_str) {
        Ok(key) => key,
        Err(_) => {
            let error_msg =
                CString::new("/echo -ts Invalid public key format. Should be FiSH11-PubKey:...")
                    .expect("Static string contains no null bytes");

            unsafe {
                ptr::write_bytes(data as *mut u8, 0, buffer_size);

                let bytes = error_msg.as_bytes_with_nul();
                let copy_len = bytes.len().min(buffer_size - 1);
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), data as *mut u8, copy_len);
                *data.add(copy_len) = 0;
            }

            return MIRC_COMMAND;
        }
    };

    // Get our keypair
    let keypair = match config::get_keypair() {
        Ok(kp) => kp,
        Err(_) => {
            let error_msg = CString::new(
                "/echo -ts No keypair found. Generate one first with FiSH11_ExchangeKey.",
            )
            .expect("Static string contains no null bytes");

            unsafe {
                ptr::write_bytes(data as *mut u8, 0, buffer_size);

                let bytes = error_msg.as_bytes_with_nul();
                let copy_len = bytes.len().min(buffer_size - 1);
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), data as *mut u8, copy_len);
                *data.add(copy_len) = 0;
            }

            return MIRC_COMMAND;
        }
    };

    // Compute the shared secret
    let shared_secret = match crypto::compute_shared_secret(&keypair.private_key, &their_public_key)
    {
        Ok(secret) => secret,
        Err(e) => {
            let error_msg = CString::new(format!("/echo -ts Error computing shared secret: {}", e))
                .expect("Error message contains no null bytes");

            unsafe {
                ptr::write_bytes(data as *mut u8, 0, buffer_size);

                let bytes = error_msg.as_bytes_with_nul();
                let copy_len = bytes.len().min(buffer_size - 1);
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), data as *mut u8, copy_len);
                *data.add(copy_len) = 0;
            }

            return MIRC_COMMAND;
        }
    };

    // Store the shared secret with duplicate handling
    let store_result = match crate::config::set_key(nickname, &shared_secret, None, false) {
        Ok(_) => Ok(()),
        Err(crate::error::FishError::DuplicateEntry(nick)) => {
            info!("/echo -ts Updating existing key for {} as part of key exchange", nick);
            crate::config::set_key(nickname, &shared_secret, None, true)
        }
        Err(e) => Err(e),
    };

    match store_result {
        Ok(_) => {
            let success_msg = CString::new(format!(
                "/echo -ts Secure key exchange completed successfully with {}",
                nickname
            ))
            .expect("Formatted string contains no null bytes");

            unsafe {
                ptr::write_bytes(data as *mut u8, 0, buffer_size);

                let bytes = success_msg.as_bytes_with_nul();
                let copy_len = bytes.len().min(buffer_size - 1);
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), data as *mut u8, copy_len);
                *data.add(copy_len) = 0;
            }
        }
        Err(e) => {
            let error_msg_content = match e {
                crate::error::FishError::DuplicateEntry(nick) => {
                    format!("/echo -ts Key for {} already exists and couldn\'t be updated", nick)
                }
                _ => format!("/echo -ts Error storing key: {}", e),
            };
            let error_msg =
                CString::new(error_msg_content).expect("Error message contains no null bytes");

            unsafe {
                ptr::write_bytes(data as *mut u8, 0, buffer_size);

                let bytes = error_msg.as_bytes_with_nul();
                let copy_len = bytes.len().min(buffer_size - 1);
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), data as *mut u8, copy_len);
                *data.add(copy_len) = 0;
            }
        }
    }

    MIRC_COMMAND
}

/// Tests the encryption/decryption cycle with a randomly generated key
///
/// This diagnostic function demonstrates the encryption workflow by:
/// 1. Generating a random 32-byte key
/// 2. Encrypting the input message
/// 3. Decrypting the result
/// 4. Displaying all three values for verification
#[no_mangle]
#[allow(non_snake_case)]
pub extern "stdcall" fn FiSH11_TestCrypt(
    _m_wnd: HWND,
    _a_wnd: HWND,
    data: *mut c_char,
    _parms: *mut c_char,
    _show: BOOL,
    _nopause: BOOL,
) -> c_int {
    let buffer_size = get_buffer_size();
    log::debug!("[FiSH11_TestCrypt] called");

    // Read input parameters
    let input = unsafe {
        if data.is_null() {
            error!("[FiSH11_TestCrypt] Data buffer pointer is null");
            return MIRC_HALT;
        }
        match CStr::from_ptr(data).to_str() {
            Ok(s) => {
                log::debug!("[FiSH11_TestCrypt] input string: {}", s);
                s.to_owned()
            },
            Err(e) => {
                error!("[FiSH11_TestCrypt] Invalid ANSI input: {}", e);
                return MIRC_HALT;
            }
        }
    };
    if input.is_empty() {
        log::debug!("[FiSH11_TestCrypt] input is empty");
        let error_msg =
            CString::new("/echo -ts Usage: /dll fish_11.dll FiSH11_TestCrypt <message>")
                .expect("Failed to create TestCrypt usage message");

        unsafe {
            ptr::write_bytes(data as *mut u8, 0, buffer_size);

            let bytes = error_msg.as_bytes_with_nul();
            let copy_len = bytes.len().min(buffer_size - 1);
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), data as *mut u8, copy_len);
            *data.add(copy_len) = 0;
        }

        return MIRC_COMMAND;
    }
    log::debug!("[FiSH11_TestCrypt] input not empty, generating key");
    let mut key = [0u8; 32];
    crate::utils::generate_random_bytes(32).iter().enumerate().for_each(|(i, &b)| key[i] = b);
    log::debug!("[FiSH11_TestCrypt] generated key: {:x?}", key);
    // Encrypt the message
    let encrypted = match crypto::encrypt_message(&key, &input, None) {
        Ok(e) => {
            log::debug!("[FiSH11_TestCrypt] encrypted: {}", e);
            e
        },
        Err(e) => {
            error!("[FiSH11_TestCrypt] Encryption failed: {}", e);
            let error_msg = CString::new(format!("/echo -ts Encryption failed: {}", e))
                .expect("Failed to create encryption error message");

            unsafe {
                ptr::write_bytes(data as *mut u8, 0, buffer_size);

                let bytes = error_msg.as_bytes_with_nul();
                let copy_len = bytes.len().min(buffer_size - 1);
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), data as *mut u8, copy_len);
                *data.add(copy_len) = 0;
            }

            return MIRC_COMMAND;
        }
    };

    // Decrypt the message
    let decrypted = match crypto::decrypt_message(&key, &encrypted) {
        Ok(d) => {
            log::debug!("[FiSH11_TestCrypt] decrypted: {}", d);
            d
        },
        Err(e) => {
            error!("[FiSH11_TestCrypt] Decryption failed: {}", e);
            let error_msg = CString::new(format!("/echo -ts Decryption failed: {}", e))
                .expect("Failed to create decryption error message");

            unsafe {
                ptr::write_bytes(data as *mut u8, 0, buffer_size);

                let bytes = error_msg.as_bytes_with_nul();
                let copy_len = bytes.len().min(buffer_size - 1);
                std::ptr::copy_nonoverlapping(bytes.as_ptr(), data as *mut u8, copy_len);
                *data.add(copy_len) = 0;
            }

            return MIRC_COMMAND;
        }
    };
    log::debug!("[FiSH11_TestCrypt] preparing result");
    // Limite la taille et filtre les caractères non imprimables
    fn safe_str(s: &str) -> String {
        s.chars()
            .map(|c| if c.is_ascii_graphic() || c == ' ' { c } else { '?' })
            .collect::<String>()
    }
    let maxlen = 512;
    let input_safe = safe_str(&input).chars().take(maxlen).collect::<String>();
    let encrypted_safe = safe_str(&encrypted).chars().take(maxlen).collect::<String>();
    let decrypted_safe = safe_str(&decrypted).chars().take(maxlen).collect::<String>();
    let result_str = format!(
        "/echo -ts Original: {} | Encrypted: {} | Decrypted: {}",
        input_safe,
        encrypted_safe,
        decrypted_safe
    );
    // Version minimale qui fonctionne :
    let result_str = format!(
        "/echo -ts Original: {} | Encrypted: {} | Decrypted: {}",
        input,
        encrypted,
        decrypted
    );
    let result = CString::new(result_str).unwrap_or_else(|_| CString::new("/echo -ts [FiSH11] Error: invalid result").unwrap());
    unsafe {
        crate::buffer_utils::write_cstring_to_buffer(data, 900, &result).ok();
    }
    MIRC_COMMAND
}
