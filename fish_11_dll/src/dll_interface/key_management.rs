use std::ffi::{c_char};
use std::os::raw::c_int;

use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::dll_function;
use crate::unified_error::{DllError, DllResult};
use crate::{buffer_utils, config, crypto, utils::normalize_nick};

/// Processes a received public key to establish a shared secret for encrypted communication.
///
/// This function completes the Diffie-Hellman key exchange by computing and storing a shared secret.
dll_function!(FiSH11_ProcessPublicKey, data, {
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.splitn(2, ' ').collect();

    if parts.len() < 2 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "expected format: <nickname> <received_key>".to_string(),
        });
    }

    let nickname = normalize_nick(parts[0]);
    let received_pubkey_str = parts[1].trim();

    if nickname.is_empty() {
        return Err(DllError::MissingParameter("nickname".to_string()));
    }
    if received_pubkey_str.is_empty() {
        return Err(DllError::MissingParameter("received_key".to_string()));
    }

    log::debug!("Processing public key from: {}", nickname);

    // 1. Extract the peer's public key from the formatted string.
    let their_public_key = crypto::extract_public_key(received_pubkey_str)?;

    // 2. Retrieve our own keypair from storage.
    let keypair = config::get_keypair()?;

    // 3. Compute the shared secret.
    let shared_secret = crypto::compute_shared_secret(&keypair.private_key, &their_public_key)?;

    // 4. Store the derived key, overwriting if it exists as part of the exchange.
    config::set_key(&nickname, &shared_secret, None, true)?;

    let success_msg = format!(
        "/echo -ts Secure key exchange completed successfully with {}",
        nickname
    );
    log::info!("Successfully processed public key for {}", nickname);

    Ok(success_msg)
});

/// Tests the encryption/decryption cycle with a randomly generated key.
///
/// This diagnostic function demonstrates the encryption workflow and returns the result.
dll_function!(FiSH11_TestCrypt, data, {
    let message = unsafe { buffer_utils::parse_buffer_input(data)? };

    if message.is_empty() {
        return Err(DllError::MissingParameter("message".to_string()));
    }

    log::debug!("Testing crypt with message: '{}'", message);

    // 1. Generate a random 32-byte key.
    let mut key = [0u8; 32];
    crypto::fill_random_bytes(&mut key)?;

    log::debug!("Generated temporary key for test");

    // 2. Encrypt the message.
    let encrypted = crypto::encrypt_message(&key, &message, None)?;

    // 3. Decrypt the result.
    let decrypted = crypto::decrypt_message(&key, &encrypted)?;

    if message != decrypted {
        return Err(DllError::Internal(
            "Decrypted message does not match original".to_string(),
        ));
    }

    log::info!("Test crypt cycle completed successfully");

    // 4. Display all three values for verification.
    Ok(format!(
        "/echo -ts Original: {} | Encrypted: {} | Decrypted: {}",
        message, encrypted, decrypted
    ))
});