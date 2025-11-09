#![no_main]

use fish_11::crypto::encrypt_message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Generate a random key from the fuzzer input
    if data.len() < 32 {
        return;
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&data[..32]);

    // Try to encrypt the rest of the data as a message
    if let Ok(message) = std::str::from_utf8(&data[32..]) {
        // Limit message size to avoid OOM
        if message.len() > 4096 {
            return;
        }

        // This should never panic, only return Err
        let _ = encrypt_message(&key, message, None, None);
    }
});
