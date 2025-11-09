#![no_main]

use fish_11::crypto::decrypt_message;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Generate a random key from the fuzzer input
    if data.len() < 32 {
        return;
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&data[..32]);

    // Try to decrypt the rest of the data as base64
    if let Ok(b64_str) = std::str::from_utf8(&data[32..]) {
        // This should never panic, only return Err
        let _ = decrypt_message(&key, b64_str, None);
    }
});
