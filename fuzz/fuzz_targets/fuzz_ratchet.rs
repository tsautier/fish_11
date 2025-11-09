#![no_main]

use fish_11::crypto::advance_ratchet_key;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Need at least 32 (key) + 12 (nonce) + some channel name
    if data.len() < 45 {
        return;
    }

    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];

    key.copy_from_slice(&data[..32]);
    nonce.copy_from_slice(&data[32..44]);

    if let Ok(channel_name) = std::str::from_utf8(&data[44..]) {
        // Limit channel name length
        if channel_name.len() > 200 {
            return;
        }

        // Test ratcheting (should never panic)
        let _ = advance_ratchet_key(&key, &nonce, channel_name);
    }
});
