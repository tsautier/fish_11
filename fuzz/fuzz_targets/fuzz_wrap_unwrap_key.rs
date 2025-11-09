#![no_main]

use fish_11::crypto::{unwrap_key, wrap_key};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Need at least 64 bytes for two keys
    if data.len() < 64 {
        return;
    }

    let mut channel_key = [0u8; 32];
    let mut shared_key = [0u8; 32];

    channel_key.copy_from_slice(&data[..32]);
    shared_key.copy_from_slice(&data[32..64]);

    // Test wrap (should never panic)
    if let Ok(wrapped) = wrap_key(&channel_key, &shared_key) {
        // Test unwrap of the wrapped key
        let _ = unwrap_key(&wrapped, &shared_key);
    }

    // Test unwrap with arbitrary data
    if let Ok(b64_str) = std::str::from_utf8(&data[64..]) {
        let _ = unwrap_key(b64_str, &shared_key);
    }
});
