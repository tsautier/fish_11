#![no_main]

use libfuzzer_sys::fuzz_target;
use base64::{Engine as _, engine::general_purpose};

fuzz_target!(|data: &[u8]| {
    if let Ok(b64_str) = std::str::from_utf8(data) {
        // Test base64 decoding with new API (0.22+)
        let _ = general_purpose::STANDARD.decode(b64_str);
        let _ = general_purpose::URL_SAFE.decode(b64_str);
        let _ = general_purpose::STANDARD_NO_PAD.decode(b64_str);
    }
});
