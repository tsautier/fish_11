#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(b64_str) = std::str::from_utf8(data) {
        // Test base64 decoding (used extensively in FiSH)
        let _ = base64::decode(b64_str);
        let _ = base64::decode_config(b64_str, base64::STANDARD);

        // Test our custom base64 variant if it exists
        // let _ = fish_11_dll::base64_utils::decode_fish_base64(b64_str);
    }
});
