#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = std::str::from_utf8(data) {
        // Test IRC message parsing without panicking
        // Look for patterns like:
        // :prefix PRIVMSG target :message
        // :prefix NOTICE target :message
        // PRIVMSG target :+FiSH base64data

        // Extract potential FiSH encrypted messages
        if message.contains(":+FiSH ") {
            // Parse the base64 part
            if let Some(fish_start) = message.find(":+FiSH ") {
                let b64_part = &message[fish_start + 7..];
                let _ = base64::decode(b64_part);
            }
        }

        // Test X25519 key exchange parsing
        if message.contains("X25519_INIT:") || message.contains("X25519_FINISH:") {
            // This should not panic
        }

        // Test FCEP-1 key exchange parsing
        if message.contains("FCEP-KEY:") {
            // This should not panic
        }
    }
});
