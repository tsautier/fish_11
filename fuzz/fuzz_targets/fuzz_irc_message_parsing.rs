#![no_main]

use libfuzzer_sys::fuzz_target;
use base64::{Engine as _, engine::general_purpose};

fuzz_target!(|data: &[u8]| {
    if let Ok(message) = std::str::from_utf8(data) {
        // Test IRC message parsing without panicking
        
        // Extract potential FiSH encrypted messages
        if let Some(fish_start) = message.find(":+FiSH ") {
            let b64_part = &message[fish_start + 7..].trim();
            if let Ok(decoded) = general_purpose::STANDARD.decode(b64_part) {
                // Test if this could be a valid encrypted message
                if decoded.len() >= 12 {
                    // Has at least nonce size, try to parse as encrypted data
                    let _ = decoded.split_at(12);
                }
            }
        }

        // Test +OK format (legacy)
        if let Some(ok_start) = message.find("+OK ") {
            let b64_part = &message[ok_start + 4..].trim();
            let _ = general_purpose::STANDARD.decode(b64_part);
        }

        // Test X25519 key exchange parsing
        if let Some(init_start) = message.find("X25519_INIT:") {
            let key_part = message[init_start + 12..].trim();
            let _ = general_purpose::STANDARD.decode(key_part);
        }

        if let Some(finish_start) = message.find("X25519_FINISH:") {
            let key_part = &message[finish_start + 14..].trim();
            let _ = general_purpose::STANDARD.decode(key_part);
        }

        // Test FCEP-1 key exchange parsing
        if let Some(fcep_start) = message.find("+FiSH-CEP-KEY:") {
            let key_part = message[fcep_start + 9..].trim();
            let _ = general_purpose::STANDARD.decode(key_part);
        }

        // Test IRC prefix parsing
        if message.starts_with(':') {
            if let Some(space_pos) = message.find(' ') {
                let _prefix = &message[1..space_pos];
                let rest = &message[space_pos + 1..];
                
                // Parse command
                if let Some(next_space) = rest.find(' ') {
                    let _command = &rest[..next_space];
                }
            }
        }
    }
});
