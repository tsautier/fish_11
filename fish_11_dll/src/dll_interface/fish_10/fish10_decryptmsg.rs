//! FiSH 10 Legacy Decryption Function
//!
//! This function provides compatibility with the legacy FiSH 10 decryption
//! using Blowfish encryption.

use std::ffi::c_char;
use std::os::raw::c_int;

use crate::crypto::blowfish;
use crate::dll_interface::utility;
use crate::platform_types::{BOOL, HWND};
use crate::unified_error::DllError;
use crate::{buffer_utils, dll_function_identifier, legacy, log_debug};

/* Legacy FiSH 10 message formats:
   :nick!ident@host PRIVMSG #chan :+OK 2T5zD0mPgMn
   :nick!ident@host PRIVMSG #chan :\x01ACTION +OK 2T5zD0mPgMn\x01
   :nick!ident@host PRIVMSG ownNick :+OK 2T5zD0mPgMn
   :nick!ident@host NOTICE ownNick :+OK 2T5zD0mPgMn
   :nick!ident@host NOTICE #chan :+OK 2T5zD0mPgMn
   :irc.tld 332 nick #chan :+OK hqnSD1kaIaE00uei/.3LjAO1Den3t/iMNsc1
   :nick!ident@host TOPIC #chan :+OK JRFEAKWS
*/

fn fish10_decrypt_msg_impl(input_str: &str) -> Result<String, DllError> {
    // Parse input: <target> <encrypted_message>
    let parsed = utility::parse_input(&input_str)?;

    let target = parsed.target.to_lowercase();
    let mut encrypted_message = parsed.message.trim();

    // Strip the "+OK " prefix if present (legacy FiSH 10 format)
    if let Some(stripped) = encrypted_message.strip_prefix("+OK ") {
        encrypted_message = stripped;

        #[cfg(debug_assertions)]
        log_debug!("FiSH10: stripped +OK prefix from legacy encrypted message");
    }

    // Check if this is a legacy target
    if !legacy::is_legacy_target(&target) {
        return Err(DllError::LegacyError {
            context: format!("Target '{}' not configured for legacy mode", target),
            cause: "No legacy key found for this target".to_string(),
        });
    }

    // Get the legacy key for this target
    let config = legacy::LEGACY_CONFIG.read();
    let keys = config.legacy_keys.read();
    let key = keys.get(&target as &str).ok_or_else(|| DllError::LegacyError {
        context: format!("Missing legacy key for target '{}'", target),
        cause: "Key not found in legacy key store".to_string(),
    })?;

    #[cfg(debug_assertions)]
    log_debug!("FiSH10: decrypting message for '{}' with legacy key", target);

    // Decrypt using legacy Blowfish algorithm
    let decrypted =
        blowfish::decrypt_message(key, encrypted_message, target.as_bytes()).map_err(|e| {
            DllError::LegacyError {
                context: format!("Blowfish decryption failed for '{}'", target),
                cause: e.to_string(),
            }
        })?;

    #[cfg(debug_assertions)]
    log_debug!("FiSH10: successfully decrypted legacy message for '{}'", target);

    Ok(decrypted)
}

dll_function_identifier!(FiSH10_DecryptMsg, data, {
    let input_str = unsafe { buffer_utils::parse_buffer_input(data)? };

    fish10_decrypt_msg_impl(&input_str)
});

#[cfg(test)]
mod tests {
    //use super::*;
    use crate::legacy::test_utils::setup_test_legacy_key;

    #[test]
    fn test_fish10_decrypt_basic() {
        setup_test_legacy_key("#test", b"testkey12345678");

        // Test with basic +OK message
        let result = super::fish10_decrypt_msg_impl("#test +OK encrypteddata");
        // Add proper assertions once blowfish implementation is complete
    }
}
