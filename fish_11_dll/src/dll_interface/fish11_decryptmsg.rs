use std::ffi::c_char;
use std::os::raw::c_int;

use crate::platform_types::BOOL;
use crate::platform_types::HWND;

use crate::buffer_utils;
use crate::config;
use crate::config::key_management::check_key_expiry;
use crate::crypto;
use crate::dll_function_identifier;
use crate::log_debug;
use crate::unified_error::DllError;
use crate::utils::normalize_nick;

/* list of stuff we possibly need to decrypt:
        :nick!ident@host PRIVMSG #chan :+FISH 2T5zD0mPgMn
        :nick!ident@host PRIVMSG #chan :\x01ACTION +FISH 2T5zD0mPgMn\x01
        :nick!ident@host PRIVMSG ownNick :+FISH 2T5zD0mPgMn
        :nick!ident@host PRIVMSG ownNick :\x01ACTION +FISH 2T5zD0mPgMn\x01
        :nick!ident@host NOTICE ownNick :+FISH 2T5zD0mPgMn
        :nick!ident@host NOTICE #chan :+FISH 2T5zD0mPgMn
        TODO: support encrypting outbound notices to the next 5 targets @#chan +#chan %#chan &#chan ~#chan
        :nick!ident@host NOTICE @#chan :+FISH 2T5zD0mPgMn
        :nick!ident@host NOTICE ~#chan :+FISH 2T5zD0mPgMn
        :nick!ident@host NOTICE %#chan :+FISH 2T5zD0mPgMn
        :nick!ident@host NOTICE +#chan :+FISH 2T5zD0mPgMn
          if '&' is within STATUSMSG=~&@%+ then &#chan is a group target not the name of a server-local channel
        :nick!ident@host NOTICE &#chan :+FISH 2T5zD0mPgMn
        (topic) :irc.tld 332 nick #chan :+FISH hqnSD1kaIaE00uei/.3LjAO1Den3t/iMNsc1
        :nick!ident@host TOPIC #chan :+FISH JRFEAKWS
        (topic /list) :irc.tld 322 nick #chan 2 :[+snt] +FISH BLAH
        @aaa=bbb;ccc;example.com/ddd=eee :nick!ident@host.com PRIVMSG me :Hello
*/

dll_function_identifier!(FiSH11_DecryptMsg, data, {
    // 1. Parse input: <target> <encrypted_message>
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.splitn(2, ' ').collect();

    if parts.len() < 2 {
        return Err(DllError::InvalidInput {
            param: "input".to_string(),
            reason: "expected format: <target> <encrypted_message>".to_string(),
        });
    }

    let target_raw = parts[0];
    let mut encrypted_message = parts[1].trim();

    // Normalize target to strip STATUSMSG prefixes (@#chan, +#chan, etc.)
    let target = crate::utils::normalize_target(target_raw);

    if target.is_empty() {
        return Err(DllError::MissingParameter("target".to_string()));
    }
    if encrypted_message.is_empty() {
        return Err(DllError::MissingParameter("encrypted_message".to_string()));
    }

    // 2. Strip the "+FiSH " prefix if present.
    if let Some(stripped) = encrypted_message.strip_prefix("+FiSH ") {
        encrypted_message = stripped;
        log_debug!("Stripped +FiSH prefix from encrypted message");
    }

    // --- Channel Decryption Logic ---
    if target.starts_with('#') || target.starts_with('&') {
        log_debug!("Decrypting for channel: {}", target);

        let encrypted_bytes = crate::utils::base64_decode(encrypted_message)?;
        if encrypted_bytes.len() < 12 {
            return Err(DllError::DecryptionFailed {
                context: "payload validation".to_string(),
                cause: "Encrypted payload too short to contain a nonce".to_string(),
            });
        }
        let nonce: [u8; 12] = encrypted_bytes[..12].try_into().unwrap();

        // 1. Anti-replay check (read-only)
        if config::check_nonce(target, &nonce)? {
            return Err(DllError::ReplayAttackDetected { channel: target.to_string() });
        }

        // 2. Attempt decryption with ratchet state
        let decrypted = config::with_ratchet_state_mut(target, |state| {
            // Try current key first
            if let Ok(plaintext) = crypto::decrypt_message(
                &state.current_key,
                encrypted_message,
                Some(target.as_bytes()),
            ) {
                // Success with current key. Advance the ratchet.
                let next_key = crypto::advance_ratchet_key(&state.current_key, &nonce, target)?;
                state.advance(next_key);
                return Ok(Some(plaintext)); // Return plaintext to outer scope
            }

            // If current key fails, try previous keys for out-of-order messages
            for old_key in state.previous_keys.iter().rev() {
                // Check newest first
                if let Ok(plaintext) =
                    crypto::decrypt_message(old_key, encrypted_message, Some(target.as_bytes()))
                {
                    // Success with a previous key. DO NOT advance the ratchet.
                    log::warn!(
                        "Decrypted message for {} with a previous ratchet key (out-of-order message)",
                        target
                    );
                    return Ok(Some(plaintext)); // Return plaintext to outer scope
                }
            }

            Ok(None) // Indicate that decryption failed
        })?;

        if let Some(plaintext) = decrypted {
            // 3. Add nonce to cache ONLY after successful decryption
            config::add_nonce(target, nonce)?;
            log::info!("Successfully decrypted ratchet message for {}", target);
            return Ok(plaintext);
        } else {
            return Err(DllError::DecryptionFailed {
                context: format!("decrypting for channel {}", target),
                cause: "Invalid key or corrupted data (ratchet exhausted)".to_string(),
            });
        }
    }

    // --- Private Message Decryption Logic ---
    let nickname = normalize_nick(target);
    log_debug!("Decrypting for nickname: {}", nickname);

    // Check for key expiration before attempting to use it.
    check_key_expiry(&nickname, None)?;

    let key_vec = config::get_key(&nickname, None)?;
    let key: &[u8; 32] = key_vec.as_slice().try_into().map_err(|_| DllError::InvalidInput {
        param: "key".to_string(),
        reason: format!("Key for {} must be exactly 32 bytes, got {}", nickname, key_vec.len()),
    })?;

    log_debug!("Successfully retrieved decryption key");

    // Decrypt the message (no AD for private messages).
    let decrypted = crypto::decrypt_message(key, encrypted_message, None).map_err(|e| {
        DllError::DecryptionFailed {
            context: format!("decrypting for {}", nickname),
            cause: e.to_string(),
        }
    })?;

    log::info!("Successfully decrypted message for {}", nickname);

    Ok(decrypted)
});

#[cfg(test)]
mod tests {

    use crate::config;
    use crate::crypto;
    use crate::utils::normalize_nick;

    #[test]
    fn test_normalize_nick() {
        assert_eq!(normalize_nick("TestNick "), "testnick");
        assert_eq!(normalize_nick("  FiSH_User"), "fish_user");
    }

    #[test]
    fn test_decryptmsg_valid() {
        let nickname = "testuser";
        let key = [0u8; 32];
        let message = "Hello world!";
        config::set_key_default(nickname, &key, true).unwrap();
        let encrypted = crypto::encrypt_message(&key, message, Some(nickname), None).unwrap();
        let decrypted = crypto::decrypt_message(&key, &encrypted, None).unwrap();
        assert_eq!(decrypted, message);
    }

    #[test]
    fn test_decryptmsg_invalid_key_length() {
        let nickname = "testuser2";
        let result = config::get_key_default(nickname);
        assert!(result.is_err());
    }

    #[test]
    fn test_decryptmsg_empty_nickname() {
        let nickname = "";
        let result = normalize_nick(nickname);
        assert_eq!(result, "");
    }
}
