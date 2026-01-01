use std::ffi::{CString, c_char};

use base64;
use base64::Engine;
use rand::Rng;
use rand::rngs::OsRng;

use crate::dll_interface::NICK_VALIDATOR;
use crate::error::FishError;
use crate::{buffer_utils, log_debug, log_error, log_warn};

/// Checks if there is an established TCP connection owned by the current process.
///
/// This uses the Windows API `GetTcpTable2` to list all TCP connections and checks
/// for any connection in the `ESTABLISHED` state that belongs to the current PID.

pub fn is_socket_connected() -> bool {
    unsafe {
        use std::alloc::{Layout, alloc, dealloc};
        use winapi::shared::tcpmib::{MIB_TCP_STATE_ESTAB, MIB_TCPROW2, MIB_TCPTABLE2};
        use winapi::shared::winerror::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR};
        use winapi::um::iphlpapi::GetTcpTable2;
        use winapi::um::processthreadsapi::GetCurrentProcessId;

        let pid = GetCurrentProcessId();
        let mut size: u32 = 0;

        // First call to get the necessary size
        // 1 (TRUE) for bOrder (third argument) to sort the table, though sorting doesn't matter for us
        let res = GetTcpTable2(std::ptr::null_mut(), &mut size, 1);

        if res != ERROR_INSUFFICIENT_BUFFER && res != NO_ERROR {
            log_debug!("GetTcpTable2 failed to get size: {}", res);
            return false;
        }

        if size == 0 {
            return false;
        }

        // Allocate buffer
        // Align to MIB_TCPTABLE2 alignment which is likely 4 or 8 bytes. 8 is safe.
        let layout = Layout::from_size_align(size as usize, 8).unwrap();
        let buffer = alloc(layout);

        if buffer.is_null() {
            log_error!("Failed to allocate memory for TCP table");
            return false;
        }

        let table_ptr = buffer as *mut MIB_TCPTABLE2;

        // Second call to get actual data
        let res = GetTcpTable2(table_ptr, &mut size, 1);

        if res != NO_ERROR {
            log_error!("GetTcpTable2 failed: {}", res);
            dealloc(buffer, layout);
            return false;
        }

        let num_entries = (*table_ptr).dwNumEntries as usize;

        // The table array is at the end of the struct.
        // In winapi, MIB_TCPTABLE2 includes table: [MIB_TCPROW2; 1]
        let rows_ptr = &((*table_ptr).table) as *const _ as *const MIB_TCPROW2;

        let mut connected = false;

        if num_entries > 0 {
            let rows = std::slice::from_raw_parts(rows_ptr, num_entries);
            for row in rows {
                // Check for Established state (MIB_TCP_STATE_ESTAB = 5) and matching PID
                if row.dwOwningPid == pid && row.dwState == MIB_TCP_STATE_ESTAB {
                    connected = true;
                    // We found one, that's enough to say we are connected
                    break;
                }
            }
        }

        dealloc(buffer, layout);

        if connected {

            #[cfg(debug_assertions)]
            log_debug!("is_socket_connected: Found established TCP connection for PID {}", pid);
        } else {

            #[cfg(debug_assertions)]
            log_debug!("is_socket_connected: No established TCP connections found for PID {}", pid);
        }

        connected
    }
}

/// Encode binary data to a base64 string using the standard Base64 alphabet with padding.
///
/// This function takes a byte slice and returns its Base64-encoded representation
/// as defined in RFC 4648. The encoding uses `+` and `/` as the 63rd and 64th characters,
/// and includes padding `=` characters as needed.
pub fn base64_encode(data: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Decode base64 data to binary
///
/// Converts a base64-encoded string into its original binary form.
/// Returns an error if the input is not valid base64.
pub fn base64_decode(s: &str) -> Result<Vec<u8>, crate::error::FishError> {
    base64::engine::general_purpose::STANDARD.decode(s).map_err(|e| FishError::Base64Error(e))
}

/// Generate random bytes
pub fn generate_random_bytes(len: usize) -> Vec<u8> {
    let mut rng = OsRng;
    let mut bytes = vec![0u8; len];
    rng.fill(&mut bytes[..]);
    bytes
}

/// Normalize a mIRC nickname (lowercase)
pub fn normalize_nick(nick: &str) -> String {
    nick.trim().to_lowercase()
}

/// Normalize a channel or target name by stripping STATUSMSG prefixes.
///
/// IRC STATUSMSG allows sending to specific user classes in a channel using prefixes such as
/// `@#channel`, `+#channel`, `%#channel`, or `~#channel`. This function removes those leading
/// prefixes so the rest of the stack always sees the bare channel name (`#channel` or `&channel`).
/// For non-channel targets (private messages), it returns the input untouched.
///
/// This function handles complex cases including:
/// - Multiple consecutive status prefixes: `@%+#test` → `#test`
/// - Mixed status prefixes: `~@#test` → `#test`
/// - Invalid/malformed prefixes: `@invalid` → `@invalid` (unchanged)
/// - Empty or whitespace-only input: "   " → ""
///
/// Examples:
/// - `@#fish_11` → `#fish_11`
/// - `@%+#test` → `#test`
/// - `~@#channel` → `#channel`
/// - `&fish_11` → `&fish_11`
/// - `bob` → `bob`
/// - `@invalid` → `@invalid`
/// - `   @#test   ` → `#test`
pub fn normalize_target(target: &str) -> &str {
    let trimmed = target.trim();

    if trimmed.is_empty() {
        return trimmed;
    }

    let status_chars = ['@', '+', '%', '~'];
    let mut seen_status = false;
    let mut channel_start = None;

    for (idx, ch) in trimmed.char_indices() {
        if ch == '#' || ch == '&' {
            channel_start = Some(idx);
            break;
        }

        if status_chars.contains(&ch) {
            seen_status = true;
            continue;
        }

        // If we encounter a non-status character before a channel prefix,
        // this is not a valid STATUSMSG format, so return the original
        break;
    }

    if let Some(idx) = channel_start {
        if seen_status && idx > 0 {
            return &trimmed[idx..];
        }
    }

    trimmed
}

/// Basic nickname validation (no null bytes or non-ASCII chars)
fn validate_nick_basic(nick: &str) -> Result<(), crate::error::FishError> {
    // Check for null bytes
    if nick.contains('\0') {
        return Err(crate::error::FishError::NullByteInString);
    }

    // Check for non-ASCII characters
    if let Some(c) = nick.chars().find(|c| !c.is_ascii()) {
        return Err(crate::error::FishError::NonAsciiCharacter(c));
    }

    Ok(())
}

/// Validate nickname according to IRC RFC 1459
pub fn validate_nickname(
    nickname: &str,
    data: *mut c_char,
    buffer_size: usize,
    trace_id: &str,
) -> bool {

    #[cfg(debug_assertions)]
    log_debug!("FiSH11_ExchangeKey[{}]: validating nickname: '{}'", trace_id, nickname); // Check if nickname is empty
    if nickname.is_empty() {
        log_warn!("FiSH11_ExchangeKey[{}]: empty nickname provided", trace_id);
        match CString::new("Usage: /dll fish_11.dll FiSH11_ExchangeKey <nickname>") {
            Ok(error_msg) => unsafe {
                let _ = buffer_utils::write_cstring_to_buffer(data, buffer_size, &error_msg);
            },
            Err(_) => {
                // This shouldn't happen since our string is static, but we handle it anyway
                log_error!("FiSH11_ExchangeKey[{}]: CString::new failed unexpectedly", trace_id);
            }
        }
        return false;
    }

    // Basic validation first
    if let Err(_) = validate_nick_basic(nickname) {
        log_error!(
            "FiSH11_ExchangeKey[{}]: nickname contains invalid characters: {}",
            trace_id,
            nickname
        );
        match CString::new("Error: nickname contains invalid characters") {
            Ok(error_msg) => unsafe {
                let _ = buffer_utils::write_cstring_to_buffer(data, buffer_size, &error_msg);
            },
            Err(_) => {
                // This shouldn't happen since our string is static, but we handle it anyway
                log_error!(
                    "FiSH11_ExchangeKey[{}]: CString::new failed for error message",
                    trace_id
                );
            }
        }
        return false;
    }

    // RFC 1459 compliant validation
    if !NICK_VALIDATOR.is_match(nickname) {
        log_error!(
            "FiSH11_ExchangeKey[{}]: invalid nickname format: {} (must be 1-16 chars, start with letter/special, contain only valid IRC chars)",
            trace_id,
            nickname
        );

        // Safe CString creation with fallback
        match CString::new(
            "Error: nickname must be 1-16 characters, start with letter/[\\]`_^{|}, contain only valid IRC characters",
        ) {
            Ok(msg) => unsafe {
                let _ = buffer_utils::write_cstring_to_buffer(data, buffer_size, &msg);
            },
            Err(_) => {
                // Try fallback message if primary fails
                match CString::new("Error: invalid nickname format") {
                    Ok(fallback_msg) => unsafe {
                        let _ =
                            buffer_utils::write_cstring_to_buffer(data, buffer_size, &fallback_msg);
                    },
                    Err(_) => {
                        // Even fallback failed - log error but can't write to buffer
                        log_error!(
                            "FiSH11_ExchangeKey[{}]: Both error messages failed CString::new",
                            trace_id
                        );
                    }
                }
            }
        }
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_nick() {
        // Tests if nickname normalization (lowercase) works correctly.
        assert_eq!(normalize_nick("TeStNiCk"), "testnick");
        assert_eq!(normalize_nick("  AnotherNick "), "anothernick");
    }

    #[test]
    fn test_normalize_target_strips_status_prefixes() {
        assert_eq!(normalize_target("@#fish_11"), "#fish_11");
        assert_eq!(normalize_target("@%+#test"), "#test");
        assert_eq!(normalize_target("~#secure"), "#secure");
        assert_eq!(normalize_target("&fish_11"), "&fish_11");
        assert_eq!(normalize_target("bob"), "bob");
    }

    #[test]
    fn test_normalize_target_complex_statusmsg() {
        // Test multiple consecutive status prefixes
        assert_eq!(normalize_target("@%+#test"), "#test");
        assert_eq!(normalize_target("~@#channel"), "#channel");
        assert_eq!(normalize_target("@%+~#complex"), "#complex");

        // Test mixed status prefixes
        assert_eq!(normalize_target("@%+#test"), "#test");

        // Test invalid/malformed prefixes (should remain unchanged)
        assert_eq!(normalize_target("@invalid"), "@invalid");
        assert_eq!(normalize_target("@#"), "#");

        // Test whitespace handling
        assert_eq!(normalize_target("   @#test   "), "#test");
        assert_eq!(normalize_target("\t@%+#test\n"), "#test");

        // Test regular channels (no prefixes)
        assert_eq!(normalize_target("#test"), "#test");
        assert_eq!(normalize_target("&test"), "&test");

        // Test private messages (no channel prefixes)
        assert_eq!(normalize_target("bob"), "bob");
        assert_eq!(normalize_target("@bob"), "@bob"); // Not a channel, so unchanged

        // Test empty and whitespace-only
        assert_eq!(normalize_target(""), "");
        assert_eq!(normalize_target("   "), "");
    }

    #[test]
    fn test_base64_roundtrip() {
        // Tests if base64 encoding and decoding preserves the original data.
        let original_data = b"some secret message with &*@# symbols";
        let encoded = base64_encode(original_data);
        let decoded = base64_decode(&encoded).expect("Base64 decoding failed");
        assert_eq!(original_data, decoded.as_slice());
    }

    #[test]
    fn test_generate_random_bytes() {
        // Tests if the function generates a byte vector of the specified length.
        assert_eq!(generate_random_bytes(0).len(), 0);
        assert_eq!(generate_random_bytes(32).len(), 32);
        assert_eq!(generate_random_bytes(128).len(), 128);
    }

    #[test]
    fn test_validate_nick_basic_ok() {
        // Tests valid nicknames.
        assert!(validate_nick_basic("SimpleNick").is_ok());
        assert!(validate_nick_basic("Nick-With-Dash").is_ok());
    }

    #[test]
    fn test_validate_nick_basic_null_byte() {
        // Tests that a nickname with a null byte is rejected.
        let result = validate_nick_basic("nick\0withnull");
        assert!(matches!(result, Err(FishError::NullByteInString)));
    }

    #[test]
    fn test_validate_nick_basic_non_ascii() {
        // Tests that a nickname with non-ASCII characters is rejected.
        let result = validate_nick_basic("nické");
        assert!(matches!(result, Err(FishError::NonAsciiCharacter('é'))));
    }
}
