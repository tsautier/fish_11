use lazy_static::lazy_static;
use regex::Regex;

/// Masks sensitive information in log messages
pub fn mask_sensitive_data(input: &str) -> String {
    let mut result = input.to_string();

    // Mask X25519 public key patterns (43-44 chars, typically ending with = or ==)
    result = mask_x25519_keys(&result);

    // Mask IP addresses
    result = mask_ip_addresses(&result);

    // Mask potential keys that look like base64
    result = mask_potential_keys(&result);

    result
}

fn mask_x25519_keys(input: &str) -> String {
    lazy_static! {
        // More precise pattern for X25519 public keys
        // - Exactly 43 base64 characters (32 bytes encoded)
        // - Optional padding (0-2 = signs)
        // - Word boundaries to avoid matching substrings
        static ref X25519_PATTERN: Regex = Regex::new(r"\b[A-Za-z0-9+/]{43}={0,2}\b").unwrap();
    }

    X25519_PATTERN.replace_all(input, "X25519_KEY_REDACTED").to_string()
}

fn mask_ip_addresses(input: &str) -> String {
    lazy_static! {
        // IPv4 pattern - more comprehensive
        static ref IP_PATTERN: Regex = Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\b").unwrap();
    }

    IP_PATTERN.replace_all(input, "IP_REDACTED").to_string()
}

fn mask_potential_keys(input: &str) -> String {
    lazy_static! {
        // Pattern for potential key-like strings (longer base64 patterns)
    static ref KEY_PATTERN: Regex = Regex::new(r"(?i)(key|token|secret|password)\s*[:=]\s*[A-Za-z0-9+/]{20,}={0,2}").unwrap();
    }

    KEY_PATTERN
        .replace_all(input, |caps: &regex::Captures| {
            if let Some(prefix) = caps.get(1) {
                format!("{}REDACTED_VALUE", prefix.as_str())
            } else {
                // Fallback if capture groups don't match as expected
                "REDACTED_KEY_VALUE".to_string()
            }
        })
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_x25519_keys() {
        let input = "Key: 3R6TSmBAdNS7Ek2NtfmjL2ocxntj5KlZsceiKjDeGZU=";
        let result = mask_x25519_keys(input);
        assert!(result.contains("X25519_KEY_REDACTED"));
    }

    #[test]
    fn test_mask_ip_addresses() {
        let input = "Connection from 192.168.1.1";
        let result = mask_ip_addresses(input);
        assert!(result.contains("IP_REDACTED"));
    }
}
