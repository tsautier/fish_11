//! Legacy configuration management for FiSH 10 compatibility
//!
//! This module handles loading and saving legacy blowfish.ini files
//! and managing legacy key configuration.

use crate::unified_error::DllError;
use std::path::PathBuf;

/// Load legacy configuration from blowfish.ini
pub fn load_legacy_config() -> Result<(), DllError> {
    // Get the blowfish.ini path
    let ini_path = get_blowfish_ini_path()?;

    log::info!("LEGACY: Loading configuration from {}", ini_path.display());

    // Check if the file exists
    if !ini_path.exists() {
        log::info!("LEGACY: blowfish.ini not found, starting with empty legacy config");
        return Ok(());
    }

    // Load keys from the blowfish.ini file
    let keys = load_keys_from_blowfish_ini(&ini_path)?;

    // Update the global legacy configuration
    let mut config = super::LEGACY_CONFIG.write();
    config.blowfish_ini_path = Some(ini_path.to_string_lossy().into_owned());

    let mut legacy_keys = config.legacy_keys.write();
    for (target, key) in keys {
        legacy_keys.insert(target, key);
    }

    log::info!("LEGACY: Loaded {} legacy keys", legacy_keys.len());

    Ok(())
}

/// Get the path to blowfish.ini file
fn get_blowfish_ini_path() -> Result<PathBuf, DllError> {
    // Try to get the mIRC directory from the main config
    let mirc_dir = crate::config::get_mirc_directory()?;

    let ini_path = mirc_dir.join("blowfish.ini");
    Ok(ini_path)
}

/// Load keys from blowfish.ini file
/// Supports both legacy format (target=hexkey) and FiSH 10 format with sections
fn load_keys_from_blowfish_ini(
    path: &std::path::Path,
) -> Result<std::collections::HashMap<String, Vec<u8>>, DllError> {
    use std::fs;
    use std::io::BufRead;

    let mut keys = std::collections::HashMap::new();
    let mut current_section: Option<String> = None;

    // Read the file line by line
    let file = fs::File::open(path).map_err(|e| DllError::LegacyError {
        context: "Reading blowfish.ini".to_string(),
        cause: format!("Failed to open file: {}", e),
    })?;

    let reader = std::io::BufReader::new(file);

    for line in reader.lines() {
        let line = line.map_err(|e| DllError::LegacyError {
            context: "Reading blowfish.ini".to_string(),
            cause: format!("Failed to read line: {}", e),
        })?;

        let line = line.trim();

        // Skip empty lines and comments
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') && !line.contains('=') {
            continue;
        }

        // Check for section headers like [network:target] or [target]
        if line.starts_with('[') && line.ends_with(']') {
            let section_name = &line[1..line.len()-1];
            current_section = Some(section_name.to_string());
            log::debug!("LEGACY: Found section [{}]", section_name);
            continue;
        }

        // Parse key=value format
        if let Some((key_name, key_value)) = parse_ini_line(line) {
            // Determine the target name
            let target = if key_name.eq_ignore_ascii_case("key") {
                // If the key name is "key", use the section name as target
                match &current_section {
                    Some(section) => section.clone(),
                    None => {
                        log::warn!("LEGACY: Found 'key=' without a section, skipping");
                        continue;
                    }
                }
            } else {
                // Use the key name as target (legacy format: target=key)
                key_name.clone()
            };

            // Decode the key value - handle both hex and plaintext formats
            let key_bytes = decode_key_value(&key_value)?;

            // Validate key length (Blowfish accepts 4-56 bytes)
            if key_bytes.len() >= 4 && key_bytes.len() <= 56 {
                let normalized_target = crate::utils::normalize_target_lowercase(&target);
                keys.insert(normalized_target.clone(), key_bytes);
                log::debug!("LEGACY: Loaded key for '{}'", normalized_target);
            } else {
                log::warn!(
                    "LEGACY: Invalid key length for '{}' ({} bytes), skipping",
                    target,
                    key_bytes.len()
                );
            }
        }
    }

    Ok(keys)
}

/// Decode a key value from blowfish.ini
/// Supports:
/// - Hex encoded keys (e.g., "6162636465666768")
/// - Plaintext keys with +OK prefix (e.g., "+OK secretpassword")
/// - Plain text keys (e.g., "mysecretkey")
fn decode_key_value(value: &str) -> Result<Vec<u8>, DllError> {
    let value = value.trim();
    
    // Check for +OK prefix (FiSH 10 plaintext key format)
    if let Some(plaintext) = value.strip_prefix("+OK ") {
        return Ok(plaintext.as_bytes().to_vec());
    }
    
    // Check for mcps prefix (CBC mode plaintext key)
    if let Some(plaintext) = value.strip_prefix("mcps ") {
        return Ok(plaintext.as_bytes().to_vec());
    }
    
    // Try to decode as hex
    if value.chars().all(|c| c.is_ascii_hexdigit()) && value.len() % 2 == 0 {
        return hex::decode(value).map_err(|e| DllError::LegacyError {
            context: "Decoding hex key".to_string(),
            cause: format!("Invalid hex: {}", e),
        });
    }
    
    // Assume it's a plaintext key
    Ok(value.as_bytes().to_vec())
}

/// Parse a blowfish.ini line in format: target=hexkey
fn parse_ini_line(line: &str) -> Option<(String, String)> {
    let parts: Vec<&str> = line.splitn(2, '=').collect();

    if parts.len() == 2 {
        let target = parts[0].trim().to_string();
        let key_hex = parts[1].trim().to_string();

        // Skip empty targets or keys
        if !target.is_empty() && !key_hex.is_empty() {
            return Some((target, key_hex));
        }
    }

    None
}

/// Save a key to blowfish.ini file
pub fn save_key_to_blowfish_ini(target: &str, key: &[u8], path: &str) -> Result<(), DllError> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let key_hex = hex::encode(key);
    let line = format!("{}={}\n", target, key_hex);

    // Open the file in append mode, create if it doesn't exist
    let mut file = OpenOptions::new().create(true).append(true).open(path).map_err(|e| {
        DllError::LegacyError {
            context: "Writing to blowfish.ini".to_string(),
            cause: format!("Failed to open file: {}", e),
        }
    })?;

    // Write the key
    file.write_all(line.as_bytes()).map_err(|e| DllError::LegacyError {
        context: "Writing to blowfish.ini".to_string(),
        cause: format!("Failed to write: {}", e),
    })?;

    log::debug!("LEGACY: Saved key for '{}' to {}", target, path);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_parse_ini_line() {
        let result = parse_ini_line("#test=6162636465666768");
        assert!(result.is_some());
        let (target, key) = result.unwrap();
        assert_eq!(target, "#test");
        assert_eq!(key, "6162636465666768");
    }

    #[test]
    fn test_parse_ini_line_invalid() {
        let result = parse_ini_line("invalidline");
        assert!(result.is_none());
    }

    #[test]
    fn test_load_keys_from_ini_legacy_format() {
        // Create a temporary blowfish.ini file with legacy format
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "#test=6162636465666768").unwrap();
        writeln!(temp_file, "#another=1234567890abcdef").unwrap();
        writeln!(temp_file, "; This is a comment").unwrap();
        writeln!(temp_file, "").unwrap();

        let path = temp_file.path();
        let result = load_keys_from_blowfish_ini(path);

        assert!(result.is_ok());
        let keys = result.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains_key("#test"));
        assert!(keys.contains_key("#another"));
    }

    #[test]
    fn test_load_keys_from_ini_section_format() {
        // Create a temporary blowfish.ini file with section format
        let mut temp_file = NamedTempFile::new().unwrap();
        writeln!(temp_file, "[irc.server.net:#channel]").unwrap();
        writeln!(temp_file, "key=6162636465666768").unwrap();
        writeln!(temp_file, "[user:nickname]").unwrap();
        writeln!(temp_file, "key=0102030405060708").unwrap();

        let path = temp_file.path();
        let result = load_keys_from_blowfish_ini(path);

        assert!(result.is_ok());
        let keys = result.unwrap();
        assert_eq!(keys.len(), 2);
        assert!(keys.contains_key("irc.server.net:#channel"));
        assert!(keys.contains_key("user:nickname"));
    }

    #[test]
    fn test_decode_key_value_hex() {
        let result = decode_key_value("6162636465666768");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"abcdefgh");
    }

    #[test]
    fn test_decode_key_value_plaintext_ok() {
        let result = decode_key_value("+OK mysecretkey");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"mysecretkey");
    }

    #[test]
    fn test_decode_key_value_plaintext_mcps() {
        let result = decode_key_value("mcps cbcsecret");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"cbcsecret");
    }

    #[test]
    fn test_decode_key_value_plaintext_fallback() {
        let result = decode_key_value("notahexkey123");
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), b"notahexkey123");
    }
}
