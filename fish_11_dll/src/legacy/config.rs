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
fn load_keys_from_blowfish_ini(
    path: &std::path::Path,
) -> Result<std::collections::HashMap<String, Vec<u8>>, DllError> {
    use std::fs;
    use std::io::BufRead;

    let mut keys = std::collections::HashMap::new();

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
        if line.is_empty() || line.starts_with(';') || line.starts_with('#') {
            continue;
        }

        // Parse key=value format
        if let Some((target, key_hex)) = parse_ini_line(line) {
            // Decode the hex key
            let key_bytes = hex::decode(key_hex).map_err(|e| DllError::LegacyError {
                context: format!("Decoding key for '{}'", target),
                cause: format!("Invalid hex: {}", e),
            })?;

            // Validate key length
            if key_bytes.len() >= 4 && key_bytes.len() <= 56 {
                keys.insert(target.clone(), key_bytes);
                log::debug!("LEGACY: Loaded key for '{}'", target);
            } else {
                log::warn!(
                    "LEGACY: Invalid key length for '{}' ({} bytes)",
                    target,
                    key_bytes.len()
                );
            }
        }
    }

    Ok(keys)
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
    use std::fs::{File, OpenOptions};
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

/// Get the current mIRC directory from the main configuration
fn get_mirc_directory() -> Result<std::path::PathBuf, DllError> {
    crate::config::get_mirc_directory().map_err(|e| DllError::ConfigError(e.to_string()))
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
    fn test_load_keys_from_ini() {
        // Create a temporary blowfish.ini file
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
}
