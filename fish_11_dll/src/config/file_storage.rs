//! File storage operations for configuration

use std::fs;
use std::path::PathBuf;

use configparser::ini::Ini;
use directories::BaseDirs;
use secrecy::ExposeSecret;

use crate::config::models::{EntryData, FishConfig};
use crate::crypto;
use crate::error::{FishError, Result};
use crate::utils::base64_encode;

/// Initialize the config file if it doesn't exist
pub fn init_config_file() -> Result<()> {
    let config_path = get_config_path()?;
    if config_path.exists() {
        return Ok(());
    }

    let mut ini = Ini::new();
    ini.set("FiSH11", "process_incoming", Some("true".to_string()));
    ini.set("FiSH11", "plain_prefix", Some("+p ".to_string()));

    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)?;
    }
    ini.write(&config_path)?;
    Ok(())
}

/// Get the path to the config file
pub fn get_config_path() -> Result<PathBuf> {
    log::debug!("get_config_path: Determining configuration file path");

    // Use environment variable for mIRC directory
    match std::env::var("MIRCDIR") {
        Ok(mirc_path) => {
            log::debug!("get_config_path: Found MIRCDIR environment variable: {}", mirc_path);

            let mut path = PathBuf::from(mirc_path);
            log::debug!("get_config_path: Created path from MIRCDIR: {}", path.display());

            // Validate path - detect directory traversal attempts
            if path.to_string_lossy().contains("..") {
                log::error!(
                    "get_config_path: Invalid path containing directory traversal: {}",
                    path.display()
                );
                return Err(FishError::ConfigError(
                    "Invalid config path: potential directory traversal".to_string(),
                ));
            }

            path.push("fish_11.ini");
            log::info!("get_config_path: Using config path from MIRCDIR: {}", path.display());

            Ok(path)
        }
        Err(e) => {
            log::error!("get_config_path: MIRCDIR environment variable not found: {}", e);
            Err(FishError::ConfigError("MIRCDIR environment variable not set".to_string()))
        }
    }
}

/// Loads the configuration from the disk or creates a new one if it doesn't exist.
///
/// This function will:
/// 1. Check if the config file exists at the expected location
/// 2. If it doesn't exist, generate a new keypair and create a default configuration
/// 3. If it exists, load all configuration sections (Keys, KeyPair, NickNetworks, etc.)
///
/// # Returns
///
/// - `Result<FishConfig>` - The loaded configuration or an error
pub fn load_config(path_override: Option<PathBuf>) -> Result<FishConfig> {
    // Set a timeout to prevent hanging
    let start_time = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(5);

    let mut config = FishConfig::new();
    let config_path = match path_override {
        Some(path) => path,
        None => get_config_path()?,
    };

    // Check if we've timed out already
    if start_time.elapsed() > timeout {
        return Err(FishError::ConfigError("Configuration loading timed out".to_string()));
    }

    // Check if the config file exists
    if !config_path.exists() {
        // Generate a keypair using crypto module
        let keypair = crypto::generate_keypair();

        // Store the keypair in the config
        config.our_private_key = Some(base64_encode(keypair.private_key.expose_secret()));
        config.our_public_key = Some(base64_encode(&keypair.public_key));

        // Save the config
        save_config(&config, None)?;

        return Ok(config);
    } // Create a new Ini object and load the file
    let mut ini = Ini::new();

    // Check if we've timed out before loading ini
    if start_time.elapsed() > timeout {
        return Err(FishError::ConfigError(
            "Configuration loading timed out before ini load".to_string(),
        ));
    }

    match ini.load(&config_path) {
        Ok(_) => {
            log::debug!("load_config: INI file loaded successfully from {}", config_path.display());
            log::debug!("load_config: Sections found: {:?}", ini.sections());
            log::debug!("load_config: Full INI map: {:?}", ini.get_map_ref());
        }
        Err(e) => return Err(FishError::ConfigError(format!("Failed to load config: {}", e))),
    };

    // Check if we've timed out after loading ini
    if start_time.elapsed() > timeout {
        return Err(FishError::ConfigError(
            "Configuration loading timed out after ini load".to_string(),
        ));
    }

    // Load [Keys] section (case-insensitive)
    for key in ["Keys", "keys"] {
        if let Some(section_map) = ini.get_map_ref().get(key) {
            for (k, v_opt) in section_map.iter() {
                if let Some(v) = v_opt {
                    config.keys.insert(k.clone(), v.clone());
                }
            }
            break; // Found the section, no need to check other cases
        }
    }

    // Load [KeyPair] section (case-insensitive)
    for key in ["KeyPair", "keypair"] {
        if let Some(private) = ini.get(key, "private") {
            config.our_private_key = Some(private.to_string());
        }
        if let Some(public) = ini.get(key, "public") {
            config.our_public_key = Some(public.to_string());
        }
    }

    // Load [NickNetworks] section (case-insensitive)
    for key in ["NickNetworks", "nicknetworks"] {
        if let Some(section_map) = ini.get_map_ref().get(key) {
            for (k, v_opt) in section_map.iter() {
                if let Some(v) = v_opt {
                    config.nick_networks.insert(k.clone(), v.clone());
                }
            }
            break; // Found the section, no need to check other cases
        }
    }

    // Load [FiSH11] section (case-insensitive)
    for section_key in ["FiSH11", "fish11"] {
        if let Some(value) = ini.get(section_key, "process_incoming") {
            config.fish11.process_incoming = value.eq_ignore_ascii_case("true") || value == "1";
        }

        if let Some(value) = ini.get(section_key, "process_outgoing") {
            config.fish11.process_outgoing = value.eq_ignore_ascii_case("true") || value == "1";
        }

        if let Some(value) = ini.get(section_key, "plain_prefix") {
            config.fish11.plain_prefix = value.to_string();
        }

        if let Some(value) = ini.get(section_key, "encrypt_notice") {
            config.fish11.encrypt_notice = value.eq_ignore_ascii_case("true") || value == "1";
        }

        if let Some(value) = ini.get(section_key, "encrypt_action") {
            config.fish11.encrypt_action = value.eq_ignore_ascii_case("true") || value == "1";
        }

        if let Some(value) = ini.get(section_key, "mark_position") {
            if let Ok(pos) = value.parse() {
                config.fish11.mark_position = pos;
            }
        }

        if let Some(value) = ini.get(section_key, "mark_encrypted") {
            config.fish11.mark_encrypted = value.to_string();
        }

        if let Some(value) = ini.get(section_key, "no_fish10_legacy") {
            config.fish11.no_fish10_legacy = value.eq_ignore_ascii_case("true") || value == "1";
        }
    }

    // Load [Startup] section (case-insensitive)
    for section_key in ["Startup", "startup"] {
        if let Some(value) = ini.get(section_key, "date") {
            if let Ok(date) = value.parse() {
                config.startup_data.date = Some(date);
            }
        }
    }

    // Load entries from section-based format [nickname@network] and [chan_channel@network] sections
    for section_name in ini.sections() {
        // Skip the standard configuration sections (case-insensitive comparison)
        let section_lower = section_name.to_lowercase();
        if section_lower == "keys"
            || section_lower == "keypair"
            || section_lower == "nicknetworks"
            || section_lower == "fish11"
            || section_lower == "startup"
            || section_name.starts_with("Entry.")
        {
            continue;
        }

        // Check if this is a valid entry section (contains @ indicating network format)
        if section_name.contains('@') {
            println!("DEBUG:   -> Processing entry section: '{}'", section_name);

            // Transform chan_ prefix back to # for channels
            let entry_key = if section_name.starts_with("chan_") {
                section_name.replacen("chan_", "#", 1)
            } else {
                section_name.clone()
            };

            let mut entry = EntryData::default();

            if let Some(key_value) = ini.get(&section_name, "key") {
                println!("DEBUG:     Found key: '{}'", key_value);
                entry.key = Some(key_value.to_string());
            } else {
                println!("DEBUG:     No key found for section '{}'", section_name);
            }

            if let Some(date_value) = ini.get(&section_name, "date") {
                println!("DEBUG:     Found date: '{}'", date_value);
                entry.date = Some(date_value.to_string());
            } else {
                println!("DEBUG:     No date found for section '{}'", section_name);
            }
            config.entries.insert(entry_key.clone(), entry);
            println!("DEBUG:     Inserted entry for: '{}'", entry_key);
        } else {
            println!("DEBUG:   -> Skipping non-entry section (no @): '{}'", section_name);
        }
    }

    println!("DEBUG: Finished processing sections. Total entries loaded: {}", config.entries.len());

    Ok(config)
}

/// Saves the configuration to disk.
///
/// This function serializes the entire FishConfig object to an INI format and writes it to the
/// standard configuration file location. It will create any necessary parent directories
/// if they don't already exist.
///
/// # Arguments
///
/// * `config` - A reference to the FishConfig object to be saved
///
/// # Returns
///
/// - `Result<()>` - Success (unit type) or an error
pub fn save_config(config: &FishConfig, path_override: Option<PathBuf>) -> Result<()> {
    // Add timeout to prevent hanging during file operations
    let start_time = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(3); // Slightly longer timeout for file operations

    log::debug!("save_config: starting configuration save");

    let mut ini = Ini::new();

    // Check timeout
    if start_time.elapsed() > timeout {
        log::error!("save_config: timed out before saving keys");
        return Err(FishError::ConfigError("Timed out before saving keys".to_string()));
    }

    // Save [Keys] section
    for (k, v) in &config.keys {
        ini.set("Keys", k, Some(v.to_string()));
    }

    // Save [KeyPair] section
    if let Some(private) = &config.our_private_key {
        ini.set("KeyPair", "private", Some(private.to_string()));
    }
    if let Some(public) = &config.our_public_key {
        ini.set("KeyPair", "public", Some(public.to_string()));
    }

    // Save [NickNetworks] section
    for (k, v) in &config.nick_networks {
        ini.set("NickNetworks", k, Some(v.to_string()));
    }

    // Save [FiSH11] section
    ini.set("FiSH11", "process_incoming", Some(config.fish11.process_incoming.to_string()));
    ini.set("FiSH11", "process_outgoing", Some(config.fish11.process_outgoing.to_string()));
    ini.set("FiSH11", "plain_prefix", Some(config.fish11.plain_prefix.clone()));
    ini.set("FiSH11", "encrypt_notice", Some(config.fish11.encrypt_notice.to_string()));
    ini.set("FiSH11", "encrypt_action", Some(config.fish11.encrypt_action.to_string()));
    ini.set("FiSH11", "mark_position", Some(config.fish11.mark_position.to_string()));
    ini.set("FiSH11", "mark_encrypted", Some(config.fish11.mark_encrypted.clone()));
    ini.set("FiSH11", "no_fish10_legacy", Some(config.fish11.no_fish10_legacy.to_string()));

    // Save [Startup] section
    if let Some(date) = config.startup_data.date {
        ini.set("Startup", "date", Some(date.to_string()));
    } // Save entry sections in new format [nickname@network] and [chan_channel@network]
    for (key, entry) in &config.entries {
        // Transform keys that start with # to use chan_ prefix for INI compatibility
        let section_name =
            if key.starts_with('#') { key.replacen('#', "chan_", 1) } else { key.clone() };

        if let Some(key_val) = &entry.key {
            ini.set(&section_name, "key", Some(key_val.clone()));
        }
        if let Some(date) = &entry.date {
            ini.set(&section_name, "date", Some(date.clone()));
        }
    }

    // Check timeout before file operations
    if start_time.elapsed() > timeout {
        log::error!("save_config: timed out before file operations");
        return Err(FishError::ConfigError("Timed out before file operations".to_string()));
    }

    // Get config path
    let config_path = match path_override {
        Some(path) => path,
        None => get_config_path()?,
    };
    log::debug!("save_config: Config path: {}", config_path.display());

    // Create parent directories if they don't exist
    if let Some(parent) = config_path.parent() {
        if !parent.exists() {
            log::debug!("save_config: creating parent directory: {}", parent.display());
            fs::create_dir_all(parent)?;
        }
    }

    // Create a temp path for safe writing
    let temp_path = config_path.with_extension("tmp");
    log::debug!("save_config: using temp file: {}", temp_path.display());

    // Check timeout before writing file
    if start_time.elapsed() > timeout {
        log::error!("save_config: timed out before writing config file");
        return Err(FishError::ConfigError("Timed out before writing config file".to_string()));
    }

    // Write to the temp file first
    match ini.write(&temp_path) {
        Ok(_) => {
            log::debug!("save_config: successfully wrote to temp file");
            // Now rename the temp file to the actual config file
            match fs::rename(&temp_path, &config_path) {
                Ok(_) => {
                    log::debug!("save_config: successfully renamed temp file to config file");
                    Ok(())
                }
                Err(e) => {
                    log::error!("save_config: failed to rename temp file: {}", e);
                    // Clean up temp file if rename failed
                    let _ = fs::remove_file(&temp_path);
                    Err(FishError::ConfigError(format!("Failed to finalize config file: {}", e)))
                }
            }
        }
        Err(e) => {
            log::error!("save_config: failed to write to temp file: {}", e);
            Err(FishError::ConfigError(format!("Failed to write config: {}", e)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::models::{EntryData, Fish11Section, FishConfig, StartupSection};
    use crate::utils::generate_random_bytes;
    use tempfile::NamedTempFile;

    // Helper to create a dummy config for testing
    fn create_dummy_config() -> FishConfig {
        let mut config = FishConfig::new();
        config.keys.insert("test_key_legacy".to_string(), "value_legacy".to_string());
        config.nick_networks.insert("test_nick".to_string(), "test_net".to_string());
        config.our_private_key = Some(base64_encode(&generate_random_bytes(32)));
        config.our_public_key = Some(base64_encode(&generate_random_bytes(32)));
        config.fish11.process_incoming = false;
        config.fish11.plain_prefix = "!!".to_string();
        // Note: configparser library trims whitespace from INI values, so we can't have leading spaces
        config.fish11.mark_encrypted = "12$chr(183)".to_string();
        config.startup_data.date = Some(123456789);
        config.entries.insert(
            "test_entry@test_net".to_string(),
            EntryData {
                key: Some("entry_key_b64".to_string()),
                date: Some("01/01/2025".to_string()),
            },
        );
        config.entries.insert(
            "#test_chan@test_net".to_string(),
            EntryData {
                key: Some("chan_key_b64".to_string()),
                date: Some("02/01/2025".to_string()),
            },
        );
        config
    }

    #[test]
    fn test_save_and_load_config_roundtrip() {
        // Tests that a config can be saved to a temporary file and loaded back correctly.
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let temp_path = temp_file.path().to_path_buf();

        let original_config = create_dummy_config();

        // Save the config to the temporary path
        save_config(&original_config, Some(temp_path.clone())).expect("Failed to save config");

        // Load the config back from the temporary path
        let loaded_config = load_config(Some(temp_path.clone())).expect("Failed to load config");

        // Assert that the loaded config matches the original
        assert_eq!(original_config, loaded_config);

        // Ensure the temp file is cleaned up
        let _ = fs::remove_file(&temp_path);
    }

    #[test]
    fn test_load_non_existent_config_creates_default() {
        // Tests that loading a non-existent config creates a default one.
        let temp_file = NamedTempFile::new().expect("Failed to create temp file");
        let temp_path = temp_file.path().to_path_buf();
        let _ = fs::remove_file(&temp_path); // Ensure it doesn't exist

        let loaded_config =
            load_config(Some(temp_path.clone())).expect("Failed to load non-existent config");

        // Check some default values
        assert!(loaded_config.our_private_key.is_some());
        assert!(loaded_config.our_public_key.is_some());
        assert_eq!(loaded_config.fish11.process_incoming, true);
        assert_eq!(loaded_config.fish11.plain_prefix, "+p ".to_string());

        // Ensure the temp file is cleaned up
        let _ = fs::remove_file(&temp_path);
    }

    #[test]
    fn test_get_config_path_with_mircdir() {
        // Set a temporary directory for MIRCDIR
        let temp_dir = tempfile::tempdir().expect("Failed to create temp dir");
        std::env::set_var("MIRCDIR", temp_dir.path());

        // Call the function
        let path_result = get_config_path();

        // Check that we got a valid path
        assert!(path_result.is_ok());

        let path = path_result.unwrap();

        // Check that the path is correct
        let mut expected_path = temp_dir.path().to_path_buf();
        expected_path.push("fish_11.ini");
        assert_eq!(path, expected_path);
    }

    #[test]
    fn test_get_config_path_no_mircdir() {
        // Ensure MIRCDIR is not set
        std::env::remove_var("MIRCDIR");

        // Call the function
        let path_result = get_config_path();

        // Check that we got an error
        assert!(path_result.is_err());
    }
}
