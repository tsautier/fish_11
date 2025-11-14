//! File storage operations for configuration
use std::fs;
use std::path::PathBuf;

use configparser::ini::Ini;
use secrecy::ExposeSecret;

use crate::config::models::{EntryData, FishConfig};
use crate::error::{FishError, Result};
use crate::log_error;
use crate::log_info;
use crate::log_warn;
use crate::utils::base64_encode;
use crate::{crypto, log_debug, log_trace};

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
    log_debug!("get_config_path: Determining configuration file path");

    // Use environment variable for mIRC directory
    match std::env::var("MIRCDIR") {
        Ok(mirc_path) => {
            log_debug!("get_config_path: Found MIRCDIR environment variable: {}", mirc_path);

            let mut path = PathBuf::from(mirc_path);
            log_debug!("get_config_path: Created path from MIRCDIR: {}", path.display());

            // Validate path - detect directory traversal attempts
            if path.to_string_lossy().contains("..") {
                log_error!(
                    "get_config_path: Invalid path containing directory traversal: {}",
                    path.display()
                );
                return Err(FishError::ConfigError(
                    "Invalid config path: potential directory traversal".to_string(),
                ));
            }

            path.push("fish_11.ini");
            log_info!("get_config_path: Using config path from MIRCDIR: {}", path.display());

            Ok(path)
        }
        Err(e) => {
            log_warn!("get_config_path: MIRCDIR environment variable not found: {}", e);

            // FALLBACK: Use current directory if MIRCDIR is not set
            // This prevents crashes and allows the DLL to work even if the environment variable is missing
            let mut path = match std::env::current_dir() {
                Ok(dir) => dir,
                Err(e) => {
                    log_error!("get_config_path: failed to get current directory: {}", e);
                    // Fallback: use "fish_11.ini" in current directory
                    PathBuf::new()
                }
            };
            path.push("fish_11.ini");

            log_warn!(
                "get_config_path: using fallback config path (current directory): {}",
                path.display()
            );

            Ok(path)
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
    let total_start = std::time::Instant::now();
    log_warn!("=== load_config: starting configuration load ===");

    // Set a timeout to prevent hanging
    let start_time = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(5);

    let mut config = FishConfig::new();

    let path_start = std::time::Instant::now();
    let config_path = match path_override {
        Some(path) => {
            log_debug!("load_config: using override path: {}", path.display());
            path
        }
        None => get_config_path()?,
    };
    log_warn!("load_config: get_config_path took {:?}", path_start.elapsed());

    log_debug!("load_config: config path: {}", config_path.display());

    // Check if we've timed out already
    if start_time.elapsed() > timeout {
        return Err(FishError::ConfigError("Configuration loading timed out".to_string()));
    }

    // Check if the config file exists
    let exists_start = std::time::Instant::now();
    let file_exists = config_path.exists();

    log_warn!("load_config: path.exists() took {:?}", exists_start.elapsed());

    if !file_exists {
        log_info!("load_config: config file does not exist, generating new keypair");

        // Generate a keypair using crypto module
        let keypair_start = std::time::Instant::now();
        let keypair = crypto::generate_keypair();
        log_warn!("load_config: generate_keypair took {:?}", keypair_start.elapsed());

        // Store the keypair in the config
        config.our_private_key = Some(base64_encode(keypair.private_key.expose_secret()));
        config.our_public_key = Some(base64_encode(&keypair.public_key));

        // Save the config
        let save_start = std::time::Instant::now();
        save_config(&config, None)?;

        log_warn!("load_config: save_config took {:?}", save_start.elapsed());
        log_warn!("load_config: TOTAL (new file) {:?}", total_start.elapsed());

        return Ok(config);
    }

    log_trace!("load_config: loading existing config file");

    // Create a new Ini object and load the file
    let mut ini = Ini::new();

    // Check if we've timed out before loading ini
    if start_time.elapsed() > timeout {
        return Err(FishError::ConfigError(
            "Configuration loading timed out before ini load".to_string(),
        ));
    }

    let ini_start = std::time::Instant::now();

    match ini.load(&config_path) {
        Ok(_) => {
            log_warn!("load_config: ini.load() took {:?}", ini_start.elapsed());
        }
        Err(e) => {
            log_error!(
                "load_config: failed to load INI file from {}: {}",
                config_path.display(),
                e
            );
            return Err(FishError::ConfigError(format!("Failed to load config: {}", e)));
        }
    };

    // Check if we've timed out after loading ini
    if start_time.elapsed() > timeout {
        return Err(FishError::ConfigError(
            "Configuration loading timed out after ini load".to_string(),
        ));
    }

    let cache_start = std::time::Instant::now();
    // OPTIMISATION: Build case-insensitive section lookup cache ONCE
    let sections_lower: std::collections::HashMap<String, String> =
        ini.sections().iter().map(|s| (s.to_lowercase(), s.clone())).collect();

    log_warn!("load_config: section cache built in {:?}", cache_start.elapsed());
    log_trace!("load_config: processing [Keys] section...");

    let keys_start = std::time::Instant::now();

    // Load [Keys] section (case-insensitive, optimized)
    if let Some(section_name) = sections_lower.get("keys") {
        if let Some(section_map) = ini.get_map_ref().get(section_name) {
            for (k, v_opt) in section_map.iter() {
                if let Some(v) = v_opt {
                    config.keys.insert(k.clone(), v.clone());
                }
            }
        }
    }
    log_warn!(
        "load_config: [Keys] processed in {:?} ({} keys)",
        keys_start.elapsed(),
        config.keys.len()
    );

    log_trace!("load_config: processing [KeyPair] section...");

    let keypair_section_start = std::time::Instant::now();

    // Load [KeyPair] section (case-insensitive, optimized)
    if let Some(section_name) = sections_lower.get("keypair") {
        if let Some(private) = ini.get(section_name, "private") {
            config.our_private_key = Some(private.to_string());
        }
        if let Some(public) = ini.get(section_name, "public") {
            config.our_public_key = Some(public.to_string());
        }
    }
    log_warn!("load_config: [KeyPair] processed in {:?}", keypair_section_start.elapsed());

    log_trace!("load_config: processing [NickNetworks] section...");

    let nick_start = std::time::Instant::now();
    // Load [NickNetworks] section (case-insensitive, optimized)
    if let Some(section_name) = sections_lower.get("nicknetworks") {
        if let Some(section_map) = ini.get_map_ref().get(section_name) {
            for (k, v_opt) in section_map.iter() {
                if let Some(v) = v_opt {
                    config.nick_networks.insert(k.clone(), v.clone());
                }
            }
        }
    }
    log_warn!("load_config: [NickNetworks] processed in {:?}", nick_start.elapsed());
    log_trace!("load_config: processing [FiSH11] section...");

    let fish11_start = std::time::Instant::now();

    // Load [FiSH11] section (case-insensitive, optimized)
    if let Some(section_name) = sections_lower.get("fish11") {
        if let Some(value) = ini.get(section_name, "process_incoming") {
            config.fish11.process_incoming = value.eq_ignore_ascii_case("true") || value == "1";
        }

        if let Some(value) = ini.get(section_name, "process_outgoing") {
            config.fish11.process_outgoing = value.eq_ignore_ascii_case("true") || value == "1";
        }

        if let Some(value) = ini.get(section_name, "plain_prefix") {
            config.fish11.plain_prefix = value.to_string();
        }

        if let Some(value) = ini.get(section_name, "encrypt_notice") {
            config.fish11.encrypt_notice = value.eq_ignore_ascii_case("true") || value == "1";
        }

        if let Some(value) = ini.get(section_name, "encrypt_action") {
            config.fish11.encrypt_action = value.eq_ignore_ascii_case("true") || value == "1";
        }

        if let Some(value) = ini.get(section_name, "mark_position") {
            if let Ok(pos) = value.parse() {
                config.fish11.mark_position = pos;
            }
        }

        if let Some(value) = ini.get(section_name, "mark_encrypted") {
            config.fish11.mark_encrypted = value.to_string();
        }

        if let Some(value) = ini.get(section_name, "no_fish10_legacy") {
            config.fish11.no_fish10_legacy = value.eq_ignore_ascii_case("true") || value == "1";
        }
    }
    log_warn!("load_config: [FiSH11] processed in {:?}", fish11_start.elapsed());
    let startup_start = std::time::Instant::now();
    // Load [Startup] section (case-insensitive, optimized)
    if let Some(section_name) = sections_lower.get("startup") {
        if let Some(value) = ini.get(section_name, "date") {
            if let Ok(date) = value.parse() {
                config.startup_data.date = Some(date);
            }
        }
    }
    log_warn!("load_config: [Startup] processed in {:?}", startup_start.elapsed());

    let entries_start = std::time::Instant::now();
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
            #[cfg(debug_assertions)]
            println!("DEBUG:   -> processing entry section: '{}'", section_name);

            // Clean section name: remove any brackets (should not be present, but defensive)
            if section_name.starts_with('[') || section_name.ends_with(']') {
                #[cfg(debug_assertions)]
                eprintln!(
                    "WARNING: Section name '{}' contains brackets. This may indicate malformed data.",
                    section_name
                );
            }
            let clean_section = section_name.trim_start_matches('[').trim_end_matches(']');

            // Transform chan_ prefix back to # for channels
            let entry_key = if clean_section.starts_with("chan_") {
                clean_section.replacen("chan_", "#", 1)
            } else {
                clean_section.to_string()
            };

            let mut entry = EntryData::default();

            if let Some(key_value) = ini.get(&section_name, "key") {
                #[cfg(debug_assertions)]
                println!("DEBUG:     found key: '{}'", key_value);
                entry.key = Some(key_value.to_string());
            } else {
                #[cfg(debug_assertions)]
                println!("DEBUG:     no key found for section '{}'", section_name);
            }

            if let Some(date_value) = ini.get(&section_name, "date") {
                #[cfg(debug_assertions)]
                println!("DEBUG:     found date: '{}'", date_value);
                entry.date = Some(date_value.to_string());
            } else {
                #[cfg(debug_assertions)]
                println!("DEBUG:     no date found for section '{}'", section_name);
            }
            config.entries.insert(entry_key.clone(), entry);
            #[cfg(debug_assertions)]
            println!("DEBUG:     inserted entry for: '{}'", entry_key);
        } else {
            #[cfg(debug_assertions)]
            println!("DEBUG:   -> skipping non-entry section (no @): '{}'", section_name);
        }
    }
    log_warn!(
        "load_config: entries processed in {:?} ({} entries)",
        entries_start.elapsed(),
        config.entries.len()
    );

    #[cfg(debug_assertions)]
    println!("DEBUG: finished processing sections. Total entries loaded: {}", config.entries.len());

    log_warn!("=== load_config: TOTAL {:?} ===", total_start.elapsed());
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
    let start_time = std::time::Instant::now();

    log_debug!(
        "save_config: starting (entries: {}, keys: {})",
        config.entries.len(),
        config.keys.len()
    );

    let mut ini = Ini::new();

    // Save [Keys] section
    let keys_section = "Keys";
    for (k, v) in &config.keys {
        ini.set(keys_section, k, Some(v.clone()));
    }

    // Save [KeyPair] section
    if let Some(private) = &config.our_private_key {
        ini.set("KeyPair", "private", Some(private.to_string()));
    }
    if let Some(public) = &config.our_public_key {
        ini.set("KeyPair", "public", Some(public.to_string()));
    }

    // Save [NickNetworks] section
    let nick_section = "NickNetworks";
    for (k, v) in &config.nick_networks {
        ini.set(nick_section, k, Some(v.clone()));
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
    }

    // OPTIMISATION: Save entry sections with minimal allocations
    let entries_start = std::time::Instant::now();

    for (key, entry) in &config.entries {
        // Clean up the key: remove any existing brackets that might have been accidentally included
        let clean_key = key.trim_start_matches('[').trim_end_matches(']');

        // Transform keys that start with # to use chan_ prefix for INI compatibility
        // Use Cow to avoid unnecessary allocations when no transformation is needed
        let section_name: std::borrow::Cow<str> = if clean_key.starts_with('#') {
            std::borrow::Cow::Owned(clean_key.replacen('#', "chan_", 1))
        } else {
            std::borrow::Cow::Borrowed(clean_key)
        };

        if let Some(key_val) = &entry.key {
            ini.set(section_name.as_ref(), "key", Some(key_val.clone()));
        }
        if let Some(date) = &entry.date {
            ini.set(section_name.as_ref(), "date", Some(date.clone()));
        }
    }

    let entries_duration = entries_start.elapsed();
    if entries_duration.as_millis() > 100 {
        log_warn!(
            "save_config: entries processing took {:?} for {} entries",
            entries_duration,
            config.entries.len()
        );
    }

    // Get config path
    let config_path = match path_override {
        Some(path) => path,
        None => get_config_path()?,
    };
    log_debug!("save_config: Config path: {}", config_path.display());

    // Create parent directories if they don't exist
    if let Some(parent) = config_path.parent() {
        if !parent.exists() {
            log_debug!("save_config: creating parent directory: {}", parent.display());
            fs::create_dir_all(parent)?;
        }
    }

    // Create a temp path for safe writing
    let temp_path = config_path.with_extension("tmp");

    // Write to the temp file first
    let write_start = std::time::Instant::now();

    match ini.write(&temp_path) {
        Ok(_) => {
            let write_duration = write_start.elapsed();

            // Now rename the temp file to the actual config file
            match fs::rename(&temp_path, &config_path) {
                Ok(_) => {
                    let total_duration = start_time.elapsed();

                    log_debug!(
                        "save_config: completed in {:?} (write: {:?}, entries: {:?})",
                        total_duration,
                        write_duration,
                        entries_duration
                    );

                    if total_duration.as_secs() > 1 {
                        log_warn!(
                            "save_config: SLOW SAVE! Took {:?} for {} entries. Check disk I/O.",
                            total_duration,
                            config.entries.len()
                        );
                    }

                    // Mark config as clean after successful save
                    config.mark_clean();

                    Ok(())
                }
                Err(e) => {
                    log_error!("save_config: failed to rename temp file: {}", e);
                    // Clean up temp file if rename failed
                    let _ = fs::remove_file(&temp_path);
                    Err(FishError::ConfigError(format!("Failed to finalize config file: {}", e)))
                }
            }
        }
        Err(e) => {
            log_error!("save_config: failed to write to temp file: {}", e);
            Err(FishError::ConfigError(format!("Failed to write config: {}", e)))
        }
    }
}

#[cfg(test)]
mod tests {
    use tempfile::NamedTempFile;

    use super::*;
    use crate::config::models::{EntryData, FishConfig};
    use crate::utils::generate_random_bytes;

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
                date: Some("2025-01-01 00:00:00".to_string()),
            },
        );
        config.entries.insert(
            "#test_chan@test_net".to_string(),
            EntryData {
                key: Some("chan_key_b64".to_string()),
                date: Some("2025-01-02 00:00:00".to_string()),
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

        // Vérifie que le fallback fonctionne : le chemin doit être fish_11.ini dans le répertoire courant
        assert!(path_result.is_ok());
        let path = path_result.unwrap();
        let mut expected_path = std::env::current_dir().unwrap();
        expected_path.push("fish_11.ini");
        assert_eq!(path, expected_path);
    }
}
