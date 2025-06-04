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

    // First, try to use environment variable for mIRC directory if available
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

            // Check if the path looks valid
            log::debug!("get_config_path: Path exists? {}", path.exists());
            if path.exists() {
                log::debug!("get_config_path: Path is file? {}", path.is_file());
                log::debug!("get_config_path: Path is directory? {}", path.is_dir());
            }

            return Ok(path);
        }
        Err(e) => {
            log::debug!("get_config_path: MIRCDIR environment variable not found: {}", e);
        }
    }

    // Fallback to local directory (where the DLL is loaded)
    match std::env::current_exe() {
        Ok(dll_path) => {
            log::debug!("get_config_path: Current executable path: {}", dll_path.display());

            if let Some(parent) = dll_path.parent() {
                log::debug!("get_config_path: Parent directory: {}", parent.display());

                let mut path = PathBuf::from(parent);
                path.push("fish_11.ini");
                log::info!(
                    "get_config_path: Using config path from current directory: {}",
                    path.display()
                );

                // Check if the path looks valid
                log::debug!("get_config_path: Path exists? {}", path.exists());
                if path.exists() {
                    log::debug!("get_config_path: Path is file? {}", path.is_file());
                    log::debug!("get_config_path: Path is directory? {}", path.is_dir());
                }

                return Ok(path);
            } else {
                log::warn!("get_config_path: Couldn't get parent directory from executable path");
            }
        }
        Err(e) => {
            log::warn!("get_config_path: Failed to get current executable path: {}", e);
        }
    }

    // Final fallback: use system config directory
    if let Some(base_dirs) = BaseDirs::new() {
        let config_dir = base_dirs.config_dir();
        log::debug!("get_config_path: System config directory: {}", config_dir.display());

        let mut path = PathBuf::from(config_dir);
        path.push("fish_11");

        // Create directory if it doesn't exist
        if !path.exists() {
            log::debug!("get_config_path: Creating directory: {}", path.display());
            if let Err(e) = std::fs::create_dir_all(&path) {
                log::error!("get_config_path: Failed to create directory: {}", e);
            }
        }

        path.push("fish_11.ini");
        log::info!(
            "get_config_path: Using config path from system config directory: {}",
            path.display()
        );
        return Ok(path);
    } else {
        log::error!("get_config_path: Couldn't determine base directories");
    }

    log::error!("get_config_path: All methods to determine config path failed");
    Err(FishError::ConfigError("Could not determine config directory".to_string()))
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
pub fn load_config() -> Result<FishConfig> {
    // Set a timeout to prevent hanging
    let start_time = std::time::Instant::now();
    let timeout = std::time::Duration::from_secs(5);

    let mut config = FishConfig::new();
    let config_path = get_config_path()?;

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
        save_config(&config)?;

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
        Ok(_) => {}
        Err(e) => return Err(FishError::ConfigError(format!("Failed to load config: {}", e))),
    };

    // Check if we've timed out after loading ini
    if start_time.elapsed() > timeout {
        return Err(FishError::ConfigError(
            "Configuration loading timed out after ini load".to_string(),
        ));
    }

    // Load [Keys] section
    if let Some(section) = ini.sections().into_iter().find(|s| s == "Keys") {
        for (k, v) in ini.get_map_ref()[&section].iter() {
            if let Some(value) = v {
                config.keys.insert(k.clone(), value.clone());
            }
        }
    }

    // Load [KeyPair] section
    if let Some(private) = ini.get("KeyPair", "private") {
        config.our_private_key = Some(private.to_string());
    }
    if let Some(public) = ini.get("KeyPair", "public") {
        config.our_public_key = Some(public.to_string());
    }

    // Load [NickNetworks] section
    if let Some(section) = ini.sections().into_iter().find(|s| s == "NickNetworks") {
        for (k, v) in ini.get_map_ref()[&section].iter() {
            if let Some(value) = v {
                config.nick_networks.insert(k.clone(), value.clone());
            }
        }
    }

    // Load [FiSH11] section
    if let Some(value) = ini.get("FiSH11", "process_incoming") {
        config.fish11.process_incoming = value.eq_ignore_ascii_case("true") || value == "1";
    }

    if let Some(value) = ini.get("FiSH11", "process_outgoing") {
        config.fish11.process_outgoing = value.eq_ignore_ascii_case("true") || value == "1";
    }

    if let Some(value) = ini.get("FiSH11", "plain_prefix") {
        config.fish11.plain_prefix = value.to_string();
    }

    if let Some(value) = ini.get("FiSH11", "encrypt_notice") {
        config.fish11.encrypt_notice = value.eq_ignore_ascii_case("true") || value == "1";
    }

    if let Some(value) = ini.get("FiSH11", "encrypt_action") {
        config.fish11.encrypt_action = value.eq_ignore_ascii_case("true") || value == "1";
    }

    if let Some(value) = ini.get("FiSH11", "mark_position") {
        if let Ok(pos) = value.parse() {
            config.fish11.mark_position = pos;
        }
    }

    if let Some(value) = ini.get("FiSH11", "mark_encrypted") {
        config.fish11.mark_encrypted = value.to_string();
    }

    if let Some(value) = ini.get("FiSH11", "no_fish10_legacy") {
        config.fish11.no_fish10_legacy = value.eq_ignore_ascii_case("true") || value == "1";
    }

    // Load [Startup] section
    if let Some(value) = ini.get("Startup", "date") {
        if let Ok(date) = value.parse() {
            config.startup_data.date = Some(date);
        }
    } // Load entries from section-based format [nickname@network] and [chan_channel@network] sections
    for section_name in ini.sections() {
        // Skip the standard configuration sections
        if section_name == "Keys"
            || section_name == "KeyPair"
            || section_name == "NickNetworks"
            || section_name == "FiSH11"
            || section_name == "Startup"
            || section_name.starts_with("Entry.")
        {
            continue;
        } // Check if this is a valid entry section (contains @ indicating network format)
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
pub fn save_config(config: &FishConfig) -> Result<()> {
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
    let config_path = get_config_path()?;
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
