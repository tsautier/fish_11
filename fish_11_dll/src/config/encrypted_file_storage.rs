//! Encrypted file storage operations for configuration
use std::fs;
use std::path::PathBuf;

use configparser::ini::Ini;
//use secrecy::ExposeSecret;
use base64;

use crate::config::models::{EntryData, FishConfig};
use crate::error::{FishError, Result};
//use crate::utils::base64_encode;
use fish_11_core::master_key::{
    EncryptedBlob, decrypt_data, derive_config_kek, derive_master_key, encrypt_data,
};

/// Configuration header for encrypted files
const ENCRYPTED_CONFIG_HEADER: &str = "# FiSH_11_ENCRYPTED_CONFIG_V1";

/// Initialize the encrypted config file if it doesn't exist
pub fn init_encrypted_config_file() -> Result<()> {
    let config_path = get_config_path()?;
    if config_path.exists() {
        return Ok(());
    }

    let mut ini = Ini::new();
    ini.set("FiSH11", "process_incoming", Some("true".to_string()));
    ini.set("FiSH11", "plain_prefix", Some("+p ".to_string()));
    ini.set("FiSH11", "encryption_prefix", Some("+FiSH".to_string()));
    ini.set("FiSH11", "fish_prefix", Some("0".to_string()));

    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)?;
    }
    ini.write(&config_path)?;
    Ok(())
}

/// Check if the config file is encrypted
fn is_encrypted_config(config_path: &PathBuf) -> Result<bool> {
    if !config_path.exists() {
        return Ok(false);
    }

    let content = fs::read_to_string(config_path)
        .map_err(|e| FishError::ConfigError(format!("Failed to read config file: {}", e)))?;

    // Check if the file starts with our encrypted header
    Ok(content.starts_with(ENCRYPTED_CONFIG_HEADER))
}

/// Load the configuration from an encrypted file or regular INI file
pub fn load_encrypted_config(path_override: Option<PathBuf>) -> Result<FishConfig> {
    let config_path = match &path_override {
        Some(path) => path.clone(),
        None => get_config_path()?,
    };

    crate::log_debug!("load_encrypted_config: config path: {}", config_path.display());

    // Check if file exists
    if !config_path.exists() {
        crate::log_info!("load_encrypted_config: config file does not exist, creating default");
        return Ok(FishConfig::new());
    }

    // Check if the file is encrypted
    if is_encrypted_config(&config_path)? {
        crate::log_debug!("load_encrypted_config: detected encrypted config file");
        load_encrypted_config_from_file(&config_path)
    } else {
        crate::log_debug!("load_encrypted_config: detected regular config file");
        // Fall back to regular loading
        crate::config::file_storage::load_config(path_override)
    }
}

/// Load configuration from an encrypted file
fn load_encrypted_config_from_file(config_path: &PathBuf) -> Result<FishConfig> {
    // Read the encrypted file content
    let content = fs::read_to_string(config_path)
        .map_err(|e| FishError::ConfigError(format!("Failed to read encrypted config: {}", e)))?;

    // Parse the header and extract encrypted data
    let lines: Vec<&str> = content.lines().collect();
    if lines.is_empty() || !lines[0].starts_with(ENCRYPTED_CONFIG_HEADER) {
        return Err(FishError::ConfigError("Invalid encrypted config header".to_string()));
    }

    // The actual encrypted data is in the second line
    if lines.len() < 2 {
        return Err(FishError::ConfigError("Encrypted config file is malformed".to_string()));
    }

    let encrypted_data = lines[1];
    let encrypted_bytes = base64::decode(encrypted_data)
        .map_err(|e| FishError::ConfigError(format!("Failed to decode encrypted data: {}", e)))?;
    let encrypted_blob = EncryptedBlob::from_bytes(&encrypted_bytes)
        .ok_or_else(|| FishError::ConfigError("Failed to parse encrypted blob".to_string()))?;

    // Get the master key from memory (this assumes the user has unlocked it)
    // For now, we'll return an error indicating that the config is encrypted but not unlocked
    return Err(FishError::ConfigError(
        "Encrypted config detected but master key not unlocked. Use FiSH11_MasterKeyUnlock first."
            .to_string(),
    ));
}

/// Check if master key is available in memory
pub fn is_master_key_available() -> bool {
    // This will check if the master key is currently held in memory
    // For now we'll return false - we'll implement this when we add the global key handle
    false
}

/// Save configuration to an encrypted file
pub fn save_encrypted_config(config: &FishConfig, path_override: Option<PathBuf>) -> Result<()> {
    let config_path = match path_override {
        Some(path) => path,
        None => get_config_path()?,
    };

    crate::log_debug!("save_encrypted_config: config path: {}", config_path.display());

    // Convert the config to a regular INI format first
    let mut ini = Ini::new();

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
    if let Some(ttl) = config.fish11.key_ttl {
        ini.set("FiSH11", "key_ttl", Some(ttl.to_string()));
    }
    ini.set("FiSH11", "encryption_prefix", Some(config.fish11.encryption_prefix.clone()));
    ini.set("FiSH11", "fish_prefix", Some(config.fish11.fish_prefix.to_string()));

    // Save [Startup] section
    if let Some(date) = config.startup_data.date {
        ini.set("Startup", "date", Some(date.to_string()));
    }

    // Save entries from config.entries to [Keys] and [Dates] sections
    let keys_section = "Keys";
    let dates_section = "Dates";

    for (entry_key, entry_data) in &config.entries {
        if let Some(key_val) = &entry_data.key {
            ini.set(keys_section, entry_key, Some(key_val.clone()));
        }
        if let Some(date_val) = &entry_data.date {
            ini.set(dates_section, entry_key, Some(date_val.clone()));
        }
    }

    // Convert to string
    let ini_string = ini.writes();

    // Check if master key is available for encryption
    if !is_master_key_available() {
        return Err(FishError::ConfigError("Cannot save encrypted config: master key not unlocked. Use FiSH11_MasterKeyUnlock first.".to_string()));
    }

    // For now, we'll return an error indicating that encryption is not yet fully implemented
    // since we need to actually implement the encryption functionality
    Err(FishError::ConfigError(
        "Encryption of config not yet fully implemented - requires master key in memory"
            .to_string(),
    ))
}

/// Get the path to the config file
pub fn get_config_path() -> Result<PathBuf> {
    crate::config::file_storage::get_config_path()
}
