//! Encrypted file storage operations for configuration
use crate::config::models::{EntryData, FishConfig};
use crate::dll_interface::fish11_masterkey::is_master_key_unlocked;
use crate::error::{FishError, Result};
use crate::log_debug;
use base64::{Engine as _, engine::general_purpose};
use fish_11_core::master_key::{
    EncryptedBlob, decrypt_data, derive_config_kek, encrypt_data,
};
use ini::Ini;
use std::fs;
use std::io::Cursor;
use std::path::PathBuf;

/// Configuration header for encrypted files
const ENCRYPTED_CONFIG_HEADER: &str = "# FiSH_11_ENCRYPTED_CONFIG_V1";

/// Initialize the encrypted config file if it doesn't exist
pub fn init_encrypted_config_file() -> Result<()> {
    let config_path = get_config_path()?;
    if config_path.exists() {
        return Ok(());
    }

    let mut ini = Ini::new();

    ini.with_section(Some("FiSH11"))
        .set("process_incoming", "true")
        .set("plain_prefix", "+p ")
        .set("encryption_prefix", "+FiSH")
        .set("fish_prefix", "0");

    if let Some(parent) = config_path.parent() {
        fs::create_dir_all(parent)?;
    }

    ini.write_to_file(&config_path)?;

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

    #[cfg(debug_assertions)]
    log_debug!("load_encrypted_config: config path: {}", config_path.display());

    // Check if file exists
    if !config_path.exists() {
        crate::log_info!("load_encrypted_config: config file does not exist, creating default");
        return Ok(FishConfig::new());
    }

    // Check if the file is encrypted
    if is_encrypted_config(&config_path)? {
        #[cfg(debug_assertions)]
        log_debug!("load_encrypted_config: detected encrypted config file");

        load_encrypted_config_from_file(&config_path)
    } else {
        log_debug!("load_encrypted_config: detected regular config file");

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

    let encrypted_bytes = general_purpose::STANDARD
        .decode(encrypted_data)
        .map_err(|e| FishError::ConfigError(format!("Failed to decode encrypted data: {}", e)))?;

    let encrypted_blob = EncryptedBlob::from_bytes(&encrypted_bytes)
        .ok_or_else(|| FishError::ConfigError("Failed to parse encrypted blob".to_string()))?;

    // Check if master key is available for decryption
    if !is_master_key_available() {
        return Err(FishError::ConfigError(
            "Encrypted config detected but master key not unlocked. Use FiSH11_MasterKeyUnlock first."
                .to_string(),
        ));
    }

    // Get the master key from memory
    let master_key = crate::dll_interface::fish11_masterkey::get_master_key_from_memory()
        .ok_or_else(|| FishError::ConfigError("Master key not available in memory".to_string()))?;

    // Create the config KEK (Key Encryption Key) using the master key
    let config_kek = derive_config_kek(&master_key);

    // Decrypt the encrypted blob using the config KEK
    let decrypted_bytes = decrypt_data(&encrypted_blob, &config_kek)
        .map_err(|e| FishError::ConfigError(format!("Failed to decrypt config: {}", e)))?;

    // Convert decrypted bytes to string
    let decrypted_content = String::from_utf8(decrypted_bytes).map_err(|e| {
        FishError::ConfigError(format!("Failed to convert decrypted data to string: {}", e))
    })?;

    // Parse the decrypted content as INI
    let mut ini = Ini::new();
    let ini = Ini::load_from_str(&decrypted_content).map_err(|e| {
        FishError::ConfigError(format!("Failed to parse decrypted INI content: {}", e))
    })?;

    // Create a new config object and populate it from the INI data
    let mut config = FishConfig::new();

    // Load [KeyPair] section
    if let Some(private) = ini.get_from(Some("KeyPair"), "private") {
        config.our_private_key = Some(private.to_string());
    }
    if let Some(public) = ini.get_from(Some("KeyPair"), "public") {
        config.our_public_key = Some(public.to_string());
    }

    // Load [NickNetworks] section
    let nick_section = "NickNetworks";
    if let Some(section) = ini.section(Some(nick_section)) {
        for (k, v) in section.iter() {
            config.nick_networks.insert(k.to_string(), v.to_string());
        }
    }

    // Load [FiSH11] section
    if let Some(process_incoming) = ini.get_from(Some("FiSH11"), "process_incoming") {
        config.fish11.process_incoming =
            process_incoming.eq_ignore_ascii_case("true") || process_incoming == "1";
    }
    if let Some(process_outgoing) = ini.get_from(Some("FiSH11"), "process_outgoing") {
        config.fish11.process_outgoing =
            process_outgoing.eq_ignore_ascii_case("true") || process_outgoing == "1";
    }
    if let Some(plain_prefix) = ini.get_from(Some("FiSH11"), "plain_prefix") {
        config.fish11.plain_prefix = plain_prefix.to_string();
    }
    if let Some(encrypt_notice) = ini.get_from(Some("FiSH11"), "encrypt_notice") {
        config.fish11.encrypt_notice =
            encrypt_notice.eq_ignore_ascii_case("true") || encrypt_notice == "1";
    }
    if let Some(encrypt_action) = ini.get_from(Some("FiSH11"), "encrypt_action") {
        config.fish11.encrypt_action =
            encrypt_action.eq_ignore_ascii_case("true") || encrypt_action == "1";
    }
    if let Some(mark_position) = ini.get_from(Some("FiSH11"), "mark_position") {
        if let Ok(pos) = mark_position.parse() {
            config.fish11.mark_position = pos;
        }
    }
    if let Some(mark_encrypted) = ini.get_from(Some("FiSH11"), "mark_encrypted") {
        config.fish11.mark_encrypted = mark_encrypted.to_string();
    }
    if let Some(no_fish10_legacy) = ini.get_from(Some("FiSH11"), "no_fish10_legacy") {
        config.fish11.no_fish10_legacy =
            no_fish10_legacy.eq_ignore_ascii_case("true") || no_fish10_legacy == "1";
    }
    if let Some(key_ttl) = ini.get_from(Some("FiSH11"), "key_ttl") {
        if let Ok(ttl) = key_ttl.parse() {
            config.fish11.key_ttl = Some(ttl);
        }
    }
    if let Some(encryption_prefix) = ini.get_from(Some("FiSH11"), "encryption_prefix") {
        config.fish11.encryption_prefix = encryption_prefix.to_string();
    }
    if let Some(fish_prefix) = ini.get_from(Some("FiSH11"), "fish_prefix") {
        config.fish11.fish_prefix = fish_prefix.eq_ignore_ascii_case("true") || fish_prefix == "1";
    }

    // Load [Startup] section
    if let Some(date) = ini.get_from(Some("Startup"), "date") {
        if let Ok(d) = date.parse() {
            config.startup_data.date = Some(d);
        }
    }

    // Load entries from [Keys] and [Dates] sections
    let keys_section = "Keys";
    let dates_section = "Dates";

    // Get the keys section if it exists
    if let Some(keys_section_data) = ini.section(Some(keys_section)) {
        // Get dates section if it exists, for efficient lookup
        let dates_section_data = ini.section(Some(dates_section));

        for (entry_key, key_val) in keys_section_data.iter() {
            // Look for corresponding date in dates section
            let date_val =
                dates_section_data.and_then(|dates| dates.get(entry_key).map(|s| s.to_string()));

            let entry_data = EntryData {
                key: Some(key_val.to_string()),
                date: date_val,
                is_exchange: Some(false), // Default to false for loaded keys
            };
            config.entries.insert(entry_key.to_string(), entry_data);
        }
    }

    Ok(config)
}

/// Check if master key is available in memory
pub fn is_master_key_available() -> bool {
    // Check if the master key is currently held in memory
    is_master_key_unlocked()
}

/// Save configuration to an encrypted file
pub fn save_encrypted_config(config: &FishConfig, path_override: Option<PathBuf>) -> Result<()> {
    let config_path = match path_override {
        Some(path) => path,
        None => get_config_path()?,
    };

    #[cfg(debug_assertions)]
    log_debug!("save_encrypted_config: config path: {}", config_path.display());

    // Convert the config to a regular INI format first
    let mut ini = Ini::new();

    // Save [KeyPair] section
    if let Some(private) = &config.our_private_key {
        ini.with_section(Some("KeyPair")).set("private", private);
    }
    if let Some(public) = &config.our_public_key {
        ini.with_section(Some("KeyPair")).set("public", public);
    }

    // Save [NickNetworks] section
    let nick_section = "NickNetworks";
    for (k, v) in &config.nick_networks {
        ini.with_section(Some(nick_section)).set(k, v);
    }

    // Save [FiSH11] section
    ini.with_section(Some("FiSH11"))
        .set("process_incoming", config.fish11.process_incoming.to_string())
        .set("process_outgoing", config.fish11.process_outgoing.to_string())
        .set("plain_prefix", config.fish11.plain_prefix.clone())
        .set("encrypt_notice", config.fish11.encrypt_notice.to_string())
        .set("encrypt_action", config.fish11.encrypt_action.to_string())
        .set("mark_position", config.fish11.mark_position.to_string())
        .set("mark_encrypted", config.fish11.mark_encrypted.clone())
        .set("no_fish10_legacy", config.fish11.no_fish10_legacy.to_string());

    if let Some(ttl) = config.fish11.key_ttl {
        ini.with_section(Some("FiSH11")).set("key_ttl", ttl.to_string());
    }

    ini.with_section(Some("FiSH11"))
        .set("encryption_prefix", config.fish11.encryption_prefix.clone())
        .set("fish_prefix", config.fish11.fish_prefix.to_string());

    // Save [Startup] section
    if let Some(date) = config.startup_data.date {
        ini.with_section(Some("Startup")).set("date", date.to_string());
    }

    // Save entries from config.entries to [Keys] and [Dates] sections
    let keys_section = "Keys";
    let dates_section = "Dates";

    for (entry_key, entry_data) in &config.entries {
        if let Some(key_val) = &entry_data.key {
            ini.with_section(Some(keys_section)).set(entry_key, key_val);
        }
        if let Some(date_val) = &entry_data.date {
            ini.with_section(Some(dates_section)).set(entry_key, date_val);
        }
    }

    // Convert to string

    let mut buffer = Cursor::new(Vec::new());
    ini.write_to(&mut buffer)?;
    let ini_string = String::from_utf8(buffer.into_inner())
        .map_err(|e| FishError::ConfigError(format!("Failed to convert INI to string: {}", e)))?;

    // Check if master key is available for encryption
    if !is_master_key_available() {
        return Err(FishError::ConfigError("Cannot save encrypted config: master key not unlocked. Use FiSH11_MasterKeyUnlock first.".to_string()));
    }

    // Get the master key from memory
    let master_key = crate::dll_interface::fish11_masterkey::get_master_key_from_memory()
        .ok_or_else(|| FishError::ConfigError("Master key not available in memory".to_string()))?;

    // Create the config KEK (Key Encryption Key) using the master key
    let config_kek = derive_config_kek(&master_key);

    // Encrypt the INI string using the config KEK
    // Using a fixed key_id for config encryption and generation 0 for now
    let encrypted_blob = encrypt_data(ini_string.as_bytes(), &config_kek, "config", 0)
        .map_err(|e| FishError::ConfigError(format!("Encryption failed: {}", e)))?;

    // Convert the encrypted blob to bytes and encode as base64
    let encrypted_bytes = encrypted_blob.to_bytes();
    let encrypted_b64 = general_purpose::STANDARD.encode(&encrypted_bytes);

    // Prepare the content to write: header + encrypted data
    let content = format!("{}\n{}\n", ENCRYPTED_CONFIG_HEADER, encrypted_b64);

    // Create parent directories if they don't exist
    if let Some(parent) = config_path.parent() {
        if !parent.exists() {
            std::fs::create_dir_all(parent)?;
        }
    }

    // Write the encrypted content to the file
    std::fs::write(&config_path, content)
        .map_err(|e| FishError::ConfigError(format!("Failed to write encrypted config: {}", e)))?;

    Ok(())
}

/// Get the path to the config file
pub fn get_config_path() -> Result<PathBuf> {
    crate::config::file_storage::get_config_path()
}
