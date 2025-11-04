//! Data models for the configuration system

use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};

/// Data for an entry (user or channel)
#[derive(Debug, Clone, Default, PartialEq)]
pub struct EntryData {
    pub key: Option<String>,
    pub date: Option<String>,
}

/// Configuration for FiSH11 settings
#[derive(PartialEq, Debug, Clone)]
pub struct Fish11Section {
    pub nickname: String,
    pub process_incoming: bool,
    pub process_outgoing: bool,
    pub plain_prefix: String,
    pub encrypt_notice: bool,
    pub encrypt_action: bool,
    pub mark_position: u8,
    pub mark_encrypted: String,
    pub no_fish10_legacy: bool,
}

impl Default for Fish11Section {
    fn default() -> Self {
        Self {
            nickname: String::new(),
            process_incoming: true,
            process_outgoing: true,
            plain_prefix: "+p ".to_string(),
            encrypt_notice: false,
            encrypt_action: false,
            mark_position: 1,
            mark_encrypted: " 12$chr(183)".to_string(),
            no_fish10_legacy: false,
        }
    }
}

/// Startup data section
#[derive(PartialEq, Debug, Clone)]
pub struct StartupSection {
    pub date: Option<u64>,
}

impl Default for StartupSection {
    fn default() -> Self {
        Self { date: None }
    }
}

/// Main configuration struct
#[derive(PartialEq, Debug, Clone)]
pub struct FishConfig {
    /// Legacy keys
    pub keys: HashMap<String, String>,
    /// Network mapping for keys
    pub nick_networks: HashMap<String, String>,
    /// Our private key
    pub our_private_key: Option<String>,
    /// Our public key
    pub our_public_key: Option<String>,
    /// Keypair creation time
    pub keypair_creation_time: Option<String>,
    /// FiSH11 settings
    pub fish11: Fish11Section,
    /// Startup data
    pub startup_data: StartupSection,
    /// Entries for channels and users
    pub entries: HashMap<String, EntryData>,
    /// Channel symmetric keys
    pub channel_keys: HashMap<String, String>,
}

impl FishConfig {
    /// Create a new configuration with default values
    pub fn new() -> Self {
        let mut startup_data = StartupSection::default();
        startup_data.date =
            Some(SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs());
        Self {
            keys: HashMap::new(),
            nick_networks: HashMap::new(),
            our_private_key: None,
            our_public_key: None,
            keypair_creation_time: None,
            fish11: Fish11Section::default(),
            startup_data,
            entries: HashMap::new(),
            channel_keys: HashMap::new(),
        }
    }

    /// Get an entry from the configuration (convenience method)
    pub fn get_entry(&self, key: &str) -> Option<&EntryData> {
        self.entries.get(key)
    }

    /// Set an entry in the configuration (convenience method)
    pub fn set_entry(&mut self, key: String, entry: EntryData) {
        self.entries.insert(key, entry);
    }

    /// Get all entries with a specific prefix
    pub fn get_entries_with_prefix(&self, prefix: &str) -> Vec<(String, &EntryData)> {
        self.entries
            .iter()
            .filter(|(key, _)| key.starts_with(prefix))
            .map(|(key, data)| (key.clone(), data))
            .collect()
    }
}
