//! Data models for the configuration system

use std::collections::{HashMap, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

/// Maximum number of previous ratchet keys to retain.
///
/// This window allows decryption of out-of-order messages while maintaining
/// forward secrecy. A window of 5 keys provides tolerance for typical IRC
/// network conditions (reordering, lag) while keeping memory usage minimal.
///
/// Security trade-off: Larger window = better reliability but slower FS.
const MAX_PREVIOUS_KEYS: usize = 5;

/// Maximum number of nonces to cache per channel for replay detection.
///
/// Each nonce is 12 bytes. A cache of 100 nonces provides:
/// - Memory: 1.2 KB per channel
/// - Protection window: ~100 messages (depends on traffic)
///
/// Security trade-off: Larger cache = longer replay protection but more memory.
const MAX_NONCE_CACHE_SIZE: usize = 100;

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

/// Holds the state for a channel's symmetric key ratchet.
#[derive(PartialEq, Debug, Clone)]
pub struct RatchetState {
    pub current_key: [u8; 32],
    pub epoch: u64,
    // A small window of previous keys to handle out-of-order messages
    pub previous_keys: VecDeque<[u8; 32]>,
}

impl RatchetState {
    pub fn new(initial_key: [u8; 32]) -> Self {
        Self {
            current_key: initial_key,
            epoch: 0,
            previous_keys: VecDeque::with_capacity(MAX_PREVIOUS_KEYS),
        }
    }

    pub fn advance(&mut self, next_key: [u8; 32]) {
        use zeroize::Zeroize;

        if self.previous_keys.len() == MAX_PREVIOUS_KEYS {
            // Zeroize the oldest key before dropping it
            if let Some(mut old_key) = self.previous_keys.pop_front() {
                old_key.zeroize();
            }
        }
        self.previous_keys.push_back(self.current_key);
        self.current_key = next_key;
        self.epoch += 1;
    }
}

/// Holds a cache of recently seen nonces to prevent replay attacks.
#[derive(PartialEq, Debug, Clone)]
pub struct NonceCache {
    pub recent_nonces: VecDeque<[u8; 12]>,
}

impl NonceCache {
    pub fn new() -> Self {
        Self { recent_nonces: VecDeque::with_capacity(MAX_NONCE_CACHE_SIZE) }
    }

    pub fn check_and_add(&mut self, nonce: [u8; 12]) -> bool {
        if self.recent_nonces.contains(&nonce) {
            return true; // Nonce is a duplicate
        }
        if self.recent_nonces.len() == MAX_NONCE_CACHE_SIZE {
            self.recent_nonces.pop_front();
        }
        self.recent_nonces.push_back(nonce);
        false // Nonce is new
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
    /// Channel symmetric keys (raw bytes)
    pub channel_keys: HashMap<String, Vec<u8>>,
    /// Channel ratchet states for Forward Secrecy
    pub channel_ratchet_states: HashMap<String, RatchetState>,
    /// Channel nonce caches for anti-replay
    pub channel_nonce_caches: HashMap<String, NonceCache>,
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
            channel_ratchet_states: HashMap::new(),
            channel_nonce_caches: HashMap::new(),
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
