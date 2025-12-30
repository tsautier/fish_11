//! Secure keystore for master key system
//!
//! Handles persistent storage of sensitive data like salts, nonce counters, etc.

use configparser::ini::Ini;
use std::collections::HashMap;
use std::path::PathBuf;
//use secrecy::{Secret, SecretString};
use serde::{Deserialize, Serialize};
//use zeroize::Zeroize;

/// Metadata associated with keys
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyMetadata {
    pub created_at: u64,      // Unix timestamp
    pub last_used: u64,       // Unix timestamp
    pub usage_count: u64,     // Number of times used
    pub message_count: u64,   // Number of messages processed with this key (kept for compatibility)
    pub data_size_bytes: u64, // Total data size (bytes) processed with this key
    pub description: String,  // Description of the key's purpose
    pub is_revoked: bool,     // Whether the key has been revoked
}

impl Default for KeyMetadata {
    fn default() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let now =
            SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs();

        Self {
            created_at: now,
            last_used: now,
            usage_count: 0,
            message_count: 0,
            data_size_bytes: 0,
            description: "New key".to_string(),
            is_revoked: false,
        }
    }
}

impl KeyMetadata {
    /// Create a new KeyMetadata with an initial message count (compat shim)
    pub fn new(initial_message_count: u64) -> Self {
        let mut km = Self::default();
        km.message_count = initial_message_count;
        km
    }
}

/// A secure keystore that manages sensitive data
pub struct Keystore {
    /// Salt used for deriving the master key
    pub master_key_salt: String,

    /// Nonce counters for different contexts
    pub nonce_counters: HashMap<String, u64>,

    /// Metadata for various keys
    pub key_metadata: HashMap<String, KeyMetadata>,

    /// File path where this keystore is persisted
    pub file_path: Option<PathBuf>,
}

impl Keystore {
    /// Create a new keystore with a random salt
    pub fn new() -> Self {
        use rand::RngCore;
        let mut salt_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut salt_bytes);
        let salt = base64::encode(&salt_bytes);

        Self {
            master_key_salt: salt,
            nonce_counters: HashMap::new(),
            key_metadata: HashMap::new(),
            file_path: None,
        }
    }

    /// Create a keystore with a specific salt
    pub fn with_salt(salt: &str) -> Self {
        Self {
            master_key_salt: salt.to_string(),
            nonce_counters: HashMap::new(),
            key_metadata: HashMap::new(),
            file_path: None,
        }
    }

    /// Get or create a nonce counter for a specific context
    pub fn get_nonce(&mut self, context: &str) -> u64 {
        let counter = self.nonce_counters.entry(context.to_string()).or_insert(0);
        *counter += 1;
        *counter - 1 // Return the previous value as the nonce
    }

    /// Increment the usage count for a key
    pub fn increment_key_usage(&mut self, key_id: &str) {
        let metadata =
            self.key_metadata.entry(key_id.to_string()).or_insert_with(KeyMetadata::default);
        metadata.usage_count += 1;

        use std::time::{SystemTime, UNIX_EPOCH};
        metadata.last_used =
            SystemTime::now().duration_since(UNIX_EPOCH).expect("Time went backwards").as_secs();
    }

    /// Mark a key as revoked
    pub fn revoke_key(&mut self, key_id: &str) {
        let metadata =
            self.key_metadata.entry(key_id.to_string()).or_insert_with(KeyMetadata::default);
        metadata.is_revoked = true;
    }

    /// Check if a key is revoked
    pub fn is_key_revoked(&self, key_id: &str) -> bool {
        self.key_metadata.get(key_id).map(|metadata| metadata.is_revoked).unwrap_or(false)
    }

    /// Get the master key salt
    pub fn get_master_salt(&self) -> Option<&str> {
        Some(&self.master_key_salt)
    }

    /// Set the master key salt
    pub fn set_master_salt(&mut self, salt: &str) {
        self.master_key_salt = salt.to_string();
    }

    /// Load keystore from default path
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        let path = Self::default_path()?;
        Self::load_from_file(&path)
    }

    /// Save keystore to default path
    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        let path = Self::default_path()?;
        self.save_to_path(&path)
    }

    /// Load keystore from a file
    pub fn load_from_file(path: &PathBuf) -> Result<Self, Box<dyn std::error::Error>> {
        let mut ini = Ini::new();
        ini.load(path)?;

        let master_key_salt = ini.get("MasterKey", "salt").unwrap_or_default();

        // Load nonce counters
        let mut nonce_counters = HashMap::new();
        if let Some(nonce_section) = ini.get_map_ref().get("NonceCounters") {
            for (key, value_opt) in nonce_section.iter() {
                if let Some(value_str) = value_opt {
                    if let Ok(value) = value_str.parse::<u64>() {
                        nonce_counters.insert(key.clone(), value);
                    }
                }
            }
        }

        // Load key metadata
        let mut key_metadata = HashMap::new();
        if let Some(metadata_section) = ini.get_map_ref().get("KeyMetadata") {
            for (key_id, value_opt) in metadata_section.iter() {
                if let Some(metadata_str) = value_opt {
                    // Parse metadata from string representation
                    // Format: "created_at:last_used:usage_count:message_count:data_size_bytes:description:is_revoked"
                    let parts: Vec<&str> = metadata_str.split(':').collect();
                    if parts.len() >= 7 {
                        if let (
                            Ok(created_at),
                            Ok(last_used),
                            Ok(usage_count),
                            Ok(message_count),
                            Ok(data_size_bytes),
                            Ok(is_revoked),
                        ) = (
                            parts[0].parse::<u64>(),
                            parts[1].parse::<u64>(),
                            parts[2].parse::<u64>(),
                            parts[3].parse::<u64>(),
                            parts[4].parse::<u64>(),
                            parts[6].parse::<bool>(),
                        ) {
                            let description = parts[5..].join(":"); // Join remaining parts for description
                            let metadata = KeyMetadata {
                                created_at,
                                last_used,
                                usage_count,
                                message_count,
                                data_size_bytes,
                                description,
                                is_revoked,
                            };
                            key_metadata.insert(key_id.clone(), metadata);
                        }
                    }
                }
            }
        }

        let mut keystore = Keystore {
            master_key_salt,
            nonce_counters,
            key_metadata,
            file_path: Some(path.clone()),
        };

        Ok(keystore)
    }

    /// Save keystore to a file
    pub fn save_to_file(&self) -> Result<(), Box<dyn std::error::Error>> {
        if let Some(ref path) = self.file_path {
            self.save_to_path(path)
        } else {
            Err("No file path specified for keystore".into())
        }
    }

    /// Save keystore to a specific file path
    pub fn save_to_path(&self, path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let mut ini = Ini::new();

        // Save master key salt
        ini.set("MasterKey", "salt", Some(self.master_key_salt.clone()));

        // Save nonce counters
        for (context, counter) in &self.nonce_counters {
            ini.set("NonceCounters", context, Some(counter.to_string()));
        }

        // Save key metadata
        for (key_id, metadata) in &self.key_metadata {
            let metadata_str = format!(
                "{}:{}:{}:{}:{}:{}:{}",
                metadata.created_at,
                metadata.last_used,
                metadata.usage_count,
                metadata.message_count,
                metadata.data_size_bytes,
                metadata.description,
                metadata.is_revoked
            );
            ini.set("KeyMetadata", key_id, Some(metadata_str));
        }

        ini.write(path)?;
        Ok(())
    }

    /// Get the default keystore path
    pub fn default_path() -> Result<PathBuf, Box<dyn std::error::Error>> {
        // Use the same directory as the config file
        use std::env;

        match env::var("MIRCDIR") {
            Ok(mirc_path) => {
                let mut path = PathBuf::from(mirc_path);
                path.push("fish_11_keystore.ini");
                Ok(path)
            }
            Err(_) => {
                // Fallback to current directory
                let mut path = env::current_dir()?;
                path.push("fish_11_keystore.ini");
                Ok(path)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_keystore_creation() {
        let keystore = Keystore::new();
        assert!(!keystore.master_key_salt.is_empty());
        assert!(keystore.nonce_counters.is_empty());
        assert!(keystore.key_metadata.is_empty());
    }

    #[test]
    fn test_nonce_counter() {
        let mut keystore = Keystore::new();

        let nonce1 = keystore.get_nonce("test_context");
        assert_eq!(nonce1, 0);

        let nonce2 = keystore.get_nonce("test_context");
        assert_eq!(nonce2, 1);

        // Different context should have its own counter
        let nonce3 = keystore.get_nonce("another_context");
        assert_eq!(nonce3, 0);
    }

    #[test]
    fn test_key_metadata() {
        let mut keystore = Keystore::new();

        keystore.increment_key_usage("test_key");
        assert_eq!(keystore.key_metadata.get("test_key").unwrap().usage_count, 1);

        keystore.increment_key_usage("test_key");
        assert_eq!(keystore.key_metadata.get("test_key").unwrap().usage_count, 2);

        keystore.revoke_key("test_key");
        assert!(keystore.is_key_revoked("test_key"));
    }
}
