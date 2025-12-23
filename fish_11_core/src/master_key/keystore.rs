//! Keystore module for persistent storage of nonce counters and key metadata
//!
//! Provides persistent storage for nonce counters, key generations, and rotation metadata.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;

/// Metadata about a key's usage and rotation status
#[derive(Debug, Clone)]
pub struct KeyMetadata {
    pub generation: u32,
    pub message_count: u64,
    pub data_size_bytes: u64,
    pub created_at: u64, // Unix timestamp
    pub last_used_at: u64, // Unix timestamp
}

impl KeyMetadata {
    pub fn new(generation: u32) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            generation,
            message_count: 0,
            data_size_bytes: 0,
            created_at: now,
            last_used_at: now,
        }
    }

    /// Update metadata after encryption operation
    pub fn record_usage(&mut self, data_size: usize) {
        self.message_count += 1;
        self.data_size_bytes += data_size as u64;
        self.last_used_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }

    /// Serialize to string (INI format)
    pub fn to_string(&self) -> String {
        format!(
            "generation={},messages={},bytes={},created={},last_used={}",
            self.generation,
            self.message_count,
            self.data_size_bytes,
            self.created_at,
            self.last_used_at
        )
    }

    /// Deserialize from string
    pub fn from_string(s: &str) -> Option<Self> {
        let mut generation = None;
        let mut message_count = None;
        let mut data_size_bytes = None;
        let mut created_at = None;
        let mut last_used_at = None;

        for part in s.split(',') {
            let kv: Vec<&str> = part.split('=').collect();
            if kv.len() != 2 {
                continue;
            }

            match kv[0].trim() {
                "generation" => generation = kv[1].trim().parse().ok(),
                "messages" => message_count = kv[1].trim().parse().ok(),
                "bytes" => data_size_bytes = kv[1].trim().parse().ok(),
                "created" => created_at = kv[1].trim().parse().ok(),
                "last_used" => last_used_at = kv[1].trim().parse().ok(),
                _ => {}
            }
        }

        Some(Self {
            generation: generation?,
            message_count: message_count?,
            data_size_bytes: data_size_bytes?,
            created_at: created_at?,
            last_used_at: last_used_at?,
        })
    }
}

/// Persistent keystore for nonce counters and key metadata
pub struct Keystore {
    nonce_counters_path: PathBuf,
    key_metadata_path: PathBuf,
}

impl Keystore {
    /// Create a new keystore
    ///
    /// # Arguments
    /// * `base_path` - The base directory for keystore files
    pub fn new(base_path: PathBuf) -> Self {
        let mut nonce_counters_path = base_path.clone();
        nonce_counters_path.push("nonce_counters.dat");
        
        let mut key_metadata_path = base_path;
        key_metadata_path.push("key_metadata.dat");

        Self {
            nonce_counters_path,
            key_metadata_path,
        }
    }

    /// Load nonce counters from disk
    pub fn load_nonce_counters(&self) -> Result<HashMap<String, u64>, String> {
        let mut counters = HashMap::new();

        if !self.nonce_counters_path.exists() {
            return Ok(counters);
        }

        let file = File::open(&self.nonce_counters_path)
            .map_err(|e| format!("Failed to open nonce counters file: {}", e))?;

        let reader = BufReader::new(file);
        for line in reader.lines() {
            let line = line.map_err(|e| format!("Failed to read line: {}", e))?;
            let parts: Vec<&str> = line.split('=').collect();
            if parts.len() == 2 {
                let key_id = parts[0].trim();
                if let Ok(counter) = parts[1].trim().parse::<u64>() {
                    counters.insert(key_id.to_string(), counter);
                }
            }
        }

        Ok(counters)
    }

    /// Save nonce counters to disk
    pub fn save_nonce_counters(&self, counters: &HashMap<String, u64>) -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.nonce_counters_path)
            .map_err(|e| format!("Failed to create nonce counters file: {}", e))?;

        for (key_id, counter) in counters {
            writeln!(file, "{}={}", key_id, counter)
                .map_err(|e| format!("Failed to write nonce counter: {}", e))?;
        }

        Ok(())
    }

    /// Load key metadata from disk
    pub fn load_key_metadata(&self) -> Result<HashMap<String, KeyMetadata>, String> {
        let mut metadata_map = HashMap::new();

        if !self.key_metadata_path.exists() {
            return Ok(metadata_map);
        }

        let file = File::open(&self.key_metadata_path)
            .map_err(|e| format!("Failed to open key metadata file: {}", e))?;

        let reader = BufReader::new(file);
        let mut current_key_id = String::new();

        for line in reader.lines() {
            let line = line.map_err(|e| format!("Failed to read line: {}", e))?;
            
            if line.starts_with('[') && line.ends_with(']') {
                // Section header [key_id]
                current_key_id = line[1..line.len() - 1].to_string();
            } else if !current_key_id.is_empty() {
                // Metadata line
                if let Some(metadata) = KeyMetadata::from_string(&line) {
                    metadata_map.insert(current_key_id.clone(), metadata);
                }
            }
        }

        Ok(metadata_map)
    }

    /// Save key metadata to disk
    pub fn save_key_metadata(&self, metadata_map: &HashMap<String, KeyMetadata>) -> Result<(), String> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.key_metadata_path)
            .map_err(|e| format!("Failed to create key metadata file: {}", e))?;

        for (key_id, metadata) in metadata_map {
            writeln!(file, "[{}]", key_id)
                .map_err(|e| format!("Failed to write key ID: {}", e))?;
            writeln!(file, "{}", metadata.to_string())
                .map_err(|e| format!("Failed to write metadata: {}", e))?;
        }

        Ok(())
    }

    /// Save a single nonce counter
    pub fn save_nonce_counter(&self, key_id: &str, counter: u64) -> Result<(), String> {
        let mut counters = self.load_nonce_counters()?;
        counters.insert(key_id.to_string(), counter);
        self.save_nonce_counters(&counters)
    }

    /// Save a single key metadata entry
    pub fn save_key_metadata_entry(&self, key_id: &str, metadata: &KeyMetadata) -> Result<(), String> {
        let mut metadata_map = self.load_key_metadata()?;
        metadata_map.insert(key_id.to_string(), metadata.clone());
        self.save_key_metadata(&metadata_map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_key_metadata_serialization() {
        let metadata = KeyMetadata {
            generation: 5,
            message_count: 100,
            data_size_bytes: 50000,
            created_at: 1700000000,
            last_used_at: 1700001000,
        };

        let serialized = metadata.to_string();
        let deserialized = KeyMetadata::from_string(&serialized).expect("Failed to deserialize");

        assert_eq!(metadata.generation, deserialized.generation);
        assert_eq!(metadata.message_count, deserialized.message_count);
        assert_eq!(metadata.data_size_bytes, deserialized.data_size_bytes);
        assert_eq!(metadata.created_at, deserialized.created_at);
        assert_eq!(metadata.last_used_at, deserialized.last_used_at);
    }

    #[test]
    fn test_keystore_nonce_counters() {
        let temp_dir = env::temp_dir();
        let mut test_path = temp_dir.clone();
        test_path.push("fish11_keystore_test");
        std::fs::create_dir_all(&test_path).ok();

        let keystore = Keystore::new(test_path.clone());

        let mut counters = HashMap::new();
        counters.insert("key1".to_string(), 100);
        counters.insert("key2".to_string(), 200);

        keystore.save_nonce_counters(&counters).expect("Save failed");
        let loaded = keystore.load_nonce_counters().expect("Load failed");

        assert_eq!(loaded.get("key1"), Some(&100));
        assert_eq!(loaded.get("key2"), Some(&200));

        // Cleanup
        std::fs::remove_dir_all(&test_path).ok();
    }
}
