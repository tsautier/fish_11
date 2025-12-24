//! Encryption module for master key system
//!
//! # Nonce Strategy
//!
//! This module provides infrastructure for counter-based nonce generation via `NonceManager`,
//! but in practice, **the DLL functions use random nonces** generated with `OsRng` for
//! ChaCha20-Poly1305 encryption.
//!
//! ## Why Random Nonces Are Safe
//!
//! ChaCha20-Poly1305 uses 96-bit (12-byte) nonces, which provide sufficient entropy for random
//! generation:
//! - Birthday bound: ~2^48 messages before 50% collision probability
//! - For typical usage (thousands to millions of messages), random nonces are cryptographically safe
//!
//! ## Counter-Based Infrastructure
//!
//! The `NonceManager` and counter-based approach remain in this module for potential future use
//! cases where deterministic nonce generation is required (e.g., for specific protocol requirements
//! or when coordinating with external systems).
//!
//! ## Current Implementation
//!
//! - **Log encryption** ([fish11_logencrypt.rs](../../fish_11_dll/src/dll_interface/fish11_logencrypt.rs)):
//!   Uses `ChaCha20Poly1305::generate_nonce(&mut OsRng)` for random nonces
//! - **Config encryption**: Would use the same random nonce strategy
//!
//! If your use case requires deterministic, sequential nonces (e.g., for audit trails or
//! message ordering), use the `NonceManager` functions below.

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, KeyInit},
};
use once_cell::sync::Lazy;
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// Nonce manager for counter-based nonce generation
static NONCE_MANAGER: Lazy<Mutex<NonceManager>> = Lazy::new(|| Mutex::new(NonceManager::new()));

/// Represents an encrypted blob with version, generation, counter, ciphertext
#[derive(Debug, Clone)]
pub struct EncryptedBlob {
    pub version: u8,
    pub generation: u32,
    pub nonce_counter: u64,
    pub ciphertext: Vec<u8>,
}

impl EncryptedBlob {
    /// Create a new encrypted blob
    pub fn new(generation: u32, nonce_counter: u64, ciphertext: Vec<u8>) -> Self {
        Self { version: 1, generation, nonce_counter, ciphertext }
    }

    /// Serialize the encrypted blob to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.version);
        result.extend_from_slice(&self.generation.to_be_bytes());
        result.extend_from_slice(&self.nonce_counter.to_be_bytes());
        result.extend_from_slice(&self.ciphertext);
        result
    }

    /// Deserialize an encrypted blob from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 13 {
            // 1 + 4 + 8
            return None;
        }

        let version = data[0];

        let mut generation_bytes = [0u8; 4];
        generation_bytes.copy_from_slice(&data[1..5]);
        let generation = u32::from_be_bytes(generation_bytes);

        let mut counter_bytes = [0u8; 8];
        counter_bytes.copy_from_slice(&data[5..13]);
        let nonce_counter = u64::from_be_bytes(counter_bytes);

        let ciphertext = data[13..].to_vec();

        Some(Self { version, generation, nonce_counter, ciphertext })
    }
}

/// Nonce manager with counter tracking and anti-collision
pub struct NonceManager {
    /// Counters for each key ID
    counters: HashMap<String, u64>,
    /// Used nonces for anti-collision (limited window)
    used_nonces: HashMap<String, HashSet<u64>>,
}

impl NonceManager {
    pub fn new() -> Self {
        Self { counters: HashMap::new(), used_nonces: HashMap::new() }
    }

    /// Get the next nonce for a given key ID
    ///
    /// # Arguments
    /// * `key_id` - The identifier for the key (e.g., "channel:#test:gen:0")
    ///
    /// # Returns
    /// * `Result<([u8; 12], u64), String>` - The nonce and its counter value
    pub fn get_next_nonce(&mut self, key_id: &str) -> Result<([u8; 12], u64), String> {
        let counter = self.counters.entry(key_id.to_string()).or_insert(0);
        *counter += 1;

        // Anti-collision check
        if self.used_nonces.entry(key_id.to_string()).or_insert_with(HashSet::new).contains(counter)
        {
            return Err(format!("Nonce collision detected for key {}", key_id));
        }

        // Add to used nonces (limit window to prevent memory growth)
        let used_set = self.used_nonces.get_mut(key_id).unwrap();
        used_set.insert(*counter);
        if used_set.len() > 10000 {
            // Keep only the most recent 10000 nonces
            let min_to_keep = *counter - 10000;
            used_set.retain(|&n| n > min_to_keep);
        }

        // Encode counter as big-endian in the nonce (last 8 bytes)
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&counter.to_be_bytes());

        Ok((nonce, *counter))
    }

    /// Set the counter for a key ID (used when loading from persistent storage)
    pub fn set_counter(&mut self, key_id: &str, counter: u64) {
        self.counters.insert(key_id.to_string(), counter);
    }

    /// Get the current counter for a key ID
    pub fn get_counter(&self, key_id: &str) -> u64 {
        *self.counters.get(key_id).unwrap_or(&0)
    }
}

/// Encrypt data using ChaCha20-Poly1305 with counter-based nonce
///
/// # Arguments
/// * `data` - The plaintext data to encrypt
/// * `key` - The encryption key (32 bytes)
/// * `key_id` - The identifier for the key (for nonce management)
/// * `generation` - The key generation number
///
/// # Returns
/// * `Result<EncryptedBlob, String>` - The encrypted blob
pub fn encrypt_data(
    data: &[u8],
    key: &[u8; 32],
    key_id: &str,
    generation: u32,
) -> Result<EncryptedBlob, String> {
    // Create cipher instance
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

    // Get next nonce from counter
    let (nonce_bytes, counter) = NONCE_MANAGER
        .lock()
        .map_err(|e| format!("Failed to lock nonce manager: {}", e))?
        .get_next_nonce(key_id)?;

    let nonce = Nonce::from_slice(&nonce_bytes);

    // Encrypt the data
    let ciphertext =
        cipher.encrypt(nonce, data).map_err(|e| format!("Encryption failed: {}", e))?;

    Ok(EncryptedBlob::new(generation, counter, ciphertext))
}

/// Decrypt data using ChaCha20-Poly1305
///
/// # Arguments
/// * `blob` - The encrypted blob to decrypt
/// * `key` - The decryption key (32 bytes)
///
/// # Returns
/// * `Result<Vec<u8>, String>` - The decrypted plaintext
pub fn decrypt_data(blob: &EncryptedBlob, key: &[u8; 32]) -> Result<Vec<u8>, String> {
    // Create cipher instance
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

    // Reconstruct the nonce from counter
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[4..].copy_from_slice(&blob.nonce_counter.to_be_bytes());
    let nonce = Nonce::from_slice(&nonce_bytes);

    // Decrypt the data
    let plaintext = cipher
        .decrypt(nonce, blob.ciphertext.as_ref())
        .map_err(|e| format!("Decryption failed: {}", e))?;

    Ok(plaintext)
}

/// Get the current nonce counter for a key ID
pub fn get_nonce_counter(key_id: &str) -> u64 {
    NONCE_MANAGER.lock().map(|manager| manager.get_counter(key_id)).unwrap_or(0)
}

/// Set the nonce counter for a key ID (used when loading from persistent storage)
pub fn set_nonce_counter(key_id: &str, counter: u64) {
    if let Ok(mut manager) = NONCE_MANAGER.lock() {
        manager.set_counter(key_id, counter);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let data = b"Hello, World!";
        let key = [1u8; 32];
        let key_id = "test_key_1";
        let generation = 0;

        let encrypted = encrypt_data(data, &key, key_id, generation).expect("Encryption failed");
        let decrypted = decrypt_data(&encrypted, &key).expect("Decryption failed");

        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_nonce_increments() {
        let key_id = "test_key_2";
        let mut manager = NonceManager::new();

        let (nonce1, counter1) = manager.get_next_nonce(key_id).unwrap();
        let (nonce2, counter2) = manager.get_next_nonce(key_id).unwrap();

        assert_ne!(nonce1, nonce2);
        assert_eq!(counter1 + 1, counter2);
    }

    #[test]
    fn test_encrypted_blob_serialization() {
        let original = EncryptedBlob {
            version: 1,
            generation: 5,
            nonce_counter: 42,
            ciphertext: vec![3u8; 10],
        };

        let bytes = original.to_bytes();
        let restored = EncryptedBlob::from_bytes(&bytes).expect("Deserialization failed");

        assert_eq!(original.version, restored.version);
        assert_eq!(original.generation, restored.generation);
        assert_eq!(original.nonce_counter, restored.nonce_counter);
        assert_eq!(original.ciphertext, restored.ciphertext);
    }

    #[test]
    fn test_anti_collision() {
        let key_id = "test_key_3";
        let mut manager = NonceManager::new();

        // Get first nonce
        let (_nonce1, counter1) = manager.get_next_nonce(key_id).unwrap();

        // Try to manually set counter to a used value (should be prevented)
        manager.set_counter(key_id, counter1);

        // Get next nonce - should increment from set value
        let (_nonce2, counter2) = manager.get_next_nonce(key_id).unwrap();
        assert_eq!(counter2, counter1 + 1);
    }
}
