// Log Key - Specialized key for encrypting/decrypting log entries

use super::master_key::MasterKey;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key};
use std::sync::{Arc, Mutex};

/// Log Rotation Policy
#[derive(Debug, Clone, Copy)]
pub enum LogRotationPolicy {
    Never,
    Daily,
    Weekly,
    Monthly,
    AfterSize(u64), // in bytes
}

/// Log Key - derived from MasterKey for log encryption
#[derive(Debug, Clone)]
pub struct LogKey {
    key_material: [u8; 32],
    version: u32,
    rotation_policy: LogRotationPolicy,
    current_size: u64,
    last_rotation: u64, // timestamp
}

impl LogKey {
    /// Create a new LogKey from master key
    pub fn new_from_master(master_key: &MasterKey) -> Self {
        let key_material = master_key.derive_subkey("log_encryption");
        Self {
            key_material,
            version: 1,
            rotation_policy: LogRotationPolicy::Never,
            current_size: 0,
            last_rotation: 0,
        }
    }

    /// Encrypt a log entry
    pub fn encrypt_log_entry(&self, log_entry: &str) -> Result<String, String> {
        use chacha20poly1305::Nonce;
        use base64::{Engine as _, engine::general_purpose};
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key_material));
        let nonce = self.generate_nonce();
        let nonce = Nonce::from_slice(&nonce);

        cipher
            .encrypt(nonce, log_entry.as_bytes())
            .map_err(|e| format!("Log encryption failed: {}", e))
            .map(|ciphertext| {
                let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
                result.extend_from_slice(&nonce);
                result.extend_from_slice(&ciphertext);
                general_purpose::STANDARD.encode(&result)
            })
    }

    /// Decrypt a log entry
    pub fn decrypt_log_entry(&self, encrypted_log: &str) -> Result<String, String> {
        use chacha20poly1305::Nonce;
        use base64::{Engine as _, engine::general_purpose};
        let encrypted_bytes =
            general_purpose::STANDARD.decode(encrypted_log).map_err(|e| format!("Base64 decode failed: {}", e))?;

        if encrypted_bytes.len() < 12 {
            return Err("Encrypted log data too short".to_string());
        }

        let nonce_bytes = &encrypted_bytes[..12];
        let nonce = Nonce::from_slice(nonce_bytes);
        let ciphertext = &encrypted_bytes[12..];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key_material));

        cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| format!("Log decryption failed: {}", e))
            .map(|plaintext| String::from_utf8_lossy(&plaintext).into_owned())
    }

    /// Generate a random nonce for encryption
    fn generate_nonce(&self) -> [u8; 12] {
        use rand::RngCore;
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    }

    /// Set rotation policy
    pub fn set_rotation_policy(&mut self, policy: LogRotationPolicy) {
        self.rotation_policy = policy;
    }

    /// Check if rotation is needed
    pub fn needs_rotation(&self) -> bool {
        use std::time::{SystemTime, UNIX_EPOCH};

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

        match self.rotation_policy {
            LogRotationPolicy::Never => false,
            LogRotationPolicy::Daily => {
                // Rotate if more than 24 hours since last rotation
                now - self.last_rotation > 86400
            }
            LogRotationPolicy::Weekly => {
                // Rotate if more than 7 days since last rotation
                now - self.last_rotation > 604800
            }
            LogRotationPolicy::Monthly => {
                // Rotate if more than 30 days since last rotation
                now - self.last_rotation > 2592000
            }
            LogRotationPolicy::AfterSize(size_limit) => self.current_size >= size_limit,
        }
    }

    /// Rotate to a new key version
    pub fn rotate(&mut self, master_key: &MasterKey) {
        self.key_material =
            master_key.derive_subkey(&format!("log_encryption_v{}", self.version + 1));
        self.version += 1;
        self.current_size = 0;

        use std::time::{SystemTime, UNIX_EPOCH};
        self.last_rotation =
            SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
    }

    /// Update current size (for size-based rotation)
    pub fn update_size(&mut self, additional_size: u64) {
        self.current_size += additional_size;
    }

    /// Get current key version
    pub fn version(&self) -> u32 {
        self.version
    }
}

/// Thread-safe wrapper for LogKey
#[derive(Clone)]
pub struct LogKeyGuard {
    inner: Arc<Mutex<LogKey>>,
}

impl LogKeyGuard {
    pub fn new_from_master(master_key: &MasterKey) -> Self {
        Self { inner: Arc::new(Mutex::new(LogKey::new_from_master(master_key))) }
    }

    pub fn encrypt_log_entry(&self, log_entry: &str) -> Result<String, String> {
        if let Ok(guard) = self.inner.lock() {
            guard.encrypt_log_entry(log_entry)
        } else {
            Err("Failed to access log key".to_string())
        }
    }

    pub fn decrypt_log_entry(&self, encrypted_log: &str) -> Result<String, String> {
        if let Ok(guard) = self.inner.lock() {
            guard.decrypt_log_entry(encrypted_log)
        } else {
            Err("Failed to access log key".to_string())
        }
    }

    pub fn set_rotation_policy(&self, policy: LogRotationPolicy) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.set_rotation_policy(policy);
        }
    }

    pub fn needs_rotation(&self) -> bool {
        if let Ok(guard) = self.inner.lock() { guard.needs_rotation() } else { false }
    }

    pub fn rotate(&self, master_key: &MasterKey) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.rotate(master_key);
        }
    }

    pub fn update_size(&self, additional_size: u64) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.update_size(additional_size);
        }
    }

    pub fn version(&self) -> u32 {
        if let Ok(guard) = self.inner.lock() { guard.version() } else { 0 }
    }
}
