// Configuration Key - Specialized key for encrypting/decrypting configuration

use super::master_key::MasterKey;
use chacha20poly1305::{ChaCha20Poly1305, Key};
use chacha20poly1305::aead::{Aead, KeyInit};
use std::sync::{Arc, Mutex};

/// Configuration Key - derived from MasterKey for config encryption
#[derive(Debug, Clone)]
pub struct ConfigKey {
    key_material: [u8; 32],
    version: u32,
}

impl ConfigKey {
    /// Create a new ConfigKey from master key
    pub fn new_from_master(master_key: &MasterKey) -> Self {
        let key_material = master_key.derive_subkey("config_encryption");
        Self {
            key_material,
            version: 1,
        }
    }

    /// Encrypt configuration data
    pub fn encrypt_config(&self, config_data: &str) -> Result<String, String> {
        use chacha20poly1305::Nonce;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key_material));
        let nonce = self.generate_nonce();
        let nonce = Nonce::from_slice(&nonce);
        
        cipher.encrypt(nonce, config_data.as_bytes())
            .map_err(|e| format!("Config encryption failed: {}", e))
            .map(|ciphertext| {
                let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
                result.extend_from_slice(&nonce);
                result.extend_from_slice(&ciphertext);
                base64::encode(&result)
            })
    }

    /// Decrypt configuration data
    pub fn decrypt_config(&self, encrypted_config: &str) -> Result<String, String> {
        use chacha20poly1305::Nonce;
        let encrypted_bytes = base64::decode(encrypted_config)
            .map_err(|e| format!("Base64 decode failed: {}", e))?;
        
        if encrypted_bytes.len() < 12 {
            return Err("Encrypted config data too short".to_string());
        }
        
        let nonce_bytes = &encrypted_bytes[..12];
        let nonce = Nonce::from_slice(nonce_bytes);
        let ciphertext = &encrypted_bytes[12..];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key_material));
        
        cipher.decrypt(nonce, ciphertext)
            .map_err(|e| format!("Config decryption failed: {}", e))
            .map(|plaintext| String::from_utf8_lossy(&plaintext).into_owned())
    }

    /// Generate a random nonce for encryption
    fn generate_nonce(&self) -> [u8; 12] {
        use rand::RngCore;
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    }

    /// Get current key version
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Rotate to a new key version
    pub fn rotate(&mut self, master_key: &MasterKey) {
        self.key_material = master_key.derive_subkey(&format!("config_encryption_v{}", self.version + 1));
        self.version += 1;
    }
}

/// Thread-safe wrapper for ConfigKey
#[derive(Clone)]
pub struct ConfigKeyGuard {
    inner: Arc<Mutex<ConfigKey>>,
}

impl ConfigKeyGuard {
    pub fn new_from_master(master_key: &MasterKey) -> Self {
        Self {
            inner: Arc::new(Mutex::new(ConfigKey::new_from_master(master_key))),
        }
    }

    pub fn encrypt_config(&self, config_data: &str) -> Result<String, String> {
        if let Ok(guard) = self.inner.lock() {
            guard.encrypt_config(config_data)
        } else {
            Err("Failed to access config key".to_string())
        }
    }

    pub fn decrypt_config(&self, encrypted_config: &str) -> Result<String, String> {
        if let Ok(guard) = self.inner.lock() {
            guard.decrypt_config(encrypted_config)
        } else {
            Err("Failed to access config key".to_string())
        }
    }

    pub fn rotate(&self, master_key: &MasterKey) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.rotate(master_key);
        }
    }
}

