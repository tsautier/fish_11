// Master Key Core - Primary key that protects all other keys

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key};
use sha2::{Digest, Sha256};
use std::sync::{Arc, Mutex};

/// Primary Master Key - protects all other keys in the system
#[derive(Debug, Clone)]
pub struct MasterKey {
    key_material: [u8; 32],
    salt: Vec<u8>,
    is_unlocked: bool,
}

impl MasterKey {
    /// Create a new MasterKey from password and salt
    pub fn new(password: &str, salt: &[u8]) -> Self {
        let mut key_material = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(password.as_bytes());
        hasher.update(salt);
        let hash = hasher.finalize();
        key_material.copy_from_slice(&hash[..32]);

        Self { key_material, salt: salt.to_vec(), is_unlocked: true }
    }

    /// Derive a subkey for specific purpose (config, logs, etc.)
    pub fn derive_subkey(&self, purpose: &str) -> [u8; 32] {
        let mut subkey = [0u8; 32];
        let mut hasher = Sha256::new();
        hasher.update(&self.key_material);
        hasher.update(purpose.as_bytes());
        let hash = hasher.finalize();
        subkey.copy_from_slice(&hash[..32]);
        subkey
    }

    /// Encrypt data using this master key
    pub fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, String> {
        use chacha20poly1305::Nonce;
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key_material));
        let nonce = self.generate_nonce();
        let nonce = Nonce::from_slice(&nonce);

        cipher.encrypt(nonce, data).map_err(|e| format!("Encryption failed: {}", e)).map(
            |ciphertext| {
                let mut result = Vec::with_capacity(nonce.len() + ciphertext.len());
                result.extend_from_slice(&nonce);
                result.extend_from_slice(&ciphertext);
                result
            },
        )
    }

    /// Decrypt data using this master key
    pub fn decrypt(&self, encrypted_data: &[u8]) -> Result<Vec<u8>, String> {
        use chacha20poly1305::Nonce;
        if encrypted_data.len() < 12 {
            return Err("Encrypted data too short".to_string());
        }

        let nonce_bytes = &encrypted_data[..12];
        let nonce = Nonce::from_slice(nonce_bytes);
        let ciphertext = &encrypted_data[12..];
        let cipher = ChaCha20Poly1305::new(Key::from_slice(&self.key_material));

        cipher.decrypt(nonce, ciphertext).map_err(|e| format!("Decryption failed: {}", e))
    }

    /// Generate a random nonce for encryption
    fn generate_nonce(&self) -> [u8; 12] {
        use rand::RngCore;
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce
    }

    /// Lock the master key (clear from memory)
    pub fn lock(&mut self) {
        self.key_material = [0u8; 32];
        self.is_unlocked = false;
    }

    /// Check if master key is unlocked
    pub fn is_unlocked(&self) -> bool {
        self.is_unlocked
    }

    /// Get the salt used for this key
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }
}

/// Thread-safe wrapper for MasterKey
#[derive(Clone)]
pub struct MasterKeyGuard {
    pub inner: Arc<Mutex<MasterKey>>,
}

impl MasterKeyGuard {
    pub fn new(password: &str, salt: &[u8]) -> Self {
        Self { inner: Arc::new(Mutex::new(MasterKey::new(password, salt))) }
    }

    pub fn lock(&self) {
        if let Ok(mut guard) = self.inner.lock() {
            guard.lock();
        }
    }

    pub fn is_unlocked(&self) -> bool {
        if let Ok(guard) = self.inner.lock() { guard.is_unlocked() } else { false }
    }

    pub fn derive_subkey(&self, purpose: &str) -> Result<[u8; 32], String> {
        if let Ok(guard) = self.inner.lock() {
            Ok(guard.derive_subkey(purpose))
        } else {
            Err("Failed to access master key".to_string())
        }
    }
}
