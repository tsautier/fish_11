//! Encryption module for master key system
//!
//! Handles encryption and decryption of sensitive data using ChaCha20-Poly1305.

use chacha20poly1305::{
    ChaCha20Poly1305, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit},
};
use rand::rngs::OsRng;
use secrecy::ExposeSecret;

/// Represents an encrypted blob with version, salt, nonce, ciphertext and tag
#[derive(Debug, Clone)]
pub struct EncryptedBlob {
    pub version: u8,
    pub salt: [u8; 32],
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl EncryptedBlob {
    /// Create a new encrypted blob
    pub fn new(salt: [u8; 32], nonce: [u8; 12], ciphertext: Vec<u8>) -> Self {
        Self { version: 1, salt, nonce, ciphertext }
    }

    /// Serialize the encrypted blob to bytes
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::new();
        result.push(self.version);
        result.extend_from_slice(&self.salt);
        result.extend_from_slice(&self.nonce);
        result.extend_from_slice(&self.ciphertext);
        result
    }

    /// Deserialize an encrypted blob from bytes
    pub fn from_bytes(data: &[u8]) -> Option<Self> {
        if data.len() < 45 {
            // 1 + 32 + 12 + min 0
            return None;
        }

        let version = data[0];
        let mut salt = [0u8; 32];
        salt.copy_from_slice(&data[1..33]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&data[33..45]);

        let ciphertext = data[45..].to_vec();

        Some(Self { version, salt, nonce, ciphertext })
    }
}

/// Encrypt data using ChaCha20-Poly1305
///
/// # Arguments
/// * `data` - The plaintext data to encrypt
/// * `key` - The encryption key (32 bytes)
///
/// # Returns
/// * `Result<EncryptedBlob, String>` - The encrypted blob
pub fn encrypt_data(data: &[u8], key: &[u8; 32]) -> Result<EncryptedBlob, String> {
    // Create cipher instance
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));

    // Generate a random nonce
    use rand::RngCore;
    use rand::rngs::OsRng;
    let mut rng = OsRng;
    let nonce = ChaCha20Poly1305::generate_nonce(&mut rng);
    let nonce_bytes: [u8; 12] = nonce.into();

    // Generate a random salt
    let mut salt = [0u8; 32];
    rng.fill_bytes(&mut salt);

    // Encrypt the data
    let ciphertext =
        cipher.encrypt(&nonce, data).map_err(|e| format!("Encryption failed: {}", e))?;

    Ok(EncryptedBlob::new(salt, nonce_bytes, ciphertext))
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

    // Reconstruct the nonce
    let nonce = Nonce::from_slice(&blob.nonce);

    // Decrypt the data
    let plaintext = cipher
        .decrypt(nonce, blob.ciphertext.as_ref())
        .map_err(|e| format!("Decryption failed: {}", e))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let data = b"Hello, World!";
        let key = [1u8; 32]; // Use a fixed key for testing

        let encrypted = encrypt_data(data, &key).expect("Encryption failed");
        let decrypted = decrypt_data(&encrypted, &key).expect("Decryption failed");

        assert_eq!(data, decrypted.as_slice());
    }

    #[test]
    fn test_encrypted_blob_serialization() {
        let original = EncryptedBlob {
            version: 1,
            salt: [1u8; 32],
            nonce: [2u8; 12],
            ciphertext: vec![3u8; 10],
        };

        let bytes = original.to_bytes();
        let restored = EncryptedBlob::from_bytes(&bytes).expect("Deserialization failed");

        assert_eq!(original.version, restored.version);
        assert_eq!(original.salt, restored.salt);
        assert_eq!(original.nonce, restored.nonce);
        assert_eq!(original.ciphertext, restored.ciphertext);
    }
}
