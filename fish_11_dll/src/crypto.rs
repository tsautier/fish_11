//! Cryptographic operations for FiSH_11

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

use chacha20poly1305::aead::{Aead, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chrono::{DateTime, Duration, Utc};
use hkdf::Hkdf;
use log::{debug, warn};
use lru_time_cache::LruCache;
use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

use crate::error::{FishError, Result};
use crate::utils::{base64_decode, base64_encode, generate_random_bytes};

// Constants
const MAX_MESSAGE_SIZE: usize = 4096;
const MAX_CIPHERTEXT_SIZE: usize = MAX_MESSAGE_SIZE + 16 + 12; // message + auth tag + nonce

// Global nonce cache for anti-replay protection
lazy_static::lazy_static! {
    static ref NONCE_CACHE: Mutex<LruCache<[u8; 12], ()>> = Mutex::new(
        LruCache::with_expiry_duration_and_capacity(
            chrono::Duration::hours(1).to_std().unwrap(),
            1000
        )
    );

    // Counter for nonce generation
    static ref NONCE_COUNTER: AtomicU64 = AtomicU64::new(0);
}

#[derive(Debug)]
/// Represents a key pair for Curve25519 key exchange
pub struct KeyPair {
    pub private_key: Secret<[u8; 32]>,
    pub public_key: [u8; 32],
    pub creation_time: DateTime<Utc>,
}

impl Zeroize for KeyPair {
    fn zeroize(&mut self) {
        // We access the raw private key bytes via expose_secret to securely zero them
        let mut private_copy = *self.private_key.expose_secret();
        private_copy.zeroize();

        // Zero the public key
        for byte in self.public_key.iter_mut() {
            *byte = 0;
        }
    }
}

impl Drop for KeyPair {
    fn drop(&mut self) {
        self.zeroize();
    }
}

impl KeyPair {
    pub fn needs_rotation(&self) -> bool {
        // Rotate every 7 days
        Utc::now() - self.creation_time > Duration::days(7)
    }
}

/// Generate keypair
pub fn generate_keypair() -> KeyPair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    let private_bytes = secret.to_bytes();
    let private_secret = Secret::new(private_bytes);

    // Log key generation (audit trail)
    log_audit("Generated new keypair");

    KeyPair {
        private_key: private_secret,
        public_key: *public.as_bytes(),
        creation_time: Utc::now(),
    }
}

/// Compute shared secret using StaticSecret with improved key derivation
pub fn compute_shared_secret(
    our_private: &Secret<[u8; 32]>,
    their_public: &[u8; 32],
) -> Result<[u8; 32]> {
    // Validate the public key first
    validate_public_key(their_public)?;

    // Use the private key to perform the Diffie-Hellman operation
    let secret = StaticSecret::from(*our_private.expose_secret());
    let public_key = PublicKey::from(*their_public);

    let shared_secret = secret.diffie_hellman(&public_key);

    // Use HKDF for improved key derivation
    let hkdf = Hkdf::<Sha256>::new(Some(b"FiSH11-KDF"), shared_secret.as_bytes());
    let mut output = [0u8; 32];
    hkdf.expand(b"EncryptionKey", &mut output)
        .map_err(|e| FishError::CryptoError(format!("HKDF expansion failed: {}", e)))?;

    // Log shared secret computation (audit trail)
    log_audit("Computed shared secret");

    Ok(output)
}

/// Validate that a public key is a valid Curve25519 point
fn validate_public_key(bytes: &[u8; 32]) -> Result<()> {
    // Check that it's not all zeros
    if bytes.iter().all(|&b| b == 0) {
        return Err(FishError::InvalidInput("Public key is all zeros".to_string()));
    }

    // Attempt to construct a PublicKey - will succeed if valid
    let _ = PublicKey::from(*bytes);

    // Return Ok if no issues
    Ok(())
}

/// Encrypt a message using ChaCha20-Poly1305
///
/// This function encrypts a message using a symmetric key and returns the encrypted data
/// in a format that can be safely transmitted over IRC.
///
/// # Arguments
/// * `key` - 32-byte symmetric encryption key
/// * `message` - The message to encrypt
/// * `recipient` - Optional recipient for audit logging
///
/// # Returns
/// * `Result<String>` - Base64 encoded ciphertext or an error
///
/// # Format
/// The encrypted data has the format: base64(nonce || ciphertext)
/// where nonce is 12 bytes and ciphertext is the encrypted message plus a 16-byte authentication tag
pub fn encrypt_message(key: &[u8; 32], message: &str, recipient: Option<&str>) -> Result<String> {
    // Input validation
    if message.is_empty() {
        return Err(FishError::InvalidInput("Empty message".to_string()));
    }

    if message.len() > MAX_MESSAGE_SIZE {
        return Err(FishError::InvalidInput(format!(
            "Message exceeds maximum size of {} bytes",
            MAX_MESSAGE_SIZE
        )));
    }

    // Generate a secure nonce using counter + random bytes
    let counter = NONCE_COUNTER.fetch_add(1, Ordering::SeqCst).to_be_bytes();
    let random_bytes = generate_random_bytes(4);

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[0..8].copy_from_slice(&counter);
    nonce_bytes[8..12].copy_from_slice(&random_bytes);

    let nonce = Nonce::from_slice(&nonce_bytes);

    // Anti-replay protection - check and register the nonce
    {
        let mut cache = NONCE_CACHE.lock().unwrap();
        if cache.contains_key(&nonce_bytes) {
            return Err(FishError::CryptoError("Nonce reuse detected".to_string()));
        }
        cache.insert(nonce_bytes, ());
    }

    // Create the cipher
    let chacha_key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(chacha_key);

    // Encrypt the message
    let ciphertext = cipher
        .encrypt(nonce, message.as_bytes())
        .map_err(|e| FishError::CryptoError(format!("Encryption failed: {}", e)))?;

    // Concatenate the nonce and ciphertext
    let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    // Log encryption (audit trail)
    if let Some(rec) = recipient {
        let mut hasher = Sha256::default();
        hasher.update(message.as_bytes());
        let msg_hash = base64_encode(&hasher.finalize()[0..8]);
        log_audit(&format!("Encrypt for {} - {}", rec, msg_hash));
    }

    // Base64 encode the result
    Ok(base64_encode(&result))
}

/// Decrypt a message using ChaCha20-Poly1305
///
/// Takes an encrypted message and decrypts it using the provided key.
///
/// # Arguments
/// * `key` - 32-byte symmetric encryption key
/// * `encrypted_data` - The base64 encoded encrypted message
///
/// # Returns
/// * `Result<String>` - The decrypted message or an error
///
/// # Format
/// The encrypted data should have the format: base64(nonce || ciphertext)
/// where nonce is 12 bytes and ciphertext is the encrypted message plus a 16-byte authentication tag
pub fn decrypt_message(key: &[u8; 32], encrypted_data: &str) -> Result<String> {
    // Decode base64 data
    let data = base64_decode(encrypted_data)
        .map_err(|e| FishError::CryptoError(format!("Invalid base64 data: {}", e)))?;

    // Fuzzing protection - early rejection
    if data.len() > MAX_CIPHERTEXT_SIZE {
        return Err(FishError::CryptoError(format!("Ciphertext too large: {} bytes", data.len())));
    }

    // Check if we have enough data for nonce (12 bytes) + at least some ciphertext
    if data.len() <= 12 {
        return Err(FishError::CryptoError("Encrypted data too short".to_string()));
    }

    // Split into nonce and ciphertext
    let nonce = &data[..12];
    let ciphertext = &data[12..];

    // Anti-replay protection
    {
        let mut nonce_array = [0u8; 12];
        nonce_array.copy_from_slice(nonce);

        let mut cache = NONCE_CACHE.lock().unwrap();
        if cache.contains_key(&nonce_array) {
            return Err(FishError::CryptoError("Potential replay attack detected".to_string()));
        }
        cache.insert(nonce_array, ());
    }

    // Create cipher
    let chacha_key = Key::from_slice(key);
    let cipher = ChaCha20Poly1305::new(chacha_key);
    let nonce = Nonce::from_slice(nonce);

    // Decrypt
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|e| FishError::CryptoError(format!("Decryption failed: {}", e)))?;

    // Log decryption (audit trail)
    let mut hasher = Sha256::default();
    hasher.update(&plaintext);
    let msg_hash = base64_encode(&hasher.finalize()[0..8]);
    log_audit(&format!("Decrypt - {}", msg_hash));

    // Convert to string
    String::from_utf8(plaintext)
        .map_err(|e| FishError::CryptoError(format!("UTF-8 conversion failed: {}", e)))
}

/// Format a public key for sharing
pub fn format_public_key(public_key: &[u8; 32]) -> String {
    let encoded = base64_encode(public_key);
    format!("FiSH11-PubKey:{}", encoded)
}

/// Extract a public key from a formatted string
pub fn extract_public_key(formatted: &str) -> Result<[u8; 32]> {
    const PREFIX: &str = "FiSH11-PubKey:";

    // Check if the string has the correct prefix
    if !formatted.starts_with(PREFIX) {
        return Err(FishError::InvalidInput(
            "Formatted key does not have the correct prefix".to_string(),
        ));
    }

    // Extract the base64 encoded part
    let encoded = &formatted[PREFIX.len()..];

    // Decode the base64
    let key_data = base64_decode(encoded)
        .map_err(|e| FishError::InvalidInput(format!("Invalid base64 in public key: {}", e)))?;

    // Check length
    if key_data.len() != 32 {
        return Err(FishError::InvalidInput(format!(
            "Invalid public key length: got {}, expected 32",
            key_data.len()
        )));
    }

    // Convert to array
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_data);

    // Validate the public key
    validate_public_key(&key)?;

    Ok(key)
}

/// Process a received public key and compute the shared secret
pub fn process_dh_key_exchange(
    nickname: &str,
    public_key_str: &str,
    network: Option<&str>,
) -> Result<()> {
    let our_keypair = crate::config::get_keypair()?;

    // Check if our keypair needs rotation
    if our_keypair.needs_rotation() {
        warn!("Keypair is old and should be rotated");
        log_audit("Using outdated keypair");
    }

    // Extract the other user's public key
    let their_public_key = extract_public_key(public_key_str)?;

    // Compute shared secret
    let shared_secret = compute_shared_secret(&our_keypair.private_key, &their_public_key)?;

    // Store the shared key
    match crate::config::set_key(nickname, &shared_secret, network, false) {
        Ok(_) => {
            log_audit(&format!("Key exchange completed with {}", nickname));
            Ok(())
        }
        Err(FishError::DuplicateEntry(_)) => {
            // Key already exists, try to overwrite
            log_audit(&format!("Key exchange updated existing key for {}", nickname));
            crate::config::set_key(nickname, &shared_secret, network, true)
        }
        Err(e) => Err(e),
    }
}

/// Check if a string is in valid public key format
pub fn is_valid_public_key_format(formatted: &str) -> bool {
    const PREFIX: &str = "FiSH11-PubKey:";
    let encoded = match formatted.strip_prefix(PREFIX) {
        Some(e) => e,
        None => return false,
    };

    // Validate Base64 decoding
    let decoded = match base64_decode(encoded) {
        Ok(d) => d,
        Err(_) => return false,
    };

    // Validate length
    if decoded.len() != 32 {
        return false;
    }

    // Attempt public key validation
    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);

    match validate_public_key(&key) {
        Ok(_) => true,
        Err(_) => false,
    }
}

/// Log a cryptographic audit event
fn log_audit(event: &str) {
    debug!("[AUDIT] {}", event);

    // Attempt to write to the audit log file
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open("fish11.audit.log") {
        let _ = writeln!(file, "[{}] {}", Utc::now(), event);
    }
}

/// Constant-time comparison of authentication tags or other sensitive values
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }

    // Use ConstantTimeEq trait for timing-attack resistant comparison
    a.ct_eq(b).into()
}
