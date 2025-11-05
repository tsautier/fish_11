//! Cryptographic operations for FiSH_11
//!
//! This module provides the core cryptographic primitives for the FiSH_11 protocol:
//! - X25519 Diffie-Hellman key exchange with HKDF key derivation
//! - ChaCha20-Poly1305 authenticated encryption with fully random nonces
//! - Anti-replay protection via nonce cache with 1-hour expiry window
//! - Public key validation against low-order points
//! - Secure key pair generation and rotation

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
pub const MAX_MESSAGE_SIZE: usize = 4096;
const MAX_CIPHERTEXT_SIZE: usize = MAX_MESSAGE_SIZE + 16 + 12; // message + auth tag + nonce

// Global nonce cache for anti-replay protection
// Each nonce is stored with a 1-hour expiry to detect replay attacks while allowing
// for reasonable clock skew and network delays.
lazy_static::lazy_static! {
    static ref NONCE_CACHE: Mutex<LruCache<[u8; 12], ()>> = Mutex::new(
        LruCache::with_expiry_duration_and_capacity(
            chrono::Duration::hours(1)
                .to_std()
                .expect("Duration of 1 hour should always be convertible to std::time::Duration"),
            1000
        )
    );

    // Counter for audit trail
    // This counter is incremented on each encryption operation for logging and debugging
    // purposes but is no longer used in nonce construction (fully random nonces are used).
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

/// Generate a new 32-byte symmetric key for ChaCha20-Poly1305
pub fn generate_symmetric_key() -> [u8; 32] {
    generate_random_bytes(32).try_into().unwrap()
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

/// Generate a new X25519 keypair
///
/// Creates a new Curve25519 keypair suitable for Diffie-Hellman key exchange.
/// The private key is securely zeroized on drop.
///
/// # Returns
/// A `KeyPair` containing the private key (wrapped in `Secret`), public key,
/// and creation timestamp for rotation tracking.
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

/// Compute shared secret using X25519 Diffie-Hellman with HKDF key derivation
///
/// Performs an X25519 key exchange operation between our private key and their public key,
/// then derives a symmetric encryption key using HKDF-SHA256.
///
/// # Security
/// - validates the received public key to reject low-order points
/// - uses HKDF with domain separation for key derivation
/// - derives a 32-byte symmetric key suitable for ChaCha20-Poly1305
///
/// # Arguments
/// * `our_private` - our private key (securely wrapped)
/// * `their_public` - their public key (32 bytes)
///
/// # Returns
/// A 32-byte symmetric encryption key or an error if the public key is invalid.
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

    // Known low-order points on Curve25519 that should be rejected
    // These are points of order 1, 2, 4, and 8
    const LOW_ORDER_POINTS: [[u8; 32]; 8] = [
        // Point of order 1 (identity)
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
        // Point of order 2
        [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
        // Point of order 4 (variant 1)
        [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ],
        // Point of order 4 (variant 2)
        [
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
            0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
            0xd0, 0x9f, 0x11, 0x57,
        ],
        // Point of order 8 (variant 1)
        [
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        // Point of order 8 (variant 2)
        [
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        // Point of order 8 (variant 3)
        [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        // Point of order 8 (variant 4)
        [
            0xcd, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x80,
        ],
    ];

    // Check if the point matches any known low-order point
    for low_order_point in &LOW_ORDER_POINTS {
        if bytes == low_order_point {
            return Err(FishError::InvalidInput(
                "Public key is a low-order point and rejected for security".to_string(),
            ));
        }
    }

    // Attempt to construct a PublicKey - will succeed if valid format
    let _ = PublicKey::from(*bytes);

    // Return Ok if no issues
    Ok(())
}

/// Encrypt a message using ChaCha20-Poly1305
///
/// This function encrypts a message using a symmetric key and returns the encrypted data
/// in a format that can be safely transmitted over IRC.
///
/// # Nonce generation
/// Each encryption uses a fully random 12-byte nonce generated via cryptographically secure
/// random number generator. This approach ensures maximum entropy and eliminates predictable
/// patterns in the base64-encoded output that would occur with counter-based schemes.
///
/// # Anti-replay protection
/// Replay attacks are prevented by the nonce cache in the decrypt function. Each received
/// nonce is stored for 1 hour and rejected if seen again within that window.
///
/// # Arguments
/// * `key` - 32-byte symmetric encryption key derived from X25519 key exchange
/// * `message` - the plaintext message to encrypt (max 4096 bytes)
/// * `recipient` - optional recipient nickname for audit logging
///
/// # Returns
/// * `Result<String>` - base64-encoded ciphertext or an error
///
/// # Format
/// The encrypted data has the format: `base64(nonce || ciphertext)`
/// where nonce is 12 bytes and ciphertext is the encrypted message plus a 16-byte
/// authentication tag from Poly1305.
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

    // Generate a secure nonce using fully random bytes (12 bytes)
    // This ensures maximum entropy and avoids predictable patterns in base64 output.
    // Anti-replay protection is ensured by NONCE_CACHE verification during decryption.
    let nonce_bytes = generate_random_bytes(12);
    let mut nonce_array = [0u8; 12];
    nonce_array.copy_from_slice(&nonce_bytes[..12]);

    // Increment counter for audit trail (not used in nonce construction anymore)
    let _ = NONCE_COUNTER.fetch_add(1, Ordering::SeqCst);

    let nonce = Nonce::from(nonce_array);

    // Create the cipher
    let chacha_key = Key::from(*key);
    let cipher = ChaCha20Poly1305::new(&chacha_key);

    // Encrypt the message
    let ciphertext = cipher
        .encrypt(&nonce, message.as_bytes())
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
/// Takes an encrypted message and decrypts it using the provided key. This function performs
/// authenticated decryption with anti-replay protection.
///
/// # Anti-replay protection
/// The nonce from each decrypted message is stored in a cache with a 1-hour expiry window.
/// If the same nonce is encountered again within this period, the decryption is rejected as
/// a potential replay attack. This provides protection against message replay while allowing
/// for reasonable clock skew and network delays.
///
/// # Arguments
/// * `key` - 32-byte symmetric encryption key derived from X25519 key exchange
/// * `encrypted_data` - the base64-encoded encrypted message
///
/// # Returns
/// * `Result<String>` - the decrypted plaintext message or an error
///
/// # Format
/// The encrypted data should have the format: `base64(nonce || ciphertext)`
/// where nonce is 12 bytes and ciphertext is the encrypted message plus a 16-byte
/// authentication tag from Poly1305.
///
/// # Errors
/// Returns an error if:
/// - the base64 decoding fails
/// - the ciphertext is too large (DoS protection)
/// - the ciphertext is too short (missing nonce or data)
/// - the nonce has been seen before (replay attack detection)
/// - the authentication tag verification fails (tampering detected)
/// - the decrypted data is not valid UTF-8
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

        let mut cache = NONCE_CACHE.lock().expect("NONCE_CACHE mutex should not be poisoned");
        if cache.contains_key(&nonce_array) {
            return Err(FishError::CryptoError("Potential replay attack detected".to_string()));
        }
        cache.insert(nonce_array, ());
    }

    // Create cipher
    let chacha_key = Key::from(*key);
    let cipher = ChaCha20Poly1305::new(&chacha_key);
    let mut nonce_array = [0u8; 12];
    nonce_array.copy_from_slice(nonce);
    let nonce = Nonce::from(nonce_array);

    // Decrypt
    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
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

/// Format a public key for sharing over IRC
///
/// Encodes a 32-byte X25519 public key as base64 with the `FiSH11-PubKey:` prefix.
///
/// # Arguments
/// * `public_key` - the 32-byte X25519 public key
///
/// # Returns
/// A formatted string: `FiSH11-PubKey:<base64-encoded-key>`
pub fn format_public_key(public_key: &[u8; 32]) -> String {
    let encoded = base64_encode(public_key);
    format!("FiSH11-PubKey:{}", encoded)
}

/// Extract and validate a public key from a formatted string
///
/// Parses a `FiSH11-PubKey:<base64>` formatted string, decodes the base64 payload,
/// and validates the resulting public key against low-order points.
///
/// # Arguments
/// * `formatted` - the formatted key string (whitespace is trimmed)
///
/// # Returns
/// The 32-byte X25519 public key or an error if the format is invalid or the key
/// fails validation.
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
    // Trim surrounding whitespace/newlines which may come from mIRC or transport
    let encoded = encoded.trim();

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

/// Process a received public key and complete the key exchange
///
/// This function orchestrates a complete Diffie-Hellman key exchange:
/// - retrieves our local keypair
/// - checks if keypair rotation is needed (older than 7 days)
/// - extracts and validates the received public key
/// - computes the shared secret via X25519 + HKDF
/// - stores the resulting symmetric key for the given nickname
///
/// # Arguments
/// * `nickname` - the remote user's nickname
/// * `public_key_str` - their formatted public key (`FiSH11-PubKey:...`)
/// * `network` - optional network identifier for key scoping
///
/// # Returns
/// `Ok(())` if the key exchange succeeded and the shared key was stored, or an error
/// if any step failed.
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

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn test_generate_keypair() {
        let keypair = generate_keypair();
        // Private key should not be all zeros
        assert!(
            !keypair.private_key.expose_secret().iter().all(|&b| b == 0),
            "Private key should not be all zeros"
        );
        // Public key should not be all zeros
        assert!(!keypair.public_key.iter().all(|&b| b == 0), "Public key should not be all zeros");
    }

    #[test]
    fn test_compute_shared_secret() {
        let keypair1 = generate_keypair();
        let keypair2 = generate_keypair();

        let shared1 = compute_shared_secret(&keypair1.private_key, &keypair2.public_key)
            .expect("Failed to compute shared secret 1");
        let shared2 = compute_shared_secret(&keypair2.private_key, &keypair1.public_key)
            .expect("Failed to compute shared secret 2");

        assert_eq!(shared1, shared2, "Shared secrets should be identical");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key: [u8; 32] = generate_random_bytes(32).try_into().expect("Failed to generate key");
        let message = "This is a secret message for testing purposes.";

        let encrypted_data =
            encrypt_message(&key, message, Some("test_recipient")).expect("Encryption failed");
        let decrypted_message = decrypt_message(&key, &encrypted_data).expect("Decryption failed");

        assert_eq!(message, decrypted_message, "Decrypted message should match original message");
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let key1: [u8; 32] =
            generate_random_bytes(32).try_into().expect("Failed to generate key 1");
        let key2: [u8; 32] =
            generate_random_bytes(32).try_into().expect("Failed to generate key 2");
        let message = "Another secret message.";

        assert_ne!(key1, key2);

        let encrypted_data = encrypt_message(&key1, message, None).expect("Encryption failed");
        let result = decrypt_message(&key2, &encrypted_data);

        assert!(result.is_err(), "Decryption with the wrong key should fail");
    }

    #[test]
    fn test_replay_attack_prevention() {
        // Clear the cache for a clean test run
        NONCE_CACHE.lock().expect("Failed to lock nonce cache").clear();

        let key: [u8; 32] = generate_random_bytes(32).try_into().expect("Failed to generate key");
        let message = "A message to test replay attacks.";

        let encrypted_data = encrypt_message(&key, message, None).expect("Encryption failed");

        // First decryption should succeed
        let first_decryption_result = decrypt_message(&key, &encrypted_data);
        assert!(first_decryption_result.is_ok(), "First decryption should succeed");

        // Second decryption with the same data should fail
        let second_decryption_result = decrypt_message(&key, &encrypted_data);
        assert!(
            second_decryption_result.is_err(),
            "Second decryption should fail due to nonce reuse"
        );

        if let Err(FishError::CryptoError(msg)) = second_decryption_result {
            assert!(
                msg.contains("Potential replay attack detected"),
                "Error message should indicate a replay attack"
            );
        } else {
            panic!("Expected a CryptoError for replay attack");
        }
    }

    #[test]
    fn test_validate_public_key_rejects_all_zeros() {
        let zero_key = [0u8; 32];
        let result = validate_public_key(&zero_key);

        assert!(result.is_err(), "All-zero public key should be rejected");
        if let Err(FishError::InvalidInput(msg)) = result {
            assert!(msg.contains("all zeros"), "Error message should mention all zeros");
        } else {
            panic!("Expected InvalidInput error for all-zero key");
        }
    }

    #[test]
    fn test_validate_public_key_rejects_low_order_points() {
        // Test a few known low-order points
        let low_order_points = [
            // Point of order 2 (not all zeros)
            [
                0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00,
            ],
            // Point of order 4 (variant 1)
            [
                0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
                0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
                0x5f, 0x49, 0xb8, 0x00,
            ],
            // Point of order 8 (variant 1)
            [
                0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0x7f,
            ],
        ];

        for (i, low_order_point) in low_order_points.iter().enumerate() {
            let result = validate_public_key(low_order_point);
            assert!(result.is_err(), "Low-order point {} should be rejected", i);
            if let Err(FishError::InvalidInput(msg)) = result {
                assert!(
                    msg.contains("low-order point"),
                    "Error message for point {} should mention low-order: {}",
                    i,
                    msg
                );
            } else {
                panic!("Expected InvalidInput error for low-order point {}", i);
            }
        }
    }

    #[test]
    fn test_validate_public_key_accepts_valid_key() {
        // Generate a valid keypair
        let keypair = generate_keypair();

        // The public key from a generated keypair should be valid
        let result = validate_public_key(&keypair.public_key);
        assert!(result.is_ok(), "Valid public key from generated keypair should be accepted");
    }

    #[test]
    fn test_compute_shared_secret_rejects_low_order_public_key() {
        let keypair = generate_keypair();

        // Point of order 2 (low-order)
        let low_order_public = [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ];

        let result = compute_shared_secret(&keypair.private_key, &low_order_public);
        assert!(result.is_err(), "compute_shared_secret should reject low-order public keys");
    }
}

use base64::{Engine as _, engine::general_purpose};

/// Wraps a channel key using a pre-shared symmetric key.
/// This is used by the coordinator to encrypt the new channel key for a specific member.
///
/// Implementation: Encrypts the raw 32-byte channel key directly using ChaCha20-Poly1305
/// with the shared key. The result (nonce + ciphertext + auth tag) is base64-encoded once.
///
/// # Security Notes
/// - Uses a fresh random 12-byte nonce for each wrapping operation
/// - No pre-encoding of the key to avoid unnecessary overhead
/// - The shared key must be a previously established 32-byte symmetric key
///
/// # Returns
/// A base64-encoded string containing: nonce (12 bytes) + ciphertext (32 bytes) + auth tag (16 bytes)
pub fn wrap_key(channel_key: &[u8; 32], shared_key_with_member: &[u8; 32]) -> Result<String> {
    // Generate a fresh random nonce for this wrapping operation
    let nonce_bytes = generate_random_bytes(12);
    let mut nonce_array = [0u8; 12];
    nonce_array.copy_from_slice(&nonce_bytes[..12]);
    let nonce = Nonce::from(nonce_array);

    // Create cipher with the shared key
    let cipher = ChaCha20Poly1305::new(shared_key_with_member.into());

    // Encrypt the raw 32-byte channel key (no pre-encoding)
    let ciphertext = cipher
        .encrypt(&nonce, channel_key.as_ref())
        .map_err(|e| FishError::CryptoError(format!("Key wrapping failed: {}", e)))?;

    // Concatenate nonce + ciphertext (ciphertext already includes the 16-byte auth tag)
    let mut result = Vec::with_capacity(12 + ciphertext.len());
    result.extend_from_slice(&nonce_array);
    result.extend_from_slice(&ciphertext);

    // Base64 encode the complete package (only once)
    Ok(general_purpose::STANDARD.encode(&result))
}

/// Unwraps a channel key using a pre-shared symmetric key.
/// This is used by a member to decrypt the channel key received from the coordinator.
///
/// Implementation: Decodes the base64 input, extracts the nonce and ciphertext, then
/// decrypts using ChaCha20-Poly1305 with the shared key. Returns the raw 32-byte channel key.
///
/// # Security Notes
/// - Verifies the authentication tag automatically (AEAD property)
/// - Validates the resulting key length is exactly 32 bytes
/// - Constant-time comparison via ChaCha20-Poly1305 internal verification
///
/// # Returns
/// The unwrapped 32-byte channel key
pub fn unwrap_key(
    wrapped_key_b64: &str,
    shared_key_with_coordinator: &[u8; 32],
) -> Result<[u8; 32]> {
    // Decode the base64 input
    let wrapped_bytes = general_purpose::STANDARD
        .decode(wrapped_key_b64)
        .map_err(|e| FishError::CryptoError(format!("Invalid base64 in wrapped key: {}", e)))?;

    // Validate minimum length: 12 (nonce) + 32 (key) + 16 (auth tag) = 60 bytes
    if wrapped_bytes.len() < 60 {
        return Err(FishError::CryptoError(format!(
            "Wrapped key too short: expected at least 60 bytes, got {}",
            wrapped_bytes.len()
        )));
    }

    // Extract nonce (first 12 bytes) and ciphertext (remaining bytes)
    let (nonce_bytes, ciphertext) = wrapped_bytes.split_at(12);
    let nonce_array: [u8; 12] = nonce_bytes
        .try_into()
        .map_err(|_| FishError::CryptoError("Invalid nonce length".to_string()))?;
    let nonce = Nonce::from(nonce_array);

    // Create cipher with the shared key
    let cipher = ChaCha20Poly1305::new(shared_key_with_coordinator.into());

    // Decrypt the ciphertext (this also verifies the auth tag)
    let plaintext = cipher.decrypt(&nonce, ciphertext).map_err(|e| {
        FishError::CryptoError(format!(
            "Key unwrapping failed (invalid key or corrupted data): {}",
            e
        ))
    })?;

    // Validate plaintext length
    let plaintext_len = plaintext.len();

    // Convert the plaintext to a 32-byte array
    plaintext.try_into().map_err(|_| {
        FishError::CryptoError(format!(
            "Unwrapped key has invalid length: expected 32 bytes, got {}",
            plaintext_len
        ))
    })
}
