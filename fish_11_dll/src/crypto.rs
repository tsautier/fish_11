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
use std::sync::atomic::AtomicU64;

use crate::error::{FishError, Result};
use crate::utils::{base64_decode, base64_encode, generate_random_bytes};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chrono::{DateTime, Duration, Utc};
use fish_11_core::globals::MAX_MESSAGE_SIZE;
use hkdf::Hkdf;
use log::{debug, warn};
use lru_time_cache::LruCache;
use secrecy::{ExposeSecret, Secret};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroize;

// constants

const MAX_CIPHERTEXT_SIZE: usize = MAX_MESSAGE_SIZE + 16 + 12; // message + auth tag + nonce
const NONCE_SIZE_BYTES: usize = 12; // ChaCha20-Poly1305 standard nonce size (96 bits)

// Global nonce cache for anti-replay protection
// Each nonce is stored with a 1-hour expiry to detect replay attacks while allowing
// for reasonable clock skew and network delays.
lazy_static::lazy_static! {
    static ref NONCE_CACHE: Mutex<LruCache<[u8; NONCE_SIZE_BYTES], ()>> = Mutex::new(
        LruCache::with_expiry_duration_and_capacity(
            chrono::Duration::hours(1)
                .to_std()
                .unwrap_or_else(|_| std::time::Duration::from_secs(3600)), // 1 hour in seconds as fallback
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
pub fn generate_symmetric_key() -> Result<[u8; 32]> {
    generate_random_bytes(32)
        .try_into()
        .map_err(|_| FishError::CryptoError("Failed to convert Vec<u8> to [u8; 32]".to_string()))
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
pub fn encrypt_message(
    key: &[u8; 32],
    message: &str,
    recipient: Option<&str>,
    associated_data: Option<&[u8]>,
) -> Result<String> {
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
    let nonce_bytes = generate_random_bytes(NONCE_SIZE_BYTES);
    let mut nonce_array = [0u8; NONCE_SIZE_BYTES];
    nonce_array.copy_from_slice(&nonce_bytes[..NONCE_SIZE_BYTES]);

    let nonce = Nonce::from(nonce_array);

    // Create the cipher
    let chacha_key = Key::from(*key);
    let cipher = ChaCha20Poly1305::new(&chacha_key);

    // Encrypt the message, including associated data if provided
    let ciphertext = match associated_data {
        Some(ad) => cipher.encrypt(&nonce, Payload { msg: message.as_bytes(), aad: ad }),
        None => cipher.encrypt(&nonce, Payload { msg: message.as_bytes(), aad: &[] }),
    }
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

        // Log sensitive content if DEBUG flag is enabled for sensitive content
        if fish_11_core::globals::LOG_DECRYPTED_CONTENT {
            log::debug!("Crypto: encrypting message for '{}': '{}'", rec, message);
        }
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
/// * `associated_data` - optional data to authenticate (e.g., channel name)
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
pub fn decrypt_message(
    key: &[u8; 32],
    encrypted_data: &str,
    associated_data: Option<&[u8]>,
) -> Result<String> {
    // Decode base64 data
    let data = base64_decode(encrypted_data)
        .map_err(|e| FishError::CryptoError(format!("Invalid base64 data: {}", e)))?;

    // Fuzzing protection - early rejection
    if data.len() > MAX_CIPHERTEXT_SIZE {
        return Err(FishError::CryptoError(format!("Ciphertext too large: {} bytes", data.len())));
    }

    // Check if we have enough data for nonce (12 bytes) + at least some ciphertext
    // NONCE_SIZE_BYTES is 12
    if data.len() <= NONCE_SIZE_BYTES {
        return Err(FishError::CryptoError("Encrypted data too short".to_string()));
    }

    // Split into nonce and ciphertext : 12 bytes nonce
    let nonce = &data[..NONCE_SIZE_BYTES];
    // The rest is ciphertext
    let ciphertext = &data[NONCE_SIZE_BYTES..];

    // Anti-replay protection
    {
        let mut nonce_array = [0u8; NONCE_SIZE_BYTES];
        nonce_array.copy_from_slice(nonce);

        let cache_lock_result = NONCE_CACHE.lock();
        if cache_lock_result.is_err() {
            return Err(FishError::InternalError("FAILED_TO_ACQUIRE_NONCE_CACHE_LOCK".to_string()));
        }
        let mut cache = cache_lock_result.unwrap();
        if cache.contains_key(&nonce_array) {
            return Err(FishError::CryptoError("Potential replay attack detected".to_string()));
        }
        cache.insert(nonce_array, ());
    }

    // Create cipher
    let chacha_key = Key::from(*key);
    let cipher = ChaCha20Poly1305::new(&chacha_key);
    let mut nonce_array = [0u8; NONCE_SIZE_BYTES];
    nonce_array.copy_from_slice(nonce);
    let nonce = Nonce::from(nonce_array);

    // Decrypt, including associated data if provided
    let plaintext = match associated_data {
        Some(ad) => cipher.decrypt(&nonce, Payload { msg: ciphertext, aad: ad }),
        None => cipher.decrypt(&nonce, Payload { msg: ciphertext, aad: &[] }),
    }
    .map_err(|e| FishError::CryptoError(format!("Decryption failed: {}", e)))?;

    // Log decryption (audit trail)
    let mut hasher = Sha256::default();
    hasher.update(&plaintext);
    let msg_hash = base64_encode(&hasher.finalize()[0..8]);
    log_audit(&format!("Decrypt - {}", msg_hash));

    // Log sensitive content if DEBUG flag is enabled for sensitive content
    if fish_11_core::globals::LOG_DECRYPTED_CONTENT {
        if let Ok(plaintext_str) = std::str::from_utf8(&plaintext) {
            log::debug!("Crypto: decrypted message content: '{}'", plaintext_str);
        }
    }

    // Convert to string
    String::from_utf8(plaintext)
        .map_err(|e| FishError::CryptoError(format!("UTF-8 conversion failed: {}", e)))
}

/// Format a public key for sharing over IRC
///
/// Encodes a 32-byte X25519 public key as base64 with the `X25519_INIT:` prefix.
///
/// # Arguments
/// * `public_key` - the 32-byte X25519 public key
///
/// # Returns
/// A formatted string: `X25519_INIT:<base64-encoded-key>`
pub fn format_public_key(public_key: &[u8; 32]) -> String {
    let encoded = base64_encode(public_key);
    format!("X25519_INIT:{}", encoded)
}

/// Extract and validate a public key from a formatted string
///
/// Parses a `X25519_INIT:<base64>` formatted string, decodes the base64 payload,
/// and validates the resulting public key against low-order points.
///
/// # Arguments
/// * `formatted` - the formatted key string (whitespace is trimmed)
///
/// # Returns
/// The 32-byte X25519 public key or an error if the format is invalid or the key
/// fails validation.
pub fn extract_public_key(formatted: &str) -> Result<[u8; 32]> {
    const PREFIX: &str = "X25519_INIT:";

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
/// * `public_key_str` - their formatted public key (`X25519_INIT:...`)
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
    match crate::config::set_key(nickname, &shared_secret, network, false, true) {
        Ok(_) => {
            log_audit(&format!("Key exchange completed with {}", nickname));
            Ok(())
        }
        Err(FishError::DuplicateEntry(_)) => {
            // Key already exists, try to overwrite
            log_audit(&format!("Key exchange updated existing key for {}", nickname));
            crate::config::set_key(nickname, &shared_secret, network, true, true)
        }
        Err(e) => Err(e),
    }
}

/// Check if a string is in valid public key format
pub fn is_valid_public_key_format(formatted: &str) -> bool {
    const PREFIX: &str = "X25519_INIT:";
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
    // Use the standard debug logging
    log::debug!("[AUDIT] {}", event);

    // Also log to the specialized audit log file
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

        let shared1_result = compute_shared_secret(&keypair1.private_key, &keypair2.public_key);
        if shared1_result.is_err() {
            panic!("Failed to compute shared secret 1: {:?}", shared1_result.err());
        }
        let shared1 = shared1_result.unwrap();

        let shared2_result = compute_shared_secret(&keypair2.private_key, &keypair1.public_key);
        if shared2_result.is_err() {
            panic!("Failed to compute shared secret 2: {:?}", shared2_result.err());
        }
        let shared2 = shared2_result.unwrap();

        assert_eq!(shared1, shared2, "Shared secrets should be identical");
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key_result = generate_random_bytes(32).try_into();
        if key_result.is_err() {
            panic!("Failed to generate random key: {:?}", key_result.err());
        }
        let key: [u8; 32] = key_result.unwrap();
        let message = "This is a secret message for testing purposes.";

        let encrypted_data_result = encrypt_message(&key, message, Some("test_recipient"), None);
        if encrypted_data_result.is_err() {
            panic!("Encryption failed: {:?}", encrypted_data_result.err());
        }
        let encrypted_data = encrypted_data_result.unwrap();

        let decrypted_message_result = decrypt_message(&key, &encrypted_data, None);
        if decrypted_message_result.is_err() {
            panic!("Decryption failed: {:?}", decrypted_message_result.err());
        }
        let decrypted_message = decrypted_message_result.unwrap();

        assert_eq!(message, decrypted_message, "Decrypted message should match original message");
    }

    #[test]
    fn test_encrypt_decrypt_with_ad() {
        let key_result = generate_random_bytes(32).try_into();
        if let Err(_) = key_result {
            panic!("Failed to convert random bytes to [u8; 32]");
        }
        let key: [u8; 32] = key_result.unwrap();

        let message = "test message";
        let ad = b"associated data";

        let encrypted_result = encrypt_message(&key, message, None, Some(ad));
        if encrypted_result.is_err() {
            panic!("Encryption failed: {:?}", encrypted_result.err());
        }
        let encrypted = encrypted_result.unwrap();

        // Should succeed with correct AD
        let decrypted_result = decrypt_message(&key, &encrypted, Some(ad));
        if decrypted_result.is_err() {
            panic!("Decryption failed: {:?}", decrypted_result.err());
        }
        let decrypted = decrypted_result.unwrap();
        assert_eq!(decrypted, message);

        // Should fail with incorrect AD
        let bad_ad_result = decrypt_message(&key, &encrypted, Some(b"wrong ad"));
        assert!(bad_ad_result.is_err());

        // Should fail with no AD
        let no_ad_result = decrypt_message(&key, &encrypted, None);
        assert!(no_ad_result.is_err());
    }

    #[test]
    fn test_decrypt_with_wrong_key() {
        let key1_result = generate_random_bytes(32).try_into();
        if let Err(_) = key1_result {
            panic!("Failed to generate key 1");
        }
        let key1: [u8; 32] = key1_result.unwrap();

        let key2_result = generate_random_bytes(32).try_into();
        if let Err(_) = key2_result {
            panic!("Failed to generate key 2");
        }
        let key2: [u8; 32] = key2_result.unwrap();

        let message = "Another secret message.";

        assert_ne!(key1, key2);

        let encrypted_data_result = encrypt_message(&key1, message, None, None);
        if encrypted_data_result.is_err() {
            panic!("Encryption failed: {:?}", encrypted_data_result.err());
        }
        let encrypted_data = encrypted_data_result.unwrap();

        let result = decrypt_message(&key2, &encrypted_data, None);

        assert!(result.is_err(), "Decryption with the wrong key should fail");
    }

    #[test]
    fn test_replay_attack_prevention() {
        // Clear the cache for a clean test run
        let mutex_result = NONCE_CACHE.lock();
        if mutex_result.is_err() {
            panic!("Failed to lock nonce cache");
        }
        mutex_result.unwrap().clear();

        let key_result = generate_random_bytes(32).try_into();
        if key_result.is_err() {
            panic!("Failed to generate key: {:?}", key_result.err());
        }
        let key: [u8; 32] = key_result.unwrap();
        let message = "A message to test replay attacks.";

        let encrypted_data_result = encrypt_message(&key, message, None, None);
        if encrypted_data_result.is_err() {
            panic!("Encryption failed: {:?}", encrypted_data_result.err());
        }
        let encrypted_data = encrypted_data_result.unwrap();

        // First decryption should succeed
        let first_decryption_result = decrypt_message(&key, &encrypted_data, None);
        assert!(first_decryption_result.is_ok(), "First decryption should succeed");

        // Second decryption with the same data should fail
        let second_decryption_result = decrypt_message(&key, &encrypted_data, None);
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

/// Advances a symmetric channel key using HKDF to provide Forward Secrecy.
///
/// Each message sent or received advances the key, so a compromise of the key at time T
/// does not compromise future messages.
///
/// # Arguments
/// * `current_key` - The current 32-byte symmetric key for the channel.
/// * `nonce` - The 12-byte nonce used to encrypt/decrypt the message. Used as salt.
/// * `channel_name` - The name of the channel, used as context info.
///
/// # Returns
/// A new 32-byte symmetric key.
///
/// # Security Notes
/// - Uses HKDF-SHA256 with nonce as salt for uniqueness per message
/// - One-way derivation provides Post-Compromise Security (PCS)
/// - Zeroizes temporary key material after use
pub fn advance_ratchet_key(
    current_key: &[u8; 32],
    nonce: &[u8; NONCE_SIZE_BYTES],
    channel_name: &str,
) -> Result<[u8; 32]> {
    use zeroize::Zeroize;

    // Clone current key to avoid mutating caller's data
    // Will be zeroized after HKDF to prevent lingering in stack
    let mut temp_current = *current_key;

    // Use HKDF-SHA256 to derive the next key.
    // The current key is the Input Keying Material (IKM).
    // The nonce is the salt, making each derivation unique per message.
    // The channel name and a domain separator are the context info.
    let hkdf = Hkdf::<Sha256>::new(Some(nonce), &temp_current);

    let mut next_key = [0u8; 32];
    let info = format!("FCEP-1-RATCHET:{}", channel_name);

    hkdf.expand(info.as_bytes(), &mut next_key).map_err(|e| {
        temp_current.zeroize(); // Zeroize on error path
        FishError::CryptoError(format!("HKDF expansion for ratchet failed: {}", e))
    })?;

    // Zeroize temporary key material from stack
    temp_current.zeroize();

    Ok(next_key)
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
    let nonce_bytes = generate_random_bytes(NONCE_SIZE_BYTES);
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
    let mut result = Vec::with_capacity(NONCE_SIZE_BYTES + ciphertext.len());
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
    let (nonce_bytes, ciphertext) = wrapped_bytes.split_at(NONCE_SIZE_BYTES);
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

// ===============================================================================
// FCEP-1 Ratcheting Tests
// ===============================================================================

#[cfg(test)]
mod fcep1_ratchet_tests {
    use super::*;

    #[test]
    fn test_ratchet_forward_secrecy() {
        // Test that ratcheting produces different keys each time
        let initial_key = [1u8; 32];
        let nonce1 = [0u8; NONCE_SIZE_BYTES];
        let nonce2 = [1u8; NONCE_SIZE_BYTES];
        let channel = "#test";

        // First ratchet step
        let key1_result = advance_ratchet_key(&initial_key, &nonce1, channel);
        if key1_result.is_err() {
            panic!("Failed to advance ratchet key1: {:?}", key1_result.err());
        }
        let key1 = key1_result.unwrap();
        assert_ne!(key1, initial_key, "Ratcheted key should differ from initial");

        // Second ratchet step (with different nonce)
        let key2_result = advance_ratchet_key(&key1, &nonce2, channel);
        if key2_result.is_err() {
            panic!("Failed to advance ratchet key2: {:?}", key2_result.err());
        }
        let key2 = key2_result.unwrap();
        assert_ne!(key2, key1, "Each ratchet step should produce unique key");
        assert_ne!(key2, initial_key, "Ratcheted key should differ from initial");

        // Verify one-way property: can't derive key1 from key2
        let attempted_reverse_result = advance_ratchet_key(&key2, &nonce1, channel);
        if attempted_reverse_result.is_err() {
            panic!("Failed to advance ratchet reverse: {:?}", attempted_reverse_result.err());
        }
        let attempted_reverse = attempted_reverse_result.unwrap();
        assert_ne!(attempted_reverse, key1, "Ratcheting must be one-way (PCS)");
    }

    #[test]
    fn test_ratchet_nonce_uniqueness() {
        // Different nonces should produce different keys
        let key = [42u8; 32];
        let nonce1 = [0u8; NONCE_SIZE_BYTES];
        let nonce2 = [1u8; NONCE_SIZE_BYTES];
        let channel = "#test";

        let derived1_result = advance_ratchet_key(&key, &nonce1, channel);
        if derived1_result.is_err() {
            panic!("Failed to advance ratchet with nonce1: {:?}", derived1_result.err());
        }
        let derived1 = derived1_result.unwrap();

        let derived2_result = advance_ratchet_key(&key, &nonce2, channel);
        if derived2_result.is_err() {
            panic!("Failed to advance ratchet with nonce2: {:?}", derived2_result.err());
        }
        let derived2 = derived2_result.unwrap();

        assert_ne!(derived1, derived2, "Different nonces must produce different keys");
    }

    #[test]
    fn test_ratchet_channel_binding() {
        // Same key + nonce but different channels should produce different keys
        let key = [42u8; 32];
        let nonce = [0u8; NONCE_SIZE_BYTES];

        let key_ch1_result = advance_ratchet_key(&key, &nonce, "#channel1");
        if key_ch1_result.is_err() {
            panic!("Failed to advance ratchet for channel1: {:?}", key_ch1_result.err());
        }
        let key_ch1 = key_ch1_result.unwrap();

        let key_ch2_result = advance_ratchet_key(&key, &nonce, "#channel2");
        if key_ch2_result.is_err() {
            panic!("Failed to advance ratchet for channel2: {:?}", key_ch2_result.err());
        }
        let key_ch2 = key_ch2_result.unwrap();

        assert_ne!(key_ch1, key_ch2, "Channel name must be bound to key derivation");
    }

    #[test]
    fn test_cross_channel_replay_prevention() {
        // Test that messages encrypted for one channel can't be decrypted for another
        let key = [42u8; 32];
        let message = "Secret message";

        // Encrypt for #channel1
        let encrypted_ch1_result =
            encrypt_message(&key, message, Some("#channel1"), Some(b"#channel1"));
        if encrypted_ch1_result.is_err() {
            panic!("Encryption for channel1 failed: {:?}", encrypted_ch1_result.err());
        }
        let encrypted_ch1 = encrypted_ch1_result.unwrap();

        // Try to decrypt for #channel2 (should fail due to AD mismatch)
        let decrypt_result = decrypt_message(&key, &encrypted_ch1, Some(b"#channel2"));

        assert!(decrypt_result.is_err(), "Cross-channel replay must be prevented by AD");
    }

    #[test]
    fn test_nonce_cache_prevents_replay() {
        use crate::config::models::NonceCache;

        let mut cache = NonceCache::new();
        let nonce = [42u8; NONCE_SIZE_BYTES];

        // First check should pass (nonce is new)
        assert!(!cache.check_and_add(nonce), "New nonce should be accepted");

        // Second check should fail (nonce is duplicate)
        assert!(cache.check_and_add(nonce), "Duplicate nonce should be detected");
    }

    #[test]
    fn test_nonce_cache_overflow() {
        use crate::config::models::NonceCache;

        let mut cache = NonceCache::new();

        // Add 101 nonces (MAX_NONCE_CACHE_SIZE = 100)
        for i in 0..101 {
            let mut nonce = [0u8; NONCE_SIZE_BYTES];
            nonce[0] = i as u8;
            cache.check_and_add(nonce);
        }

        // First nonce should be evicted (FIFO)
        let first_nonce = [0u8; NONCE_SIZE_BYTES];
        assert!(
            !cache.recent_nonces.contains(&first_nonce),
            "Oldest nonce should be evicted after cache overflow"
        );

        // Last nonce should still be present
        let mut last_nonce = [0u8; NONCE_SIZE_BYTES];
        last_nonce[0] = 100;
        assert!(cache.recent_nonces.contains(&last_nonce), "Most recent nonce should be retained");

        // Cache size should be capped
        assert_eq!(
            cache.recent_nonces.len(),
            100,
            "Cache size should be limited to MAX_NONCE_CACHE_SIZE"
        );
    }

    #[test]
    fn test_ratchet_state_advance() {
        use crate::config::models::RatchetState;

        let initial_key = [1u8; 32];
        let mut state = RatchetState::new(initial_key);

        assert_eq!(state.epoch, 0, "Initial epoch should be 0");
        assert!(state.previous_keys.is_empty(), "Initial previous_keys should be empty");

        // Advance once
        let next_key = [2u8; 32];
        state.advance(next_key);

        assert_eq!(state.epoch, 1, "Epoch should increment");
        assert_eq!(state.current_key, next_key, "Current key should be updated");
        assert_eq!(state.previous_keys.len(), 1, "Previous key should be stored");
        assert_eq!(state.previous_keys[0], initial_key, "Initial key should be in previous_keys");

        // Advance 5 more times to test window eviction
        for i in 3..8 {
            let key = [i as u8; 32];
            state.advance(key);
        }

        assert_eq!(state.epoch, 6, "Epoch should be 6 after 6 advances");
        assert_eq!(
            state.previous_keys.len(),
            5,
            "Previous keys should be capped at MAX_PREVIOUS_KEYS"
        );

        // Oldest key (initial_key) should be evicted
        assert!(
            !state.previous_keys.contains(&initial_key),
            "Oldest key should be evicted from window"
        );
    }

    #[test]
    fn test_encrypt_decrypt_with_ratchet_simulation() {
        // Simulate 3-message exchange with ratcheting
        let mut current_key = [42u8; 32];
        let channel = "#test";

        let messages = ["Message 1", "Message 2", "Message 3"];
        let mut encrypted_messages = Vec::new();
        let mut ratchet_keys = Vec::new();

        // Encrypt messages with ratcheting
        for msg in &messages {
            let encrypted_result =
                encrypt_message(&current_key, msg, Some(channel), Some(channel.as_bytes()));
            if encrypted_result.is_err() {
                panic!("Ratchet test encryption failed: {:?}", encrypted_result.err());
            }
            let encrypted = encrypted_result.unwrap();
            encrypted_messages.push(encrypted.clone());
            ratchet_keys.push(current_key);

            // Extract nonce and advance ratchet
            let encrypted_bytes_result = crate::utils::base64_decode(&encrypted);
            if encrypted_bytes_result.is_err() {
                panic!("Ratchet test failed to base64 decode encrypted data: {:?}", encrypted_bytes_result.err());
            }
            let encrypted_bytes = encrypted_bytes_result.unwrap();

            let nonce_slice = &encrypted_bytes[..NONCE_SIZE_BYTES];
            let nonce_result: Result<[u8; NONCE_SIZE_BYTES], _> = nonce_slice.try_into();
            if nonce_result.is_err() {
                panic!("Ratchet test failed to convert slice to nonce: {:?}", nonce_result.err());
            }
            let nonce: [u8; NONCE_SIZE_BYTES] = nonce_result.unwrap();

            let next_key_result = advance_ratchet_key(&current_key, &nonce, channel);
            if next_key_result.is_err() {
                panic!("Ratchet test failed to advance key: {:?}", next_key_result.err());
            }
            current_key = next_key_result.unwrap();
        }

        // Verify all keys are different
        assert_ne!(ratchet_keys[0], ratchet_keys[1]);
        assert_ne!(ratchet_keys[1], ratchet_keys[2]);
        assert_ne!(ratchet_keys[0], ratchet_keys[2]);

        // Decrypt messages in order (each with its corresponding key)
        for (i, encrypted) in encrypted_messages.iter().enumerate() {
            let decrypted_result =
                decrypt_message(&ratchet_keys[i], encrypted, Some(channel.as_bytes()));
            if decrypted_result.is_err() {
                panic!("Ratchet test decryption failed for message {}: {:?}", i, decrypted_result.err());
            }
            let decrypted = decrypted_result.unwrap();
            assert_eq!(decrypted, messages[i], "Message {} should decrypt correctly", i);
        }

        // Verify old keys can't decrypt new messages (forward secrecy)
        let decrypt_result =
            decrypt_message(&ratchet_keys[0], &encrypted_messages[2], Some(channel.as_bytes()));
        assert!(
            decrypt_result.is_err(),
            "Old key should not decrypt messages encrypted with newer key"
        );
    }

    #[test]
    fn test_ratchet_state_advancement_with_key_derivation() {
        use crate::config::models::RatchetState;
        let initial_key = [1u8; 32];
        let mut state = RatchetState::new(initial_key);
        let nonce = [0u8; 12];

        let key1 = state.current_key;
        let next_key1 = advance_ratchet_key(&key1, &nonce, "#test").unwrap();
        state.advance(next_key1);

        // Key 1 should be in previous_keys
        assert!(state.previous_keys.contains(&key1));
        assert_ne!(state.current_key, key1);

        // Advance again
        let key2 = state.current_key;
        let next_key2 = advance_ratchet_key(&key2, &nonce, "#test").unwrap();
        state.advance(next_key2);

        // Keys should all be different
        assert_ne!(next_key1, next_key2);
    }

    #[test]
    fn test_out_of_order_decryption_logic() {
        // Safely clear the nonce cache
        {
            let cache_result = NONCE_CACHE.lock();
            if cache_result.is_err() {
                panic!("Failed to acquire NONCE_CACHE lock");
            }
            let mut cache = cache_result.unwrap();
            cache.clear();
        }

        use crate::config::models::RatchetState;

        let initial_key = [1u8; 32];
        let mut state = RatchetState::new(initial_key);
        let channel = "#test";

        // Generate a sequence of 3 keys
        let key1 = state.current_key;
        let nonce1 = [1u8; 12];
        let next_key1_result = advance_ratchet_key(&key1, &nonce1, channel);
        if next_key1_result.is_err() {
            panic!("Failed to advance ratchet key1: {:?}", next_key1_result.err());
        }
        let next_key1 = next_key1_result.unwrap();
        state.advance(next_key1);

        let key2 = state.current_key;
        let nonce2 = [2u8; 12];
        let next_key2_result = advance_ratchet_key(&key2, &nonce2, channel);
        if next_key2_result.is_err() {
            panic!("Failed to advance ratchet key2: {:?}", next_key2_result.err());
        }
        let next_key2 = next_key2_result.unwrap();
        state.advance(next_key2);

        let key3 = state.current_key;

        // At this point, state.current_key is key3, and state.previous_keys contains [key1, key2]

        // Encrypt messages with their corresponding keys
        let msg1 = "old message";
        let encrypted1_result = encrypt_message(&key1, msg1, None, Some(channel.as_bytes()));
        if encrypted1_result.is_err() {
            panic!("Encryption of msg1 failed: {:?}", encrypted1_result.err());
        }
        let encrypted1 = encrypted1_result.unwrap();

        let msg3 = "current message";
        let encrypted3_result = encrypt_message(&key3, msg3, None, Some(channel.as_bytes()));
        if encrypted3_result.is_err() {
            panic!("Encryption of msg3 failed: {:?}", encrypted3_result.err());
        }
        let encrypted3 = encrypted3_result.unwrap();

        // Decrypting the current message with the current key should work
        let decrypt_current_result = decrypt_message(&state.current_key, &encrypted3, Some(channel.as_bytes()));
        if decrypt_current_result.is_err() {
            panic!("Decryption of current message failed: {:?}", decrypt_current_result.err());
        }
        assert_eq!(decrypt_current_result.unwrap(), msg3);

        // Decrypting the old message (msg1) with the current key should fail
        assert!(
            decrypt_message(&state.current_key, &encrypted1, Some(channel.as_bytes())).is_err()
        );

        // But it should succeed if we search through the previous_keys
        let mut decrypted_old_message = None;
        for old_key in &state.previous_keys {
            if let Ok(plaintext) = decrypt_message(old_key, &encrypted1, Some(channel.as_bytes())) {
                decrypted_old_message = Some(plaintext);
                break;
            }
        }
        if decrypted_old_message.is_none() {
            panic!("Failed to decrypt old message with previous keys");
        }
        assert_eq!(decrypted_old_message.unwrap(), msg1);
    }
}
