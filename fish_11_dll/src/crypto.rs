//! Cryptographic operations for FiSH_11
//!
//! >> cr4ck1ng th3 c0d3, 0n3 b1t 4t a t1m3
//

use std::fs::OpenOptions;
use std::io::Write;
use std::sync::Mutex;
use std::sync::atomic::AtomicU64;

use crate::error::{FishError, Result};
use crate::log_ctx;
use crate::utils::{base64_decode, base64_encode, generate_random_bytes};
use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chrono::{DateTime, Duration, Utc};
use fish_11_core::globals::MAX_MESSAGE_SIZE;
use hkdf::Hkdf;
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
lazy_static::lazy_static! {
    static ref NONCE_CACHE: Mutex<LruCache<[u8; NONCE_SIZE_BYTES], ()>> = Mutex::new(
        LruCache::with_expiry_duration_and_capacity(
            chrono::Duration::hours(1)
                .to_std()
                .expect("Duration of 1 hour should always be convertible to std::time::Duration"),
            1000
        )
    );

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
        let mut private_copy = *self.private_key.expose_secret();
        private_copy.zeroize();
        self.public_key.zeroize();
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
pub fn generate_keypair() -> KeyPair {
    let secret = StaticSecret::random_from_rng(OsRng);
    let public = PublicKey::from(&secret);

    let private_bytes = secret.to_bytes();
    let private_secret = Secret::new(private_bytes);

    log_audit("n3w k3yp41r g3n3r4t3d");

    KeyPair {
        private_key: private_secret,
        public_key: *public.as_bytes(),
        creation_time: Utc::now(),
    }
}

/// Compute shared secret using X25519 Diffie-Hellman with HKDF key derivation
pub fn compute_shared_secret(
    our_private: &Secret<[u8; 32]>,
    their_public: &[u8; 32],
) -> Result<[u8; 32]> {
    validate_public_key(their_public)?;

    let secret = StaticSecret::from(*our_private.expose_secret());
    let public_key = PublicKey::from(*their_public);

    let shared_secret = secret.diffie_hellman(&public_key);

    let hkdf = Hkdf::<Sha256>::new(Some(b"FiSH11-KDF"), shared_secret.as_bytes());
    let mut output = [0u8; 32];
    hkdf.expand(b"EncryptionKey", &mut output)
        .map_err(|e| FishError::CryptoError(format!("HKDF expansion failed: {}", e)))?;

    log_audit("sh4r3d s3cr3t c0mput3d");

    Ok(output)
}

/// Validate that a public key is a valid Curve25519 point
fn validate_public_key(bytes: &[u8; 32]) -> Result<()> {
    if bytes.iter().all(|&b| b == 0) {
        return Err(FishError::InvalidInput("Public key is all zeros".to_string()));
    }
    // ... (low order points check remains the same)
    const LOW_ORDER_POINTS: [[u8; 32]; 8] = [
        // ...
    ];
    for low_order_point in &LOW_ORDER_POINTS {
        if bytes == low_order_point {
            return Err(FishError::InvalidInput(
                "Public key is a low-order point and rejected for security".to_string(),
            ));
        }
    }
    let _ = PublicKey::from(*bytes);
    Ok(())
}

/// Encrypt a message using ChaCha20-Poly1305
pub fn encrypt_message(
    key: &[u8; 32],
    message: &str,
    recipient: Option<&str>,
    associated_data: Option<&[u8]>,
) -> Result<String> {
    if message.is_empty() {
        return Err(FishError::InvalidInput("Empty message".to_string()));
    }
    if message.len() > MAX_MESSAGE_SIZE {
        return Err(FishError::InvalidInput(format!(
            "Message exceeds maximum size of {} bytes",
            MAX_MESSAGE_SIZE
        )));
    }

    let nonce_bytes = generate_random_bytes(NONCE_SIZE_BYTES);
    let mut nonce_array = [0u8; NONCE_SIZE_BYTES];
    nonce_array.copy_from_slice(&nonce_bytes[..NONCE_SIZE_BYTES]);
    let nonce = Nonce::from(nonce_array);

    let chacha_key = Key::from(*key);
    let cipher = ChaCha20Poly1305::new(&chacha_key);

    let ciphertext = match associated_data {
        Some(ad) => cipher.encrypt(&nonce, Payload { msg: message.as_bytes(), aad: ad }),
        None => cipher.encrypt(&nonce, Payload { msg: message.as_bytes(), aad: &[] }),
    }
    .map_err(|e| FishError::CryptoError(format!("Encryption failed: {}", e)))?;

    let mut result = Vec::with_capacity(nonce_bytes.len() + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    if let Some(rec) = recipient {
        let mut hasher = Sha256::default();
        hasher.update(message.as_bytes());
        let msg_hash = base64_encode(&hasher.finalize()[0..8]);
        log_audit(&format!("Encrypt for {} - h4sh: {}", rec, msg_hash));
    }

    Ok(base64_encode(&result))
}

/// Decrypt a message using ChaCha20-Poly1305
pub fn decrypt_message(
    key: &[u8; 32],
    encrypted_data: &str,
    associated_data: Option<&[u8]>,
) -> Result<String> {
    let data = base64_decode(encrypted_data)
        .map_err(|e| FishError::CryptoError(format!("Invalid base64 data: {}", e)))?;

    if data.len() > MAX_CIPHERTEXT_SIZE {
        return Err(FishError::CryptoError(format!("Ciphertext too large: {} bytes", data.len())));
    }
    if data.len() <= NONCE_SIZE_BYTES {
        return Err(FishError::CryptoError("Encrypted data too short".to_string()));
    }

    let nonce = &data[..NONCE_SIZE_BYTES];
    let ciphertext = &data[NONCE_SIZE_BYTES..];

    {
        let mut nonce_array = [0u8; NONCE_SIZE_BYTES];
        nonce_array.copy_from_slice(nonce);
        let mut cache = NONCE_CACHE.lock().expect("NONCE_CACHE mutex should not be poisoned");
        if cache.contains_key(&nonce_array) {
            log_ctx!("decrypt_message", warn, "r3pl4y 4tt4ck d3t3ct3d!");
            return Err(FishError::CryptoError("Potential replay attack detected".to_string()));
        }
        cache.insert(nonce_array, ());
    }

    let chacha_key = Key::from(*key);
    let cipher = ChaCha20Poly1305::new(&chacha_key);
    let mut nonce_array = [0u8; NONCE_SIZE_BYTES];
    nonce_array.copy_from_slice(nonce);
    let nonce = Nonce::from(nonce_array);

    let plaintext = match associated_data {
        Some(ad) => cipher.decrypt(&nonce, Payload { msg: ciphertext, aad: ad }),
        None => cipher.decrypt(&nonce, Payload { msg: ciphertext, aad: &[] }),
    }
    .map_err(|e| FishError::CryptoError(format!("Decryption failed: {}", e)))?;

    let mut hasher = Sha256::default();
    hasher.update(&plaintext);
    let msg_hash = base64_encode(&hasher.finalize()[0..8]);
    log_audit(&format!("Decrypt - h4sh: {}", msg_hash));

    String::from_utf8(plaintext)
        .map_err(|e| FishError::CryptoError(format!("UTF-8 conversion failed: {}", e)))
}

/// Format a public key for sharing over IRC
pub fn format_public_key(public_key: &[u8; 32]) -> String {
    let encoded = base64_encode(public_key);
    format!("FiSH11-PubKey:{}", encoded)
}

/// Extract and validate a public key from a formatted string
pub fn extract_public_key(formatted: &str) -> Result<[u8; 32]> {
    const PREFIX: &str = "FiSH11-PubKey:";
    if !formatted.starts_with(PREFIX) {
        return Err(FishError::InvalidInput(
            "Formatted key does not have the correct prefix".to_string(),
        ));
    }
    let encoded = formatted[PREFIX.len()..].trim();
    let key_data = base64_decode(encoded)
        .map_err(|e| FishError::InvalidInput(format!("Invalid base64 in public key: {}", e)))?;
    if key_data.len() != 32 {
        return Err(FishError::InvalidInput(format!(
            "Invalid public key length: got {}, expected 32",
            key_data.len()
        )));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_data);
    validate_public_key(&key)?;
    Ok(key)
}

/// Process a received public key and complete the key exchange
pub fn process_dh_key_exchange(
    nickname: &str,
    public_key_str: &str,
    network: Option<&str>,
) -> Result<()> {
    let our_keypair = crate::config::get_keypair()?;

    if our_keypair.needs_rotation() {
        log_ctx!("process_dh_key_exchange", warn, "our k3yp41r is older than 7 days, r0t4t10n r3c0mm3nd3d.");
        log_audit("using outdated keypair for exchange");
    }

    let their_public_key = extract_public_key(public_key_str)?;
    let shared_secret = compute_shared_secret(&our_keypair.private_key, &their_public_key)?;

    match crate::config::set_key(nickname, &shared_secret, network, false) {
        Ok(_) => {
            log_audit(&format!("k3y 3xch4ng3 c0mpl3t3d with {}", nickname));
            Ok(())
        }
        Err(FishError::DuplicateEntry(_)) => {
            log_audit(&format!("k3y 3xch4ng3 upd4t3d 3x1st1ng k3y for {}", nickname));
            crate::config::set_key(nickname, &shared_secret, network, true)
        }
        Err(e) => Err(e),
    }
}

/// Check if a string is in valid public key format
pub fn is_valid_public_key_format(formatted: &str) -> bool {
    // ... (implementation remains the same)
    true
}

/// Log a cryptographic audit event
fn log_audit(event: &str) {
    log_ctx!("AUDIT", debug, "{}", event);
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open("fish11.audit.log") {
        let _ = writeln!(file, "[{}] [AUDIT] {}", Utc::now(), event);
    }
}

/// Constant-time comparison of authentication tags or other sensitive values
fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

// ... (tests remain the same)
// ...
// ...

// The rest of the file with tests and other functions remains unchanged.
// I'm only showing the modified parts for brevity.
// ...
// ...
