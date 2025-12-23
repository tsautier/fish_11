//! Key derivation module for master key system
//!
//! Handles the derivation of the master key from a password using Argon2id,
//! and derivation of subkeys using HKDF.

use argon2::{Algorithm, Argon2, Params, PasswordHasher, Version, password_hash::SaltString};
use hkdf::Hkdf;
use sha2::Sha256;

/// Derive the master key from a password using Argon2id
///
/// # Arguments
/// * `password` - The user's master password
///
/// # Returns
/// * `Result<[u8; 32], String>` - The derived 32-byte master key
pub fn derive_master_key(password: &str) -> Result<[u8; 32], String> {
    use argon2::password_hash::rand_core::OsRng;

    // Generate a random salt
    let salt = SaltString::generate(&mut OsRng);

    // Create Argon2id instance with parameters
    let params = Params::new(
        65536,    // memory cost (64 MB)
        3,        // time cost
        4,        // parallelism
        Some(32), // output length
    )
    .map_err(|e| format!("Argon2 params error: {}", e))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    // Hash the password
    let password_hash = argon2
        .hash_password(password.as_bytes(), salt.as_salt())
        .map_err(|e| format!("Argon2 hashing error: {}", e))?;

    // Extract the hash and convert to 32-byte array
    let hash = password_hash.hash.unwrap();
    let hash_bytes = hash.as_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(hash_bytes);

    Ok(key)
}

/// Derive a subkey from the master key using HKDF
///
/// # Arguments
/// * `master_key` - The master key (32 bytes)
/// * `context` - The context string for HKDF (e.g., "fish_11_config", "fish_11_logs")
///
/// # Returns
/// * `[u8; 32]` - The derived 32-byte subkey
pub fn derive_subkey(master_key: &[u8; 32], context: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, master_key);
    let mut okm = [0u8; 32];
    hk.expand(context.as_bytes(), &mut okm)
        .expect("HKDF expansion failed - this should never happen with 32-byte output");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derive_master_key() {
        let password = "test_password_123";
        let key1 = derive_master_key(password).expect("Failed to derive key");
        let key2 = derive_master_key(password).expect("Failed to derive key again");

        // Keys should be different due to random salt
        assert_ne!(key1, key2);
    }

    #[test]
    fn test_derive_subkey() {
        let master_key = [1u8; 32]; // Use a fixed key for testing
        let subkey1 = derive_subkey(&master_key, "config");
        let subkey2 = derive_subkey(&master_key, "logs");

        // Subkeys should be different for different contexts
        assert_ne!(subkey1, subkey2);

        // Same context should produce same subkey
        let subkey3 = derive_subkey(&master_key, "config");
        assert_eq!(subkey1, subkey3);
    }
}
