//! Legacy FiSH 10 compatibility module
//!
//! This module provides compatibility with the legacy FiSH 10 protocol
//! using Blowfish encryption and blowfish.ini key management.

pub mod blowfish;
pub mod config;
pub mod dh1080;
pub mod encryption;
pub mod fish10_engine;
pub mod key_management;
pub mod message_detection;
use crate::unified_error::DllError;
use parking_lot::RwLock;
use std::sync::Arc;

/// Legacy configuration structure
#[derive(Debug, Clone)]
pub struct LegacyConfig {
    pub blowfish_ini_path: Option<String>,
    pub legacy_keys: Arc<RwLock<std::collections::HashMap<String, Vec<u8>>>>,
    pub dh1080_keys: Arc<RwLock<std::collections::HashMap<String, num_bigint::BigUint>>>,
}

impl Default for LegacyConfig {
    fn default() -> Self {
        Self {
            blowfish_ini_path: None,
            legacy_keys: Arc::new(RwLock::new(std::collections::HashMap::new())),
            dh1080_keys: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }
}

/// Global legacy configuration instance
use once_cell::sync::Lazy;
pub static LEGACY_CONFIG: Lazy<Arc<RwLock<LegacyConfig>>> =
    Lazy::new(|| Arc::new(RwLock::new(LegacyConfig::default())));

/// Initialize the legacy compatibility system
pub fn init_legacy_system() {
    log::info!("LEGACY: Initializing FiSH 10 compatibility system");

    // Load legacy configuration
    if let Err(e) = config::load_legacy_config() {
        log::warn!("LEGACY: Failed to load legacy config: {}", e);
    }

    // Initialize the FiSH 10 engine for fish_inject integration
    if let Err(e) = fish10_engine::init_fish10_engine() {
        log::warn!("LEGACY: Failed to initialize FiSH 10 engine: {}", e);
    }
}

/// Check if legacy mode is enabled for a given target
pub fn is_legacy_target(target: &str) -> bool {
    let config = LEGACY_CONFIG.read();
    let keys = config.legacy_keys.read();
    keys.contains_key(target)
}

/// Get a legacy key for a target
pub fn get_legacy_key(target: &str) -> Option<Vec<u8>> {
    let config = LEGACY_CONFIG.read();
    let keys = config.legacy_keys.read();
    keys.get(target).cloned()
}

/// Get the FiSH 10 engine pointer for registration with fish_inject
pub fn get_fish10_engine_ptr() -> Option<*const fish10_engine::Fish10Engine> {
    fish10_engine::get_fish10_engine()
}

/// Get the topic encryption setting for a channel
pub fn get_encrypt_topic_setting(network: &str, channel: &str) -> Result<bool, DllError> {
    config::get_encrypt_topic_setting(network, channel)
}

/// Set the topic encryption setting for a channel
pub fn set_encrypt_topic_setting(
    network: &str,
    channel: &str,
    enabled: bool,
) -> Result<(), DllError> {
    config::set_encrypt_topic_setting(network, channel, enabled)
}

#[cfg(test)]
pub mod test_utils {
    use super::*;

    /// Setup a test legacy key for testing purposes
    pub fn setup_test_legacy_key(target: &str, key: &[u8]) {
        let mut config = LEGACY_CONFIG.write();
        let mut keys = config.legacy_keys.write();
        keys.insert(target.to_string(), key.to_vec());
    }

    /// Clear all test legacy keys
    pub fn clear_test_legacy_keys() {
        let mut config = LEGACY_CONFIG.write();
        let mut keys = config.legacy_keys.write();
        keys.clear();
    }

    /// Setup a test DH1080 key for testing purposes
    pub fn setup_test_dh1080_key(target: &str, private_key: num_bigint::BigUint) {
        let mut config = LEGACY_CONFIG.write();
        let mut keys = config.dh1080_keys.write();
        keys.insert(target.to_string(), private_key);
    }

    /// Clear all test DH1080 keys
    pub fn clear_test_dh1080_keys() {
        let mut config = LEGACY_CONFIG.write();
        let mut keys = config.dh1080_keys.write();
        keys.clear();
    }
}

#[cfg(test)]
mod integration_tests {
    use super::*;
    use crate::legacy::blowfish;
    use crate::legacy::dh1080;
    use crate::legacy::key_management;
    use crate::legacy::message_detection;

    #[test]
    fn test_complete_dh1080_key_exchange_workflow() {
        // Step 1: Generate key pairs for both parties
        let alice_keypair = dh1080::generate_dh1080_keypair().unwrap();
        let bob_keypair = dh1080::generate_dh1080_keypair().unwrap();

        // Step 2: Compute shared secrets (both parties should get the same result)
        let alice_shared = dh1080::compute_dh1080_shared_secret(
            &alice_keypair.private_key(),
            &bob_keypair.public_key,
        )
        .unwrap();

        let bob_shared = dh1080::compute_dh1080_shared_secret(
            &bob_keypair.private_key(),
            &alice_keypair.public_key,
        )
        .unwrap();

        // Step 3: Verify the shared secrets match
        assert_eq!(alice_shared, bob_shared);
        assert!(!alice_shared.is_empty());
    }

    #[test]
    fn test_complete_legacy_encryption_decryption_workflow() {
        // Step 1: Generate a shared secret using DH1080 (simulating key exchange)
        let alice_keypair = dh1080::generate_dh1080_keypair().unwrap();
        let bob_keypair = dh1080::generate_dh1080_keypair().unwrap();

        let shared_secret = dh1080::compute_dh1080_shared_secret(
            &alice_keypair.private_key(),
            &bob_keypair.public_key,
        )
        .unwrap();

        // Step 2: Use the shared secret as the encryption key
        let encryption_key = shared_secret.as_bytes();

        // Step 3: Encrypt a message using Blowfish
        let plaintext = "Hello, this is a test message!";
        let encrypted = blowfish::encrypt_message(encryption_key, plaintext, &[]).unwrap();

        // Step 4: Decrypt the message using the same key
        let decrypted = blowfish::decrypt_message(encryption_key, &encrypted, &[]).unwrap();

        // Step 5: Verify the decrypted message matches the original
        assert_eq!(plaintext, decrypted);
    }

    #[test]
    fn test_message_detection_and_parsing() {
        // Test that message detection works correctly
        let fish10_message = "+OK abcdef123456";
        assert!(message_detection::is_fish10_message(fish10_message));

        let payload = message_detection::extract_fish10_payload(fish10_message).unwrap();
        assert_eq!(payload, "abcdef123456");

        let mcps_message = "mcps xyz789";
        assert!(message_detection::is_fish10_message(mcps_message));

        let payload = message_detection::extract_fish10_payload(mcps_message).unwrap();
        assert_eq!(payload, "xyz789");

        let non_fish10_message = "Hello world";
        assert!(!message_detection::is_fish10_message(non_fish10_message));
    }

    #[test]
    fn test_legacy_key_storage_and_retrieval() {
        // Test storing and retrieving a legacy key
        let target = "test_user";
        let key = "6162636465666768"; // Hex representation of "abcdefgh"

        // Store the key
        key_management::set_legacy_key(target, key).unwrap();
        assert!(key_management::has_legacy_key(target));

        // Test listing keys
        let keys = key_management::list_legacy_keys();
        assert!(keys.contains(&target.to_string()));

        // Test removing a key
        key_management::remove_legacy_key(target).unwrap();
        assert!(!key_management::has_legacy_key(target));
    }

    #[test]
    fn test_legacy_encryption_with_stored_key() {
        // Test the complete workflow with key storage
        let target = "test_user";
        let plaintext = "This is a test message for legacy encryption";

        // Generate a shared secret (simulating DH1080 exchange)
        let keypair1 = dh1080::generate_dh1080_keypair().unwrap();
        let keypair2 = dh1080::generate_dh1080_keypair().unwrap();
        let shared_secret =
            dh1080::compute_dh1080_shared_secret(&keypair1.private_key(), &keypair2.public_key)
                .unwrap();

        // Convert the shared secret to hex for storage
        let shared_secret_hex = hex::encode(shared_secret.as_bytes());

        // Store the shared secret as a legacy key
        key_management::set_legacy_key(target, &shared_secret_hex).unwrap();

        // Encrypt the message using the stored key
        if key_management::has_legacy_key(target) {
            // Get the key bytes from the stored hex
            let key_bytes = hex::decode(&shared_secret_hex).unwrap();

            let encrypted = blowfish::encrypt_message(&key_bytes, plaintext, &[]).unwrap();

            // Decrypt the message using the same key
            let decrypted = blowfish::decrypt_message(&key_bytes, &encrypted, &[]).unwrap();

            // Verify the decrypted message matches the original
            assert_eq!(plaintext, decrypted);
        } else {
            panic!("Failed to retrieve stored key");
        }
    }

    #[test]
    fn test_dh1080_message_parsing() {
        // Test DH1080 message detection and parsing
        let init_message = "DH1080_INIT some_public_key_data";
        assert!(message_detection::is_dh1080_message(init_message));

        let message_type = message_detection::parse_dh1080_message_type(init_message).unwrap();
        assert_eq!(message_type, "INIT");

        let public_key = message_detection::extract_dh1080_public_key(init_message).unwrap();
        assert_eq!(public_key, "some_public_key_data");

        let finish_message = "DH1080_FINISH another_public_key";
        assert!(message_detection::is_dh1080_message(finish_message));

        let message_type = message_detection::parse_dh1080_message_type(finish_message).unwrap();
        assert_eq!(message_type, "FINISH");

        let public_key = message_detection::extract_dh1080_public_key(finish_message).unwrap();
        assert_eq!(public_key, "another_public_key");
    }

    #[test]
    fn test_legacy_topic_encryption_workflow() {
        // Test the complete topic encryption workflow
        let target = "#test_channel";
        let plaintext_topic = "This is a test topic for encryption";

        // Generate a shared secret (simulating DH1080 exchange)
        let keypair1 = dh1080::generate_dh1080_keypair().unwrap();
        let keypair2 = dh1080::generate_dh1080_keypair().unwrap();
        let shared_secret =
            dh1080::compute_dh1080_shared_secret(&keypair1.private_key(), &keypair2.public_key)
                .unwrap();

        // Convert the shared secret to hex for storage
        let shared_secret_hex = hex::encode(shared_secret.as_bytes());

        // Store the shared secret as a legacy key
        key_management::set_legacy_key(target, &shared_secret_hex).unwrap();

        // Encrypt the topic using the stored key
        if key_management::has_legacy_key(target) {
            // Get the key bytes from the stored hex
            let key_bytes = hex::decode(&shared_secret_hex).unwrap();

            // Encrypt the topic
            let encrypted = blowfish::encrypt_message(&key_bytes, plaintext_topic, &[]).unwrap();
            let encrypted_with_prefix = format!("+OK {}", encrypted);

            // Decrypt the topic using the same key
            let decrypted = blowfish::decrypt_message(&key_bytes, &encrypted, &[]).unwrap();

            // Verify the decrypted topic matches the original
            assert_eq!(plaintext_topic, decrypted);
        } else {
            panic!("Failed to retrieve stored key");
        }
    }

    #[test]
    fn test_topic_encryption_settings() {
        // Test storing and retrieving topic encryption settings
        let network = "test_network_unique_12345";
        let channel = "#test_channel_unique_67890";

        // Set topic encryption to enabled
        let result = set_encrypt_topic_setting(network, channel, true);
        assert!(result.is_ok());

        // Check if the setting was stored correctly
        let result = get_encrypt_topic_setting(network, channel);
        assert!(result.is_ok());
        assert!(result.unwrap());

        // Set topic encryption to disabled
        let result = set_encrypt_topic_setting(network, channel, false);
        assert!(result.is_ok());

        // Check if the setting was updated correctly
        let result = get_encrypt_topic_setting(network, channel);
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}
