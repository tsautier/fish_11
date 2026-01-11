//! Legacy compatibility tests for FiSH 10 integration
//!
//! These tests verify that the legacy FiSH 10 compatibility layer
//! works correctly with the new FiSH 11 architecture.

use fish_11::legacy;
use fish_11::unified_error::DllError;

fn clear_test_legacy_keys() {
    let keys = legacy::key_management::list_legacy_keys();
    for k in keys {
        let _ = legacy::key_management::remove_legacy_key(&k);
    }
}

fn setup_test_legacy_key(name: &str, key_bytes: &[u8]) {
    let hex = key_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    legacy::key_management::set_legacy_key(name, &hex).expect("failed to set test key");
}

#[test]
fn test_legacy_system_initialization() {
    // Initialize the legacy system
    legacy::init_legacy_system();

    // Verify that the legacy config is initialized
    let config = legacy::LEGACY_CONFIG.read();
    assert!(config.legacy_keys.read().is_empty()); // Should start empty
}

#[test]
fn test_legacy_key_management() {
    // Clear any existing keys
    clear_test_legacy_keys();

    // Test setting a key
    legacy::key_management::set_legacy_key("#test", "6162636465666768").unwrap();

    // Test that the key exists
    assert!(legacy::key_management::has_legacy_key("#test"));

    // Test listing keys
    let keys = legacy::key_management::list_legacy_keys();
    assert!(keys.contains(&String::from("#test")));

    // Test removing the key
    legacy::key_management::remove_legacy_key("#test").unwrap();
    assert!(!legacy::key_management::has_legacy_key("#test"));
}

#[test]
fn test_legacy_message_detection() {
    assert!(legacy::encryption::is_legacy_message("+OK abc123"));
    assert!(!legacy::encryption::is_legacy_message("Hello world"));
    assert!(!legacy::encryption::is_legacy_message("+FISH abc123"));
}

#[test]
fn test_password_to_key_conversion() {
    let key = legacy::key_management::password_to_key("testpassword");
    assert_eq!(key.len(), 16); // Should be 16 bytes (128 bits)
}

#[test]
fn test_legacy_encryption_format() {
    // Setup a test key
    setup_test_legacy_key("#test", b"testkey12345678");

    // Test encryption produces the right format
    let result = legacy::encryption::legacy_encrypt("#test", "Hello");
    assert!(result.is_ok());
    let encrypted = result.unwrap();
    assert!(encrypted.starts_with("+OK "));
}

#[test]
fn test_invalid_key_length() {
    let result = legacy::key_management::set_legacy_key("#test", "6162"); // Too short
    assert!(result.is_err());

    if let Err(DllError::LegacyError { context, cause }) = result {
        assert!(context.contains("Setting key"));
        assert!(cause.contains("Invalid key length"));
    } else {
        panic!("Expected LegacyError");
    }
}

#[test]
fn test_legacy_target_detection() {
    // Clear any existing keys
    clear_test_legacy_keys();

    // Test that a target without a key is not detected as legacy
    assert!(!legacy::is_legacy_target("#unknown"));

    // Setup a key
    setup_test_legacy_key("#legacy", b"testkey12345678");

    // Test that the target is now detected as legacy
    assert!(legacy::is_legacy_target("#legacy"));
}
