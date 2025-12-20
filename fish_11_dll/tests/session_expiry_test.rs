use chrono::{Duration, Local, NaiveDateTime};
use fish_11::config::config_access::{read_config, write_config};
use fish_11::config::models::EntryData;
use fish_11::config::{
    get_configured_key_ttl, get_key, get_key_status, key_management::KeyStatus,
    set_configured_key_ttl, set_key,
};
use fish_11::error::FishError;
use fish_11::utils::generate_random_bytes;
use std::thread;
use std::time::Duration as StdDuration;

#[test]
fn test_session_expiry() {
    // 1. Setup: Set a short TTL for testing (though we'll simulate time passage by modifying entry date)
    // We use the minimum allowed TTL to be safe, but we'll manually age the key
    let _ = set_configured_key_ttl(3600); // 1 hour

    let nickname = "expiry_test_user";
    let key_bytes = generate_random_bytes(32);
    let key: [u8; 32] = key_bytes.try_into().expect("Key length mismatch");

    // 2. Set an exchange key
    // is_exchange = true
    let result = set_key(nickname, &key, None, true, true);
    assert!(result.is_ok(), "Failed to set key: {:?}", result.err());

    // 3. Verify key is accessible initially
    let retrieved = get_key(nickname, None);
    assert!(retrieved.is_ok(), "Key should be accessible immediately");

    // 4. Manually age the key to simulate expiration
    // We need to modify the config directly to change the date
    {
        let mut guard = write_config().expect("Failed to acquire write lock");
        let config = guard.config_mut();

        // Find the entry for this user (using default network)
        // Note: set_key might use 'default' or resolved network.
        // Since we didn't specify network, it likely went to 'default' or current global.
        // We'll search for it.

        let mut found = false;

        for (key_string, entry) in config.entries.iter_mut() {
            if key_string.contains(nickname) {
                // Set date to 25 hours ago (expired, as default/min TTL is likely <= 24h)
                // 25 hours ago = Now - 25h
                let past_time = Local::now() - Duration::hours(25);
                entry.date = Some(past_time.format("%Y-%m-%d %H:%M:%S").to_string());
                found = true;
                break;
            }
        }
        assert!(found, "Could not find key entry to modify date");
        guard.save_if_modified().expect("Failed to save modified config");
    }

    // 5. Verify key is now expired
    let retrieved_expired = get_key(nickname, None);
    match retrieved_expired {
        Err(FishError::KeyExpired(_)) => {
            // Expected
        }
        Ok(_) => panic!("Key should have expired but was returned successfully"),
        Err(e) => panic!("Expected KeyExpired error, got: {:?}", e),
    }

    // 6. Set a FRESH key for the same user
    let new_key_bytes = generate_random_bytes(32);
    let new_key: [u8; 32] = new_key_bytes.try_into().expect("Key length mismatch");

    let result_new = set_key(nickname, &new_key, None, true, true);
    assert!(result_new.is_ok(), "Failed to set new key");

    // 7. Verify new key is accessible
    let retrieved_new = get_key(nickname, None);
    assert!(retrieved_new.is_ok(), "New fresh key should be accessible");
}

#[test]
fn test_manual_key_does_not_expire() {
    let nickname = "manual_key_user";
    let key_bytes = generate_random_bytes(32);
    let key: [u8; 32] = key_bytes.try_into().expect("Key length mismatch");

    // Set a MANUAL key (is_exchange = false)
    let result = set_key(nickname, &key, None, true, false);
    assert!(result.is_ok());

    // Manually age the key significantly
    {
        let mut guard = write_config().expect("Failed to acquire write lock");
        let config = guard.config_mut();

        for (key_string, entry) in config.entries.iter_mut() {
            if key_string.contains(nickname) {
                let past_time = Local::now() - Duration::days(365); // 1 year ago
                entry.date = Some(past_time.format("%Y-%m-%d %H:%M:%S").to_string());
                break;
            }
        }
        guard.save_if_modified().expect("Failed to save");
    }

    // Verify manual key is still accessible despite age
    let retrieved = get_key(nickname, None);
    assert!(retrieved.is_ok(), "Manual keys should not expire");
}
