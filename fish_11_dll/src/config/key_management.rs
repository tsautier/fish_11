use chrono::Local;
use secrecy::ExposeSecret;

use crate::config::config_access::{with_config, with_config_mut};
use crate::config::models::EntryData;
use crate::config::networks;
use crate::crypto;
use crate::error::{FishError, Result};
use crate::utils::{base64_decode, base64_encode, normalize_nick};

/// Set a key for a nickname
pub fn set_key(
    nickname: &str,
    key: &[u8; 32],
    network: Option<&str>,
    overwrite: bool,
) -> Result<()> {
    #[cfg(debug_assertions)]
    log::info!("set_key: Called with nickname='{}', network={:?}, overwrite={}", nickname, network, overwrite);

    let normalized_nick = normalize_nick(nickname);

    #[cfg(debug_assertions)]
    log::info!("set_key: Normalized nickname: '{}'", normalized_nick);

    // Validate network name if provided
    if let Some(net) = network {
        #[cfg(debug_assertions)]
        log::info!("set_key: Validating network name '{}'...", net);

        networks::validate_network_name(net)?;

        #[cfg(debug_assertions)]
        log::info!("set_key: Network name validated");
    }

    #[cfg(debug_assertions)]
    log::info!("set_key: Calling with_config_mut...");

    with_config_mut(|config| {
        // Check for existing key if not overwriting
        if !overwrite {
            if config.keys.contains_key(&normalized_nick) {
                return Err(FishError::DuplicateEntry(normalized_nick.clone()));
            } // Check for existing entries in the proper network format if not overwriting
            let net = match network {
                Some(n) => n.to_string(),
                None => match networks::get_network_for_nick(&normalized_nick) {
                    Ok(Some(n)) => n,
                    _ => ".".to_string(),
                },
            };

            let entry_key = format!("{}:{}", net, nickname);
            log::debug!("Checking for existing key with entry: {}", entry_key);

            if config.entries.contains_key(&entry_key) {
                return Err(FishError::DuplicateEntry(normalized_nick.clone()));
            }
        } // Create/update entry
        let now = Local::now();
        let date_str = now.format("%d/%m/%Y").to_string();

        // Use network name in the entry key format or default to current network if not specified
        let network_name = network.unwrap_or("default");

        // Determine if this is a channel or user based on nickname starting with '#'
        let entry_key = if normalized_nick.starts_with('#') {
            format!("{}@{}", normalized_nick, network_name) // Format: #channel@network
        } else {
            format!("{}@{}", normalized_nick, network_name) // Format: nickname@network
        };

        log::debug!("Setting key for entry: {}", entry_key);

        let entry = EntryData { key: Some(base64_encode(key)), date: Some(date_str) };

        // Check for existing entry if not overwriting
        if !overwrite && config.entries.contains_key(&entry_key) {
            return Err(FishError::DuplicateEntry(entry_key));
        }

        config.entries.insert(entry_key, entry);
        Ok(())
    })?;

    // Update network mapping if provided (using our new networks module)
    if let Some(net) = network {
        networks::set_network_for_nick(&normalized_nick, net)?;
    }

    Ok(())
}

/// Get a key for a nickname - simplified without legacy handling
pub fn get_key(nickname: &str, network: Option<&str>) -> Result<Vec<u8>> {
    let normalized_nick = normalize_nick(nickname);

    // Get the network name
    let network_name = match network {
        Some(net) => net.to_string(),
        None => match networks::get_network_for_nick(&normalized_nick) {
            Ok(Some(net)) => net,
            Ok(None) => "default".to_string(),
            Err(_) => "default".to_string(),
        },
    };

    // Create the entry key to look for - format: nickname@network or #channel@network
    let entry_key = if normalized_nick.starts_with('#') {
        format!("{}@{}", normalized_nick, network_name)
    } else {
        format!("{}@{}", normalized_nick, network_name)
    };

    // Find the key
    with_config(|config| {
        if let Some(entry) = config.entries.get(&entry_key) {
            if let Some(ref key_str) = entry.key {
                return base64_decode(key_str).map_err(FishError::from);
            }
        }

        Err(FishError::KeyNotFound(normalized_nick))
    })
}

/// Delete a key for a nickname
pub fn delete_key(nickname: &str, network: Option<&str>) -> Result<()> {
    let normalized_nick = normalize_nick(nickname);

    // Get network info
    let network_name = match network {
        Some(net) => net.to_string(),
        None => match networks::get_network_for_nick(&normalized_nick) {
            Ok(Some(net)) => net,
            Ok(None) => "default".to_string(),
            Err(_) => "default".to_string(),
        },
    };

    // Remove the network mapping if no network was explicitly provided
    if network.is_none() && networks::has_network(&normalized_nick)? {
        networks::remove_network_for_nick(&normalized_nick)?;
    }

    with_config_mut(|config| {
        // Try to remove the key in the new format
        let entry_key = if normalized_nick.starts_with('#') {
            format!("{}@{}", normalized_nick, network_name)
        } else {
            format!("{}@{}", normalized_nick, network_name)
        };

        log::debug!("Attempting to delete key with entry: {}", entry_key);

        let entry_removed = config.entries.remove(&entry_key).is_some(); // Remove from keys map too if present
        let key_removed = config.keys.remove(&normalized_nick).is_some();

        if entry_removed || key_removed {
            log::debug!("Successfully removed key for {}", normalized_nick);
            Ok(())
        } else {
            log::debug!("Key not found for {} in any format", normalized_nick);
            Err(FishError::KeyNotFound(normalized_nick))
        }
    })
}

/// Get our keypair
pub fn get_our_keypair() -> Result<([u8; 32], [u8; 32])> {
    with_config(|config| {
        // Get the private key
        let private_key = match &config.our_private_key {
            Some(encoded) => {
                let bytes = base64_decode(encoded).map_err(|_| {
                    FishError::ConfigError("Invalid private key format".to_string())
                })?;

                if bytes.len() != 32 {
                    return Err(FishError::ConfigError("Invalid private key length".to_string()));
                }

                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                key
            }
            None => return Err(FishError::ConfigError("No private key stored".to_string())),
        };

        // Get the public key
        let public_key = match &config.our_public_key {
            Some(encoded) => {
                let bytes = base64_decode(encoded)
                    .map_err(|_| FishError::ConfigError("Invalid public key format".to_string()))?;

                if bytes.len() != 32 {
                    return Err(FishError::ConfigError("Invalid public key length".to_string()));
                }

                let mut key = [0u8; 32];
                key.copy_from_slice(&bytes);
                key
            }
            None => return Err(FishError::ConfigError("No public key stored".to_string())),
        };

        Ok((private_key, public_key))
    })
}

/// List all stored keys in the configuration
pub fn list_keys() -> Result<Vec<(String, String, Option<String>, Option<String>)>> {
    with_config(|config| {
        let mut result = Vec::new();

        // Process all entries in the new format: "nickname@network" or "#channel@network"
        for (entry_key, entry) in config.entries.iter() {
            // Skip entries without keys
            if entry.key.is_none() {
                continue;
            }

            // Check if this is the new format entry (contains @)
            if let Some(at_pos) = entry_key.find('@') {
                let (name_part, network_part) = entry_key.split_at(at_pos);
                let network = &network_part[1..]; // Remove the '@'

                if !name_part.is_empty() && !network.is_empty() {
                    let is_channel = name_part.starts_with('#');

                    result.push((
                        name_part.to_string(),
                        network.to_string(),
                        Some(if is_channel { "channel".to_string() } else { "user".to_string() }),
                        entry.date.clone(),
                    ));

                    log::debug!(
                        "Found key for {} on network {} ({})",
                        name_part,
                        network,
                        if is_channel { "channel" } else { "user" }
                    );
                }
            }
        }

        log::debug!("list_keys: Found {} total keys", result.len());
        Ok(result)
    })
}

/// Get our stored keypair, or generate a new one if none exists
pub fn get_keypair() -> Result<crypto::KeyPair> {
    // First try to get existing keypair
    let keypair_result = with_config(|config| {
        // If we have both keys, return them
        if let (Some(private_b64), Some(public_b64)) =
            (&config.our_private_key, &config.our_public_key)
        {
            let private_data = base64_decode(private_b64)?;
            let public_data = base64_decode(public_b64)?;

            if private_data.len() != 32 || public_data.len() != 32 {
                return Err(FishError::ConfigError("Invalid stored keypair".to_string()));
            }
            let mut private_key = [0u8; 32];
            let mut public_key = [0u8; 32];

            private_key.copy_from_slice(&private_data);
            public_key.copy_from_slice(&public_data);
            // Get approximate creation time from metadata or use current time
            let creation_time = match &config.keypair_creation_time {
                Some(time_str) => chrono::DateTime::parse_from_rfc3339(time_str)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now()),
                None => chrono::Utc::now(),
            };

            return Ok(Some(crypto::KeyPair {
                private_key: secrecy::Secret::new(private_key),
                public_key,
                creation_time,
            }));
        }

        // No keys found
        Ok(None)
    })?;

    // If we found a keypair, return it
    if let Some(keypair) = keypair_result {
        return Ok(keypair);
    }

    // Otherwise, generate a new keypair
    let keypair = crypto::generate_keypair();
    store_keypair(&keypair)?;

    Ok(keypair)
}

/// Store our keypair for future use
pub fn store_keypair(keypair: &crypto::KeyPair) -> Result<()> {
    with_config_mut(|config| {
        config.our_private_key = Some(base64_encode(keypair.private_key.expose_secret()));
        config.our_public_key = Some(base64_encode(&keypair.public_key));
        config.keypair_creation_time = Some(keypair.creation_time.to_rfc3339());
        Ok(())
    })
}

/// Get a key for a nickname using default network (backward compatibility)
pub fn get_key_default(nickname: &str) -> Result<Vec<u8>> {
    get_key(nickname, Some("default"))
}

/// Delete a key for a nickname using default network (backward compatibility)  
pub fn delete_key_default(nickname: &str) -> Result<()> {
    delete_key(nickname, Some("default"))
}

/// Set a key for a nickname using default network (backward compatibility)
pub fn set_key_default(nickname: &str, key: &[u8; 32], overwrite: bool) -> Result<()> {
    set_key(nickname, key, Some("default"), overwrite)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::FishError;
    use crate::utils::generate_random_bytes;

    // Helper to generate a random 32-byte key.
    fn random_key() -> [u8; 32] {
        generate_random_bytes(32).try_into().unwrap()
    }

    #[test]
    fn test_set_and_get_key() {
        // Tests adding a key and retrieving it.
        let nickname = "test_user_1";
        let key = random_key();

        set_key_default(nickname, &key, true).expect("Failed to set key");
        let retrieved_key = get_key_default(nickname).expect("Failed to get key");

        assert_eq!(key.to_vec(), retrieved_key);
        // Cleanup
        delete_key_default(nickname).ok();
    }

    #[test]
    fn test_get_non_existent_key() {
        // Tests that getting a non-existent key fails correctly.
        let nickname = "non_existent_user";
        let result = get_key_default(nickname);

        assert!(matches!(result, Err(FishError::KeyNotFound(_))));
    }

    #[test]
    fn test_delete_key() {
        // Tests deleting a key.
        let nickname = "test_user_to_delete";
        let key = random_key();

        set_key_default(nickname, &key, true).expect("Failed to set key");
        delete_key_default(nickname).expect("Failed to delete key");

        let result = get_key_default(nickname);
        assert!(matches!(result, Err(FishError::KeyNotFound(_))));
    }

    #[test]
    fn test_list_keys() {
        // Tests listing all available keys.
        let nickname1 = "list_user_1";
        let nickname2 = "#list_channel_1";
        let key1 = random_key();
        let key2 = random_key();

        set_key(nickname1, &key1, Some("testnet"), true).expect("Failed to set key 1");
        set_key(nickname2, &key2, Some("testnet"), true).expect("Failed to set key 2");

        let keys = list_keys().expect("Failed to list keys");

        let found1 = keys.iter().any(|(name, net, _, _)| name == nickname1 && net == "testnet");
        let found2 = keys.iter().any(|(name, net, _, _)| name == nickname2 && net == "testnet");

        assert!(found1, "Key for user 1 not found in list");
        assert!(found2, "Key for channel 1 not found in list");

        // Cleanup
        delete_key(nickname1, Some("testnet")).ok();
        delete_key(nickname2, Some("testnet")).ok();
    }
}
