use chrono::Local;
use secrecy::ExposeSecret;

use crate::config::config_access::{with_config, with_config_mut};
use crate::config::models::{EntryData, FishConfig};
use crate::config::networks;
use crate::crypto;
use crate::error::{FishError, Result};
use crate::log_debug;
use crate::unified_error::{DllError, DllResult};
use crate::utils::{base64_decode, base64_encode, normalize_nick};
use chrono::NaiveDateTime;

use crate::log_info;

// ============================================================================
// TTL Configuration Constants
// ============================================================================
/// Minimum allowed TTL for exchange keys (1 hour)
/// Prevents too frequent re-keying which could impact performance and user experience
const MIN_KEY_TTL: i64 = 3600;

/// Maximum allowed TTL for exchange keys (7 days)
/// Ensures regular key rotation for security best practices
const MAX_KEY_TTL: i64 = 604800;

/// Grace period for clock drift when checking key expiration (5 minutes)
/// Allows tolerance for time synchronization issues between clients
const KEY_EXPIRY_GRACE_PERIOD: i64 = 300;

// ============================================================================
/// Represents the status and configuration of an encryption key for a specific user on a network.
///
/// This structure holds information about a key's current state, including whether it's
/// being used for key exchange, its validity, and its time-to-live (TTL) configuration.
///
/// # Fields
///
/// * `nickname` - The nickname/username associated with this key
/// * `network` - The network identifier where this key is used
/// * `is_exchange` - Indicates if this key is currently being used for a key exchange operation
/// * `is_valid` - Indicates whether the key is valid and can be used for encryption/decryption
/// * `ttl` - Optional time-to-live in seconds. When `Some(value)`, the key will expire after
///   the specified duration. When `None`, the key has no expiration.
///
/// # Note
///
/// TTL configuration via INI file is currently unimplemented. This is placeholder
/// functionality for future development.
// ============================================================================

#[derive(Debug, Clone)]
pub struct KeyStatus {
    pub nickname: String,
    pub network: String,
    pub is_exchange: bool,
    pub is_valid: bool,
    pub ttl: Option<i64>,
}

// Internal lock-free helper functions
// ============================================================================
// These functions work with a provided &FishConfig or &mut FishConfig reference
// and do NOT acquire locks. They are used by the public functions to avoid
// nested lock acquisition which causes deadlocks.
// ============================================================================
//
/// Resolves the network name for a nickname with priority fallback.
/// Priority: explicitly provided > globally set > existing mapping for nick > "default"
fn resolve_network_name(
    config: &FishConfig,
    network: Option<&str>,
    normalized_nick: &str,
    check_existing_mapping: bool,
) -> String {
    match network {
        Some(net) => net.to_string(),
        None => {
            // Try to use the global current network first
            crate::get_current_network()
                .or_else(|| {
                    // If checking existing mapping is enabled, try to get network for nick
                    if check_existing_mapping {
                        networks::get_network_for_nick_internal(config, normalized_nick)
                    } else {
                        None
                    }
                })
                .unwrap_or_else(|| "default".to_string())
        }
    }
}

/// Resolves the network name without checking existing mapping (lock-free version).
/// Priority: explicitly provided > current global network > "default"
fn resolve_network_name_simple(network: Option<&str>) -> String {
    match network {
        Some(net) => net.to_string(),
        None => crate::get_current_network().unwrap_or_else(|| "default".to_string()),
    }
}

/// Internal: get a key from config without acquiring locks
fn get_key_internal(config: &FishConfig, nickname: &str, network: Option<&str>) -> Result<Vec<u8>> {
    let normalized_nick = normalize_nick(nickname);

    // Get the network name (using internal lock-free version)
    let network_name = match network {
        Some(net) => net.to_string(),
        None => match networks::get_network_for_nick_internal(config, &normalized_nick) {
            Some(net) => net,
            None => "default".to_string(),
        },
    };

    // Create the entry key to look for
    let entry_key = if normalized_nick.starts_with('#') {
        format!("{}@{}", normalized_nick, network_name)
    } else {
        format!("{}@{}", normalized_nick, network_name)
    };

    // Find the key
    if let Some(entry) = config.entries.get(&entry_key) {
        if let Some(ref key_str) = entry.key {
            return base64_decode(key_str).map_err(FishError::from);
        }
    }

    // Fallback: if not found with specific network, try with @default
    if network_name != "default" {
        let default_entry_key = format!("{}@default", normalized_nick);
        if let Some(entry) = config.entries.get(&default_entry_key) {
            if let Some(ref key_str) = entry.key {
                log_debug!("Key found with fallback to @default for {}", normalized_nick);
                return base64_decode(key_str).map_err(FishError::from);
            }
        }
    }

    Err(FishError::KeyNotFound(normalized_nick))
}

// ============================================================================
// Public API functions - these acquire locks and call internal versions
// ============================================================================

/// Set a key for a nickname
pub fn set_key(
    nickname: &str,
    key: &[u8; 32],
    network: Option<&str>,
    overwrite: bool,
    is_exchange: bool,
) -> Result<()> {
    #[cfg(debug_assertions)]
    log_debug!(
        "set_key: Called with nickname='{}', network={:?}, overwrite={}, is_exchange={}",
        nickname,
        network,
        overwrite,
        is_exchange
    );

    let normalized_nick = normalize_nick(nickname);

    #[cfg(debug_assertions)]
    log_debug!("set_key: normalized nickname: '{}'", normalized_nick);

    // Validate network name if provided
    if let Some(net) = network {
        #[cfg(debug_assertions)]
        log_debug!("set_key: validating network name '{}'...", net);

        networks::validate_network_name(net)?;

        #[cfg(debug_assertions)]
        log_debug!("set_key: network name validated");
    }

    #[cfg(debug_assertions)]
    log_info!("set_key: calling with_config_mut...");

    with_config_mut(|config| {
        // Check for existing key if not overwriting
        if !overwrite {
            if config.keys.contains_key(&normalized_nick) {
                return Err(FishError::DuplicateEntry(normalized_nick.clone()));
            } // Check for existing entries in the proper network format if not overwriting
            let net = match network {
                Some(n) => n.to_string(),
                None => match networks::get_network_for_nick_internal(config, &normalized_nick) {
                    Some(n) => n,
                    None => ".".to_string(),
                },
            };

            let entry_key = format!("{}:{}", net, nickname);
            log_debug!("Checking for existing key with entry: {}", entry_key);

            if config.entries.contains_key(&entry_key) {
                return Err(FishError::DuplicateEntry(normalized_nick.clone()));
            }
        } // Create/update entry
        let now = Local::now();
        let date_str = now.format("%Y-%m-%d %H:%M:%S").to_string();

        // Use network name in the entry key format
        // Priority: explicitly provided > globally set > existing mapping > "default"
        let network_name = resolve_network_name(config, network, &normalized_nick, true);

        // Determine if this is a channel or user based on nickname starting with '#'
        let entry_key = if normalized_nick.starts_with('#') {
            format!("{}@{}", normalized_nick, network_name) // Format: #channel@network
        } else {
            format!("{}@{}", normalized_nick, network_name) // Format: nickname@network
        };

        log_debug!("Setting key for entry: {}", entry_key);

        let entry = EntryData {
            key: Some(base64_encode(key)),
            date: Some(date_str),
            is_exchange: Some(is_exchange),
        };

        // Check for existing entry if not overwriting
        if !overwrite && config.entries.contains_key(&entry_key) {
            return Err(FishError::DuplicateEntry(entry_key));
        }

        config.entries.insert(entry_key, entry);
        Ok(())
    })?;

    // Determine which network to use for the mapping
    // Priority: explicitly provided > current global network > default
    let mapping_network = resolve_network_name_simple(network);

    // Update network mapping with the network that was actually used
    // This ensures the mapping is always kept in sync with the entry format
    networks::set_network_for_nick(&normalized_nick, &mapping_network)?;

    Ok(())
}

/// Get a key for a nickname - simplified without legacy handling
pub fn get_key(nickname: &str, network: Option<&str>) -> Result<Vec<u8>> {
    with_config(|config| get_key_internal(config, nickname, network))
}

/// Delete a key for a nickname
pub fn delete_key(nickname: &str, network: Option<&str>) -> Result<()> {
    let normalized_nick = normalize_nick(nickname);

    // Determine if we should remove network mapping after deletion
    let should_remove_network = network.is_none();

    with_config_mut(|config| {
        // Get network info (using internal lock-free version)
        let network_name = match network {
            Some(net) => net.to_string(),
            None => match networks::get_network_for_nick_internal(config, &normalized_nick) {
                Some(net) => net,
                None => "default".to_string(),
            },
        };

        // Try to remove the key in the new format
        let entry_key = if normalized_nick.starts_with('#') {
            format!("{}@{}", normalized_nick, network_name)
        } else {
            format!("{}@{}", normalized_nick, network_name)
        };

        log_debug!("Attempting to delete key with entry: {}", entry_key);

        let entry_removed = config.entries.remove(&entry_key).is_some();
        // Remove from keys map too if present
        let key_removed = config.keys.remove(&normalized_nick).is_some();

        // Remove network mapping if no network was explicitly provided
        if should_remove_network && networks::has_network_internal(config, &normalized_nick) {
            config.nick_networks.remove(&normalized_nick);
        }

        if entry_removed || key_removed {
            log_debug!("Successfully removed key for {}", normalized_nick);
            Ok(())
        } else {
            log_debug!("Key not found for {} in any format", normalized_nick);
            Err(FishError::KeyNotFound(normalized_nick))
        }
    })?;

    Ok(())
}

/// Get the time-to-live (TTL) for a key in seconds.
///
/// Returns:
/// - `Ok(Some(seconds))` - Time remaining until expiration (0 if expired)
/// - `Ok(None)` - Key is not an exchange key (no TTL)
/// - `Err` - Key not found or other error
pub fn get_key_ttl(nickname: &str, network: Option<&str>) -> DllResult<Option<i64>> {
    // Get configured TTL instead of hardcoded value
    let key_lifetime_seconds = get_configured_key_ttl();
    let normalized_nick = normalize_nick(nickname);

    let result = with_config(|config| {
        let network_name = resolve_network_name(config, network, &normalized_nick, true);
        let entry_key = format!("{}@{}", normalized_nick, network_name);

        if let Some(entry) = config.entries.get(&entry_key) {
            if entry.is_exchange != Some(true) {
                return Ok(None); // Not an exchange key, no TTL
            }

            if let Some(date_str) = &entry.date {
                match NaiveDateTime::parse_from_str(date_str, "%Y-%m-%d %H:%M:%S") {
                    Ok(key_date) => {
                        let now = Local::now().naive_local();
                        let duration = now.signed_duration_since(key_date);
                        let elapsed_seconds = duration.num_seconds();

                        // Add grace period to account for clock drift
                        let remaining_seconds =
                            key_lifetime_seconds + KEY_EXPIRY_GRACE_PERIOD - elapsed_seconds;

                        if remaining_seconds > 0 {
                            return Ok(Some(remaining_seconds));
                        } else {
                            return Ok(Some(0)); // Expired
                        }
                    }
                    Err(_) => Ok(None), // Date parsing failed, treat as no TTL
                }
            } else {
                Ok(None) // No date, no TTL
            }
        } else {
            Err(FishError::KeyNotFound(normalized_nick.to_string()))
        }
    });
    result.map_err(DllError::from)
}

/// Get the time-to-live (TTL) for a key in a human-readable format.
///
/// Returns:
/// - `Ok(String)` - Human-readable TTL description
/// - `Err` - Key not found or other error
pub fn get_key_ttl_human_readable(nickname: &str, network: Option<&str>) -> DllResult<String> {
    let ttl = get_key_ttl(nickname, network)?;

    match ttl {
        Some(0) => Ok("EXPIRED".to_string()),
        Some(seconds) => {
            let hours = seconds / 3600;
            let minutes = (seconds % 3600) / 60;
            if hours > 0 {
                Ok(format!("{}h {}m", hours, minutes))
            } else {
                Ok(format!("{}m", minutes))
            }
        }
        None => Ok("NO_TTL".to_string()),
    }
}

/// Get the configured TTL for exchange keys (in seconds).
///
/// This function reads the TTL from the configuration file, defaulting to 24 hours.
/// The TTL can be configured in `fish_11.ini` under the `[fish11]` section with the key `key_ttl`.
///
/// # Configuration Example
/// ```ini
/// [fish11]
/// key_ttl=86400  ; 24 hours in seconds
/// ```
///
/// # Returns
/// - Configured TTL value if found and valid (>= 3600 and <= 604800)
/// - Default value of 86400 seconds (24 hours) if not configured or invalid
///
/// # Valid Range
/// - Minimum: 3600 seconds (1 hour) - prevents too frequent re-keying
/// - Maximum: 604800 seconds (7 days) - ensures regular key rotation for security
pub fn get_configured_key_ttl() -> i64 {
    const DEFAULT_TTL: i64 = 86400; // 24 hours
    const MIN_TTL: i64 = 3600; // 1 hour minimum
    const MAX_TTL: i64 = 604800; // 7 days maximum

    let result = with_config(|config| {
        // Read key_ttl from fish11 section, defaulting to 24 hours
        Ok(config.fish11.key_ttl.unwrap_or(DEFAULT_TTL))
    });

    match result {
        Ok(ttl) => {
            // Validate TTL is within acceptable range
            if ttl < MIN_TTL {
                log_debug!(
                    "Configured TTL ({}) is below minimum ({}), using minimum",
                    ttl,
                    MIN_TTL
                );
                MIN_TTL
            } else if ttl > MAX_TTL {
                log_debug!("Configured TTL ({}) exceeds maximum ({}), using maximum", ttl, MAX_TTL);
                MAX_TTL
            } else {
                ttl
            }
        }
        Err(e) => {
            log_debug!("Failed to read TTL config: {}, using default ({})", e, DEFAULT_TTL);
            DEFAULT_TTL
        }
    }
}

/// Set the TTL for exchange keys (in seconds).
///
/// This function updates the `key_ttl` setting in the `[fish11]` section of the configuration file.
/// The value is validated to be within the allowed range and persisted immediately.
///
/// # Arguments
///
/// * `ttl_seconds` - The new TTL value in seconds.
///
/// # Valid Range
/// - Minimum: 3600 seconds (1 hour) - prevents too frequent re-keying
/// - Maximum: 604800 seconds (7 days) - ensures regular key rotation for security
///
/// # Returns
/// - `Ok(())` - TTL successfully updated and saved
/// - `Err(DllError::InvalidInput)` - Value outside valid range
/// - `Err(DllError::ConfigError)` - Failed to save configuration
///
/// # Example
/// ```ignore
/// // Set TTL to 48 hours (172800 seconds)
/// set_configured_key_ttl(172800)?;
/// ```
pub fn set_configured_key_ttl(ttl_seconds: i64) -> DllResult<()> {
    log_debug!("Attempting to set configured key TTL to {} seconds", ttl_seconds);

    // Validate TTL is within acceptable range
    if ttl_seconds < MIN_KEY_TTL {
        log_debug!("Invalid TTL value: {}. Below minimum of {} seconds.", ttl_seconds, MIN_KEY_TTL);
        return Err(DllError::InvalidInput {
            param: "ttl_seconds".to_string(),
            reason: format!(
                "Value {} is below minimum. Must be at least {} seconds (1 hour).",
                ttl_seconds, MIN_KEY_TTL
            ),
        });
    }

    if ttl_seconds > MAX_KEY_TTL {
        log_debug!(
            "Invalid TTL value: {}. Exceeds maximum of {} seconds.",
            ttl_seconds,
            MAX_KEY_TTL
        );
        return Err(DllError::InvalidInput {
            param: "ttl_seconds".to_string(),
            reason: format!(
                "Value {} exceeds maximum. Must be at most {} seconds (7 days).",
                ttl_seconds, MAX_KEY_TTL
            ),
        });
    }

    with_config_mut(|config| {
        log_debug!("Setting config.fish11.key_ttl to Some({})", ttl_seconds);
        config.fish11.key_ttl = Some(ttl_seconds);
        config.mark_dirty();
        Ok(())
    })?;

    log_debug!("Successfully set and saved key TTL to {} seconds.", ttl_seconds);
    Ok(())
}

/// Check if a key is about to expire (within a configurable warning threshold).
///
/// Returns:
/// - `Ok(true)` - Key is about to expire (within 1 hour)
/// - `Ok(false)` - Key is not about to expire
/// - `Err` - Key not found or other error
pub fn is_key_about_to_expire(nickname: &str, network: Option<&str>) -> DllResult<bool> {
    const WARNING_THRESHOLD_SECONDS: i64 = 3600; // 1 hour warning threshold

    let ttl = get_key_ttl(nickname, network)?;

    match ttl {
        Some(seconds) => {
            // If seconds is 0 or negative, the key is expired
            if seconds <= WARNING_THRESHOLD_SECONDS { Ok(true) } else { Ok(false) }
        }
        None => Ok(false), // Not an exchange key, no TTL
    }
}

/// Get detailed key status information.
///
/// Returns:
/// - `Ok(KeyStatus)` - Detailed status information
/// - `Err` - Key not found or other error
pub fn get_key_status(nickname: &str, network: Option<&str>) -> DllResult<KeyStatus> {
    let normalized_nick = normalize_nick(nickname);

    let result = with_config(|config| {
        let network_name = resolve_network_name(config, network, &normalized_nick, true);
        let entry_key = format!("{}@{}", normalized_nick, network_name);

        if let Some(entry) = config.entries.get(&entry_key) {
            let is_exchange = entry.is_exchange == Some(true);
            let is_valid = is_exchange; // For now, we consider exchange keys as valid

            let ttl = if is_exchange {
                match get_key_ttl(nickname, network) {
                    Ok(Some(seconds)) => Some(seconds),
                    Ok(None) => None,
                    Err(_) => None,
                }
            } else {
                None
            };

            Ok(KeyStatus {
                nickname: normalized_nick.to_string(),
                network: network_name,
                is_exchange,
                is_valid,
                ttl,
            })
        } else {
            Err(FishError::KeyNotFound(normalized_nick.to_string()))
        }
    });
    result.map_err(DllError::from)
}

/// Get key status in a human-readable format.
///
/// Returns:
/// - `Ok(String)` - Human-readable status description
/// - `Err` - Key not found or other error
pub fn get_key_status_human_readable(nickname: &str, network: Option<&str>) -> DllResult<String> {
    let status = get_key_status(nickname, network)?;

    let mut parts = vec![];

    if status.is_exchange {
        parts.push("exchange key".to_string());
    } else {
        parts.push("manual key".to_string());
    }

    if let Some(ttl) = status.ttl {
        if ttl <= 0 {
            parts.push("expired".to_string());
        } else {
            let hours = ttl / 3600;
            let minutes = (ttl % 3600) / 60;
            if hours > 0 {
                parts.push(format!("expires in {}h {}m", hours, minutes));
            } else {
                parts.push(format!("expires in {}m", minutes));
            }
        }
    }

    Ok(parts.join(", "))
}

/// Get all keys with their TTL information.
///
/// Returns:
/// - `Ok(Vec<KeyInfo>)` - List of all keys with their information
pub fn get_all_keys_with_ttl() -> DllResult<Vec<KeyInfo>> {
    let mut keys_info = Vec::new();

    let result = with_config(|config| {
        for (entry_key, entry) in &config.entries {
            // Parse nickname and network from the entry key
            let (nickname, network) = if let Some(at_pos) = entry_key.find('@') {
                let nick = &entry_key[..at_pos];
                let net = &entry_key[at_pos + 1..];
                (nick.to_string(), net.to_string())
            } else {
                // Fallback for keys without network
                (entry_key.clone(), "default".to_string())
            };

            let is_exchange = entry.is_exchange == Some(true);
            let ttl = if is_exchange {
                match get_key_ttl(&nickname, Some(&network)) {
                    Ok(Some(seconds)) => Some(seconds),
                    _ => None,
                }
            } else {
                None
            };

            keys_info.push(KeyInfo { nickname, network, is_exchange, ttl });
        }
        Ok(())
    });
    result.map_err(DllError::from)?;

    Ok(keys_info)
}

/// Key information structure
#[derive(Debug, Clone)]
pub struct KeyInfo {
    pub nickname: String,
    pub network: String,
    pub is_exchange: bool,
    pub ttl: Option<i64>, // Time to live in seconds
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

                    log_debug!(
                        "Found key for {} on network {} ({})",
                        name_part,
                        network,
                        if is_channel { "channel" } else { "user" }
                    );
                }
            }
        }

        log_debug!("list_keys: Found {} total keys", result.len());
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

/// Check if a key has expired and delete it if it has.
pub fn check_key_expiry(nickname: &str, network: Option<&str>) -> DllResult<()> {
    // Get configured TTL instead of hardcoded value
    let key_lifetime_seconds = get_configured_key_ttl();
    let normalized_nick = normalize_nick(nickname);

    // This closure returns Ok(true) if a key was expired, Ok(false) otherwise.
    let was_expired = with_config_mut(|config| {
        // Use the simpler resolution method for consistency
        let network_name = resolve_network_name_simple(network);
        let entry_key = format!("{}@{}", normalized_nick, network_name);

        if let Some(entry) = config.entries.get(&entry_key) {
            if entry.is_exchange != Some(true) {
                return Ok(false);
            }

            if let Some(date_str) = &entry.date {
                if let Ok(key_date) = NaiveDateTime::parse_from_str(date_str, "%Y-%m-%d %H:%M:%S") {
                    let now = Local::now().naive_local();
                    let duration = now.signed_duration_since(key_date);

                    // Add grace period to account for clock drift
                    if duration.num_seconds() > key_lifetime_seconds + KEY_EXPIRY_GRACE_PERIOD {
                        log_debug!(
                            "Key for '{}' on network '{}' has expired (age: {}s). Deleting.",
                            normalized_nick,
                            network_name,
                            duration.num_seconds()
                        );
                        // Key has expired, remove it and signal that it was expired.
                        config.entries.remove(&entry_key);
                        config.keys.remove(&normalized_nick);
                        config.nick_networks.remove(&normalized_nick);
                        return Ok(true);
                    }
                }
            }
        }
        Ok(false)
    })
    .map_err(DllError::from)?;

    if was_expired {
        Err(DllError::KeyExpired { nickname: normalized_nick.to_string() })
    } else {
        Ok(())
    }
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
    set_key(nickname, key, Some("default"), overwrite, false)
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

        set_key(nickname1, &key1, Some("testnet"), true, false).expect("Failed to set key 1");
        set_key(nickname2, &key2, Some("testnet"), true, false).expect("Failed to set key 2");

        let keys = list_keys().expect("Failed to list keys");

        let found1 = keys.iter().any(|(name, net, _, _)| name == nickname1 && net == "testnet");
        let found2 = keys.iter().any(|(name, net, _, _)| name == nickname2 && net == "testnet");

        assert!(found1, "Key for user 1 not found in list");
        assert!(found2, "Key for channel 1 not found in list");

        // Cleanup
        delete_key(nickname1, Some("testnet")).ok();
        delete_key(nickname2, Some("testnet")).ok();
    }

    #[test]
    fn test_get_key_ttl() {
        // Tests getting TTL for a key
        let nickname = "ttl_test_user";
        let key = random_key();

        // Set a key with exchange flag
        set_key(nickname, &key, Some("testnet"), true, true).expect("Failed to set key");

        // Check that TTL is returned
        let ttl = get_key_ttl(nickname, Some("testnet")).expect("Failed to get TTL");
        assert!(ttl.is_some());
        assert!(ttl.unwrap() > 0);

        // Cleanup
        delete_key(nickname, Some("testnet")).ok();
    }

    #[test]
    fn test_get_key_ttl_human_readable() {
        // Tests getting human-readable TTL for a key
        let nickname = "ttl_readable_test_user";
        let key = random_key();

        // Set a key with exchange flag
        set_key(nickname, &key, Some("testnet"), true, true).expect("Failed to set key");

        // Check that human-readable TTL is returned
        let ttl = get_key_ttl_human_readable(nickname, Some("testnet")).expect("Failed to get TTL");
        assert!(!ttl.is_empty());

        // Cleanup
        delete_key(nickname, Some("testnet")).ok();
    }

    #[test]
    fn test_key_expiry() {
        // Tests key expiry functionality
        let nickname = "expiry_test_user";
        let key = random_key();

        // Set a key with exchange flag
        set_key(nickname, &key, Some("testnet"), true, true).expect("Failed to set key");

        // Check that key is not expired
        let result = check_key_expiry(nickname, Some("testnet"));
        assert!(result.is_ok());

        // Cleanup
        delete_key(nickname, Some("testnet")).ok();
    }

    #[test]
    fn test_key_status() {
        // Tests getting key status
        let nickname = "status_test_user";
        let key = random_key();

        // Set a key with exchange flag
        set_key(nickname, &key, Some("testnet"), true, true).expect("Failed to set key");

        // Check that key status is returned
        let status = get_key_status(nickname, Some("testnet")).expect("Failed to get key status");
        assert_eq!(status.nickname, nickname);
        assert!(status.is_exchange);
        assert!(status.is_valid);

        // Test human-readable status
        let human_readable = get_key_status_human_readable(nickname, Some("testnet"))
            .expect("Failed to get human-readable status");
        assert!(!human_readable.is_empty());

        // Cleanup
        delete_key(nickname, Some("testnet")).ok();
    }

    #[test]
    fn test_get_all_keys_with_ttl() {
        // Tests getting all keys with TTL
        let nickname = "all_keys_test_user";
        let key = random_key();

        // Set a key with exchange flag
        set_key(nickname, &key, Some("testnet"), true, true).expect("Failed to set key");

        // Check that all keys are returned
        let all_keys = get_all_keys_with_ttl().expect("Failed to get all keys");
        assert!(!all_keys.is_empty());

        // Cleanup
        delete_key(nickname, Some("testnet")).ok();
    }
}
