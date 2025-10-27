//! Network management operations for FiSH 11

use std::collections::{HashMap, HashSet};

use crate::config::config_access::{with_config, with_config_mut};
use crate::error::Result;

/// Get the network associated with a nickname
///
/// # Arguments
/// * `nickname` - The nickname to look up
///
/// # Returns
/// * `Result<Option<String>>` - The network name if found, None otherwise
pub fn get_network_for_nick(nickname: &str) -> Result<Option<String>> {
    with_config(|config| Ok(config.nick_networks.get(nickname).cloned()))
}

/// Set the network for a nickname
///
/// # Arguments
/// * `nickname` - The nickname to associate with a network
/// * `network` - The network name
///
/// # Returns
/// * `Result<()>` - Success or failure
pub fn set_network_for_nick(nickname: &str, network: &str) -> Result<()> {
    with_config_mut(|config| {
        config.nick_networks.insert(nickname.to_string(), network.to_string());
        Ok(())
    })
}

/// Remove the network for a nickname
///
/// # Arguments
/// * `nickname` - The nickname to remove network association for
///
/// # Returns
/// * `Result<()>` - Success or failure
pub fn remove_network_for_nick(nickname: &str) -> Result<()> {
    with_config_mut(|config| {
        config.nick_networks.remove(nickname);
        Ok(())
    })
}

/// Get all networks
///
/// # Returns
/// * `Result<Vec<String>>` - A list of all unique networks
pub fn get_all_networks() -> Result<Vec<String>> {
    with_config(|config| {
        let networks: Vec<String> =
            config.nick_networks.values().cloned().collect::<HashSet<_>>().into_iter().collect();
        Ok(networks)
    })
}

/// Get all nicknames for a specific network
///
/// # Arguments
/// * `network` - The network name to look up nicknames for
///
/// # Returns
/// * `Result<Vec<String>>` - A list of nicknames associated with the network
pub fn get_nicknames_by_network(network: &str) -> Result<Vec<String>> {
    with_config(|config| {
        let nicknames: Vec<String> = config
            .nick_networks
            .iter()
            .filter(|(_, v)| v == &network)
            .map(|(k, _)| k.clone())
            .collect();
        Ok(nicknames)
    })
}

/// Get all nickname-network mappings
///
/// # Returns
/// * `Result<HashMap<String, String>>` - All nickname to network mappings
pub fn get_all_network_mappings() -> Result<HashMap<String, String>> {
    with_config(|config| Ok(config.nick_networks.clone()))
}

/// Clear all network mappings
///
/// # Returns
/// * `Result<()>` - Success or failure
pub fn clear_all_network_mappings() -> Result<()> {
    with_config_mut(|config| {
        config.nick_networks.clear();
        Ok(())
    })
}

/// Check if a nickname has a network assigned
///
/// # Arguments
/// * `nickname` - The nickname to check
///
/// # Returns
/// * `Result<bool>` - True if the nickname has a network assigned
pub fn has_network(nickname: &str) -> Result<bool> {
    with_config(|config| Ok(config.nick_networks.contains_key(nickname)))
}

/// Count how many nicknames are mapped to networks
///
/// # Returns
/// * `Result<usize>` - The count of nickname-network mappings
pub fn count_network_mappings() -> Result<usize> {
    with_config(|config| Ok(config.nick_networks.len()))
}

/// Count how many unique networks are used
///
/// # Returns
/// * `Result<usize>` - The count of unique networks
pub fn count_unique_networks() -> Result<usize> {
    with_config(|config| {
        let unique_networks: HashSet<_> = config.nick_networks.values().collect();
        Ok(unique_networks.len())
    })
}

/// Rename a network across all nickname mappings
///
/// # Arguments
/// * `old_name` - The current network name
/// * `new_name` - The new network name to use
///
/// # Returns
/// * `Result<usize>` - The number of nickname mappings updated
pub fn rename_network(old_name: &str, new_name: &str) -> Result<usize> {
    with_config_mut(|config| {
        let mut count = 0;

        for (_, network) in config.nick_networks.iter_mut() {
            if network == old_name {
                *network = new_name.to_string();
                count += 1;
            }
        }

        Ok(count)
    })
}

/// Delete all mappings for a specific network
///
/// # Arguments
/// * `network` - The network name to delete mappings for
///
/// # Returns
/// * `Result<usize>` - The number of nickname mappings removed
pub fn delete_network(network: &str) -> Result<usize> {
    with_config_mut(|config| {
        let nicknames_to_remove: Vec<String> = config
            .nick_networks
            .iter()
            .filter(|(_, v)| v == &network)
            .map(|(k, _)| k.clone())
            .collect();

        let count = nicknames_to_remove.len();

        for nickname in nicknames_to_remove {
            config.nick_networks.remove(&nickname);
        }

        Ok(count)
    })
}

/// Merge two networks, moving all nicknames from source to destination
///
/// # Arguments
/// * `source_network` - The source network name
/// * `destination_network` - The destination network name
///
/// # Returns
/// * `Result<usize>` - The number of nickname mappings updated
pub fn merge_networks(source_network: &str, destination_network: &str) -> Result<usize> {
    with_config_mut(|config| {
        let nicknames_to_update: Vec<String> = config
            .nick_networks
            .iter()
            .filter(|(_, v)| v == &source_network)
            .map(|(k, _)| k.clone())
            .collect();

        let count = nicknames_to_update.len();

        for nickname in nicknames_to_update {
            config.nick_networks.insert(nickname, destination_network.to_string());
        }

        Ok(count)
    })
}

/// Validate a network name to ensure it doesn't contain characters that would corrupt entry keys
///
/// # Arguments
/// * `name` - The network name to validate
///
/// # Returns
/// * `Result<()>` - Success if valid, Error if invalid
pub fn validate_network_name(name: &str) -> Result<()> {
    if name.contains(':') {
        return Err(crate::error::FishError::InvalidNetworkName(name.to_string()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Helper to ensure a clean state for tests.
    fn setup() {
        clear_all_network_mappings().expect("Failed to clear mappings");
    }

    #[test]
    fn test_set_and_get_network_for_nick() {
        // Tests setting and retrieving a network for a nickname.
        setup();
        let nickname = "test_nick";
        let network = "test_net";

        set_network_for_nick(nickname, network).expect("Failed to set network");
        let retrieved = get_network_for_nick(nickname).expect("Failed to get network").unwrap();

        assert_eq!(retrieved, network);
    }

    #[test]
    fn test_remove_network_for_nick() {
        // Tests removing a network association.
        setup();
        let nickname = "test_nick_2";
        let network = "test_net_2";

        set_network_for_nick(nickname, network).expect("Failed to set network");
        remove_network_for_nick(nickname).expect("Failed to remove network");

        let retrieved = get_network_for_nick(nickname).expect("Failed to get network");
        assert!(retrieved.is_none());
    }

    #[test]
    fn test_get_all_networks() {
        // Tests listing all unique networks.
        setup();
        set_network_for_nick("user1", "net1").unwrap();
        set_network_for_nick("user2", "net2").unwrap();
        set_network_for_nick("user3", "net1").unwrap();

        let mut networks = get_all_networks().unwrap();
        networks.sort();

        assert_eq!(networks, vec!["net1", "net2"]);
    }

    #[test]
    fn test_validate_network_name() {
        // Tests the validation of network names.
        assert!(validate_network_name("good-net").is_ok());
        let result = validate_network_name("bad:net");
        assert!(result.is_err());
        assert!(matches!(result, Err(crate::error::FishError::InvalidNetworkName(_))));
    }
}
