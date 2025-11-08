//! Entry operations for configuration management

use chrono::Local;

use crate::config::config_access::{with_config, with_config_mut};
use crate::error::Result;
use crate::utils::base64_encode;

/// Get channel data
pub fn get_channel_data(
    channel: &str,
    network: &str,
) -> Result<Option<(Option<String>, Option<String>)>> {
    with_config(|config| {
        // Ensure channel starts with #
        let channel_name =
            if channel.starts_with('#') { channel } else { &format!("#{}", channel) };
        // Format: #channel@network
        let entry_key = format!("{}@{}", channel_name, network);

        if let Some(entry) = config.get_entry(&entry_key) {
            Ok(Some((entry.key.clone(), entry.date.clone())))
        } else {
            Ok(None)
        }
    })
}

/// Set channel data
pub fn set_channel_data(
    channel: &str,
    network: &str,
    key: Option<&[u8; 32]>,
    date: Option<&str>,
) -> Result<()> {
    with_config_mut(|config| {
        // Ensure channel starts with #
        let channel_name =
            if channel.starts_with('#') { channel } else { &format!("#{}", channel) };
        // Format: #channel@network
        let entry_key = format!("{}@{}", channel_name, network);

        let mut entry = config.get_entry(&entry_key).cloned().unwrap_or_default();

        if let Some(k) = key {
            entry.key = Some(base64_encode(k));
        }

        if let Some(d) = date {
            entry.date = Some(d.to_string());
        } else if entry.date.is_none() {
            // Set current date if none exists. Use ISO-like date/time format to include time
            // This mirrors the logging timestamp style used elsewhere in the project.
            let now = Local::now();
            entry.date = Some(now.format("%Y-%m-%d %H:%M:%S").to_string());
        }

        config.set_entry(entry_key, entry);
        Ok(())
    })
}

/// Get user data
pub fn get_user_data(
    username: &str,
    network: &str,
) -> Result<Option<(Option<String>, Option<String>)>> {
    with_config(|config| {
        // Format: nickname@network
        let entry_key = format!("{}@{}", username, network);

        if let Some(entry) = config.get_entry(&entry_key) {
            Ok(Some((entry.key.clone(), entry.date.clone())))
        } else {
            Ok(None)
        }
    })
}

/// Set user data
pub fn set_user_data(
    username: &str,
    network: &str,
    key: Option<&[u8; 32]>,
    date: Option<&str>,
) -> Result<()> {
    with_config_mut(|config| {
        // Format: nickname@network
        let entry_key = format!("{}@{}", username, network);

        let mut entry = config.get_entry(&entry_key).cloned().unwrap_or_default();

        if let Some(k) = key {
            entry.key = Some(base64_encode(k));
        }

        if let Some(d) = date {
            entry.date = Some(d.to_string());
        } else if entry.date.is_none() {
            // Set current date if none exists. Use ISO-like date/time format to include time
            // This mirrors the logging timestamp style used elsewhere in the project.
            let now = Local::now();
            entry.date = Some(now.format("%Y-%m-%d %H:%M:%S").to_string());
        }

        config.set_entry(entry_key, entry);
        Ok(())
    })
}

/// List all channel entries
pub fn list_channel_entries() -> Result<Vec<(String, String, Option<String>, Option<String>)>> {
    with_config(|config| {
        let mut result = Vec::new();

        // Find all entries with "#" prefix followed by "@" (channels)
        for (entry_key, entry) in config.entries.iter() {
            if let Some(at_pos) = entry_key.find('@') {
                let (name_part, network_part) = entry_key.split_at(at_pos);
                let network = &network_part[1..]; // Remove the '@'

                if name_part.starts_with('#') {
                    result.push((
                        name_part.to_string(),
                        network.to_string(),
                        entry.key.clone(),
                        entry.date.clone(),
                    ));
                }
            }
        }

        Ok(result)
    })
}

/// List all user entries
pub fn list_user_entries() -> Result<Vec<(String, String, Option<String>, Option<String>)>> {
    with_config(|config| {
        let mut result = Vec::new();

        // Find all entries without "#" prefix but with "@" (users)
        for (entry_key, entry) in config.entries.iter() {
            if let Some(at_pos) = entry_key.find('@') {
                let (name_part, network_part) = entry_key.split_at(at_pos);
                let network = &network_part[1..]; // Remove the '@'

                if !name_part.starts_with('#') {
                    result.push((
                        name_part.to_string(),
                        network.to_string(),
                        entry.key.clone(),
                        entry.date.clone(),
                    ));
                }
            }
        }

        Ok(result)
    })
}
