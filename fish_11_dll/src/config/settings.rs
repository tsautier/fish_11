use std::time::{SystemTime, UNIX_EPOCH};

use chrono::{DateTime, Local, TimeZone};

use crate::config::Fish11Section;
use crate::config::config_access::{with_config, with_config_mut};
use crate::error::{FishError, Result};

/// Get a reference to the FiSH11 configuration section
pub fn get_fish11_config() -> Result<Fish11Section> {
    log::debug!("get_fish11_config: Calling with_config...");
    let result = with_config(|config| {
        log::debug!("get_fish11_config: Inside with_config closure, about to clone fish11 section...");
        let cloned = config.fish11.clone();
        log::debug!("get_fish11_config: fish11 section cloned successfully");
        Ok(cloned)
    });
    log::debug!("get_fish11_config: with_config returned, result={:?}", result.is_ok());
    result
}

/// Update the FiSH11 configuration section
pub fn update_fish11_config(fish11_config: Fish11Section) -> Result<()> {
    with_config_mut(|config| {
        config.fish11 = fish11_config;
        Ok(())
    })
}

/// Check if a message should be encrypted based on configuration
pub fn should_encrypt_message(is_notice: bool, is_action: bool) -> Result<bool> {
    with_config(|config| {
        if is_notice && !config.fish11.encrypt_notice {
            return Ok(false);
        }

        if is_action && !config.fish11.encrypt_action {
            return Ok(false);
        }

        Ok(true)
    })
}

/// Check if outgoing messages should be processed
pub fn should_process_outgoing() -> Result<bool> {
    with_config(|config| Ok(config.fish11.process_outgoing))
}

/// Check if incoming messages should be processed
pub fn should_process_incoming() -> Result<bool> {
    with_config(|config| Ok(config.fish11.process_incoming))
}

/// Get the plain text prefix
pub fn get_plain_prefix() -> Result<String> {
    with_config(|config| Ok(config.fish11.plain_prefix.clone()))
}

/// Get the encryption mark information
pub fn get_encryption_mark() -> Result<(u8, String)> {
    with_config(|config| Ok((config.fish11.mark_position, config.fish11.mark_encrypted.clone())))
}

/// Check if legacy Fish 10 compatibility is disabled
pub fn is_fish10_legacy_disabled() -> Result<bool> {
    with_config(|config| Ok(config.fish11.no_fish10_legacy))
}

/// Get the startup timestamp
pub fn get_startup_time() -> Result<u64> {
    with_config(|config| {
        config
            .startup_data
            .date
            .ok_or_else(|| FishError::ConfigError("No startup timestamp found".to_string()))
    })
}

/// Update the startup timestamp (usually called when the application starts)
pub fn update_startup_time() -> Result<()> {
    with_config_mut(|config| {
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

        config.startup_data.date = Some(now);
        Ok(())
    })
}

/// Get a human-readable string of the startup time
pub fn get_startup_time_formatted() -> Result<String> {
    with_config(|config| {
        let timestamp = config
            .startup_data
            .date
            .ok_or_else(|| FishError::ConfigError("No startup timestamp found".to_string()))?;

        // Convert timestamp to DateTime
        let dt = DateTime::from_timestamp(timestamp as i64, 0)
            .ok_or_else(|| FishError::ConfigError("Invalid timestamp".to_string()))?;
        let datetime: DateTime<Local> = Local.from_utc_datetime(&dt.naive_utc());

        // Format as a human-readable string
        Ok(datetime.format("%Y-%m-%d %H:%M:%S").to_string())
    })
}
