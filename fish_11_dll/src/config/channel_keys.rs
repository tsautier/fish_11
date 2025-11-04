//! Manages channel-specific symmetric keys in the configuration.

use crate::config::config_access::{with_config, with_config_mut};
use crate::error::{FishError, Result};
use crate::utils::base64_encode;

pub fn set_channel_key(channel_name: &str, key: &[u8; 32]) -> Result<()> {
    if !channel_name.starts_with('#') {
        return Err(FishError::InvalidInput(
            "channel_name must start with #".to_string(),
        ));
    }

    with_config_mut(|config| {
        let b64_key = base64_encode(key);
        config.channel_keys.insert(channel_name.to_string(), b64_key);
        Ok(())
    })
}

pub fn get_channel_key(channel_name: &str) -> Result<[u8; 32]> {
    if !channel_name.starts_with('#') {
        return Err(FishError::InvalidInput(
            "channel_name must start with #".to_string(),
        ));
    }

    with_config(|config| {
        config
            .channel_keys
            .get(channel_name)
            .ok_or_else(|| FishError::KeyNotFound(channel_name.to_string()))
            .and_then(|b64_key| {
                let key_bytes = crate::utils::base64_decode(b64_key)?;
                key_bytes.try_into().map_err(|_|
                    FishError::ConfigError("Invalid key length for channel".to_string())
                )
            })
    })
}
