//! Key rotation module for master key system
//!
//! Provides automatic key rotation based on volume, message count, and time limits.

use super::keystore::KeyMetadata;

/// Rotation policy limits
pub const MAX_MESSAGES_PER_KEY: u64 = 1_000_000; // 1M messages
pub const MAX_DATA_SIZE_PER_KEY: u64 = 100 * 1024 * 1024 * 1024; // 100GB
pub const MAX_KEY_AGE_SECONDS: u64 = 90 * 24 * 60 * 60; // 90 days

/// Rotation reason
#[derive(Debug, Clone, PartialEq)]
pub enum RotationReason {
    MessageLimit,
    DataSizeLimit,
    AgeLimit,
    Manual,
}

/// Check if a key should be rotated based on its metadata
///
/// # Arguments
/// * `metadata` - The key metadata to check
///
/// # Returns
/// * `Option<RotationReason>` - The reason for rotation, if any
pub fn should_rotate_key(metadata: &KeyMetadata) -> Option<RotationReason> {
    // Check message count limit
    if metadata.message_count >= MAX_MESSAGES_PER_KEY {
        return Some(RotationReason::MessageLimit);
    }

    // Check data size limit
    if metadata.data_size_bytes >= MAX_DATA_SIZE_PER_KEY {
        return Some(RotationReason::DataSizeLimit);
    }

    // Check age limit
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    
    let age = now.saturating_sub(metadata.created_at);
    if age >= MAX_KEY_AGE_SECONDS {
        return Some(RotationReason::AgeLimit);
    }

    None
}

/// Calculate the percentage of usage for each limit
pub fn calculate_usage_percentages(metadata: &KeyMetadata) -> (f64, f64, f64) {
    let message_pct = (metadata.message_count as f64 / MAX_MESSAGES_PER_KEY as f64) * 100.0;
    let data_pct = (metadata.data_size_bytes as f64 / MAX_DATA_SIZE_PER_KEY as f64) * 100.0;
    
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let age = now.saturating_sub(metadata.created_at);
    let age_pct = (age as f64 / MAX_KEY_AGE_SECONDS as f64) * 100.0;

    (message_pct, data_pct, age_pct)
}

/// Generate a rotation warning message
pub fn rotation_warning_message(metadata: &KeyMetadata) -> Option<String> {
    let (msg_pct, data_pct, age_pct) = calculate_usage_percentages(metadata);
    
    // Warning threshold: 80%
    if msg_pct >= 80.0 || data_pct >= 80.0 || age_pct >= 80.0 {
        let mut warnings = Vec::new();
        
        if msg_pct >= 80.0 {
            warnings.push(format!("Message count: {:.1}%", msg_pct));
        }
        if data_pct >= 80.0 {
            warnings.push(format!("Data size: {:.1}%", data_pct));
        }
        if age_pct >= 80.0 {
            warnings.push(format!("Key age: {:.1}%", age_pct));
        }
        
        return Some(format!(
            "Key rotation approaching: {}. Consider rotating soon.",
            warnings.join(", ")
        ));
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rotation_message_limit() {
        let mut metadata = KeyMetadata::new(0);
        metadata.message_count = MAX_MESSAGES_PER_KEY + 1;

        assert_eq!(should_rotate_key(&metadata), Some(RotationReason::MessageLimit));
    }

    #[test]
    fn test_rotation_data_limit() {
        let mut metadata = KeyMetadata::new(0);
        metadata.data_size_bytes = MAX_DATA_SIZE_PER_KEY + 1;

        assert_eq!(should_rotate_key(&metadata), Some(RotationReason::DataSizeLimit));
    }

    #[test]
    fn test_rotation_age_limit() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let mut metadata = KeyMetadata::new(0);
        metadata.created_at = now - MAX_KEY_AGE_SECONDS - 1;

        assert_eq!(should_rotate_key(&metadata), Some(RotationReason::AgeLimit));
    }

    #[test]
    fn test_no_rotation_needed() {
        let metadata = KeyMetadata::new(0);
        assert_eq!(should_rotate_key(&metadata), None);
    }

    #[test]
    fn test_usage_percentages() {
        let mut metadata = KeyMetadata::new(0);
        metadata.message_count = MAX_MESSAGES_PER_KEY / 2; // 50%
        
        let (msg_pct, _data_pct, _age_pct) = calculate_usage_percentages(&metadata);
        assert!((msg_pct - 50.0).abs() < 0.1);
    }

    #[test]
    fn test_rotation_warning() {
        let mut metadata = KeyMetadata::new(0);
        metadata.message_count = (MAX_MESSAGES_PER_KEY as f64 * 0.85) as u64; // 85%
        
        let warning = rotation_warning_message(&metadata);
        assert!(warning.is_some());
        assert!(warning.unwrap().contains("Message count: 85.0%"));
    }
}
