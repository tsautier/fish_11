//! Encrypted configuration file storage
//!
//! Provides functions for securely storing and loading configuration files
//! using the master key encryption system.

use crate::master_key::{
    encryption::{encrypt_data, decrypt_data, EncryptedBlob},
    derivation::derive_config_kek,
};
use std::path::PathBuf;

/// Header for encrypted configuration files
const ENCRYPTED_CONFIG_HEADER: &str = "# FiSH_11_ENCRYPTED_CONFIG_V1";

/// Encrypt configuration data using the master key
pub fn encrypt_config_data(
    data: &str,
    master_key: &[u8; 32],
) -> Result<Vec<u8>, String> {
    // Derive a config-specific encryption key
    let config_key = derive_config_kek(master_key);
    
    // Encrypt the data using random nonce (as per existing pattern)
    let encrypted_blob = encrypt_data(
        data.as_bytes(),
        &config_key,
        "config",
        0
    ).map_err(|e| format!("Config encryption failed: {}", e))?;
    
    // Convert to bytes for storage
    let encrypted_bytes = encrypted_blob.to_bytes();
    
    // Add header and encode as base64 for easier handling
    let base64_data = base64::encode(&encrypted_bytes);
    
    // Format: header + base64_encoded(encrypted_data)
    let result = format!("{}\n{}\n", ENCRYPTED_CONFIG_HEADER, base64_data);
    
    Ok(result.into_bytes())
}

/// Decrypt configuration data using the master key
pub fn decrypt_config_data(
    encrypted_data: &[u8],
    master_key: &[u8; 32],
) -> Result<String, String> {
    // Convert to string for parsing
    let content = String::from_utf8(encrypted_data.to_vec())
        .map_err(|e| format!("Invalid UTF-8 in encrypted config: {}", e))?;
    
    // Parse the header and encrypted data
    let lines: Vec<&str> = content.lines().collect();
    
    if lines.is_empty() || !lines[0].starts_with(ENCRYPTED_CONFIG_HEADER) {
        return Err("Invalid encrypted config header".to_string());
    }
    
    if lines.len() < 2 {
        return Err("Encrypted config file is malformed".to_string());
    }
    
    // Decode the base64 encrypted data
    let encrypted_b64 = lines[1];
    let encrypted_bytes = base64::decode(encrypted_b64)
        .map_err(|e| format!("Failed to decode base64: {}", e))?;
    
    // Parse the encrypted blob
    let encrypted_blob = EncryptedBlob::from_bytes(&encrypted_bytes)
        .ok_or_else(|| "Failed to parse encrypted blob".to_string())?;
    
    // Derive the config-specific decryption key
    let config_key = derive_config_kek(master_key);
    
    // Decrypt the data
    let decrypted_bytes = decrypt_data(&encrypted_blob, &config_key)
        .map_err(|e| format!("Config decryption failed: {}", e))?;
    
    // Convert to string
    let result = String::from_utf8(decrypted_bytes)
        .map_err(|e| format!("Invalid UTF-8 in decrypted config: {}", e))?;
    
    Ok(result)
}

/// Check if configuration data is encrypted
pub fn is_encrypted_config(data: &[u8]) -> bool {
    // Try to convert to string and check header
    if let Ok(content) = String::from_utf8(data.to_vec()) {
        content.lines().next().map_or(false, |line| {
            line.starts_with(ENCRYPTED_CONFIG_HEADER)
        })
    } else {
        false
    }
}

/// Get the default configuration file path
pub fn get_config_path() -> Result<PathBuf, String> {
    use std::env;
    
    match env::var("MIRCDIR") {
        Ok(mirc_path) => {
            let mut path = PathBuf::from(mirc_path);
            path.push("fish_11.ini");
            Ok(path)
        }
        Err(_) => {
            // Fallback to current directory
            match std::env::current_dir() {
                Ok(mut path) => {
                    path.push("fish_11.ini");
                    Ok(path)
                }
                Err(e) => Err(format!("Failed to get current directory: {}", e)),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let test_data = "[FiSH11]\nprocess_incoming=true\nplain_prefix=+p ";
        let master_key = [42u8; 32]; // Test key
        
        // Encrypt
        let encrypted = encrypt_config_data(test_data, &master_key).unwrap();
        
        // Verify it's encrypted (has header)
        assert!(is_encrypted_config(&encrypted));
        
        // Decrypt
        let decrypted = decrypt_config_data(&encrypted, &master_key).unwrap();
        
        // Verify roundtrip
        assert_eq!(decrypted, test_data);
    }
    
    #[test]
    fn test_encrypted_config_detection() {
        let plain_data = b"[FiSH11]\nkey=value";
        let encrypted_data = b"# FiSH_11_ENCRYPTED_CONFIG_V1\nabc123";
        
        assert!(!is_encrypted_config(plain_data));
        assert!(is_encrypted_config(encrypted_data));
    }
    
    #[test]
    fn test_invalid_encrypted_data() {
        let invalid_data = b"invalid header\nabc123";
        let master_key = [42u8; 32];
        
        let result = decrypt_config_data(invalid_data, &master_key);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid encrypted config header"));
    }
}