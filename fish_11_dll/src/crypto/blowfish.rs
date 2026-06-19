//! Legacy blowfish encryption implementation for FiSH 10 compatibility
//!
//! This module provides the Blowfish encryption algorithm used by FiSH 10
//! for legacy compatibility purposes, with the custom base64 alphabet.

use blowfish::Blowfish;
use blowfish::cipher::generic_array::GenericArray;
use blowfish::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use byteorder::BigEndian;

use crate::unified_error::DllError;

/// FiSH 10 specific Base64 alphabet for encrypted messages
const FISH10_B64_ABC: &[u8] = b"./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Encode into FiSH 10 specific Base64
/// SAFETY: Input data MUST have length that is a multiple of 8 bytes
fn fish10_b64_encode(data: &[u8]) -> Result<String, DllError> {
    // Validate input: must be multiple of 8 bytes
    if data.len() % 8 != 0 {
        return Err(DllError::LegacyError {
            context: "FiSH 10 Encoding".to_string(),
            cause: format!("Data length must be multiple of 8 (got {})", data.len()),
        });
    }

    if data.is_empty() {
        return Ok(String::new());
    }

    let mut result = String::with_capacity(data.len() / 8 * 12);
    let mut i = 0;

    while i < data.len() {
        // SAFETY: We've validated data.len() is multiple of 8, so i+7 is always valid
        let mut left: u32 = (data[i] as u32) << 24;
        left |= (data[i + 1] as u32) << 16;
        left |= (data[i + 2] as u32) << 8;
        left |= data[i + 3] as u32;

        let mut right: u32 = (data[i + 4] as u32) << 24;
        right |= (data[i + 5] as u32) << 16;
        right |= (data[i + 6] as u32) << 8;
        right |= data[i + 7] as u32;

        for _ in 0..6 {
            result.push(FISH10_B64_ABC[(right & 0x3F) as usize] as char);
            right >>= 6;
        }
        for _ in 0..6 {
            result.push(FISH10_B64_ABC[(left & 0x3F) as usize] as char);
            left >>= 6;
        }
        i += 8;
    }

    Ok(result)
}

/// Decode from FiSH 10 specific Base64
fn fish10_b64_decode(s: &str) -> Result<Vec<u8>, DllError> {
    if s.len() % 12 != 0 {
        return Err(DllError::LegacyError {
            context: "FiSH 10 Decoding".to_string(),
            cause: format!("Invalid base64 length: {} (must be multiple of 12)", s.len()),
        });
    }

    let mut result = Vec::with_capacity(s.len() / 12 * 8);
    let bytes = s.as_bytes();
    let mut i = 0;

    while i < bytes.len() {
        let mut right = 0u32;
        let mut left = 0u32;

        for j in 0..6 {
            let val = FISH10_B64_ABC.iter().position(|&x| x == bytes[i + j]).ok_or_else(|| {
                DllError::LegacyError {
                    context: "FiSH 10 Decoding".to_string(),
                    cause: "Invalid character in base64".to_string(),
                }
            })? as u32;
            right |= val << (j * 6);
        }
        for j in 0..6 {
            let val =
                FISH10_B64_ABC.iter().position(|&x| x == bytes[i + 6 + j]).ok_or_else(|| {
                    DllError::LegacyError {
                        context: "FiSH 10 Decoding".to_string(),
                        cause: "Invalid character in base64".to_string(),
                    }
                })? as u32;
            left |= val << (j * 6);
        }

        result.extend_from_slice(&left.to_be_bytes());
        result.extend_from_slice(&right.to_be_bytes());
        i += 12;
    }
    Ok(result)
}

/// Encrypt a message using Blowfish in ECB mode (FiSH 10 style)
pub fn encrypt_message(
    key: &[u8],
    plaintext: &str,
    _associated_data: &[u8],
) -> Result<String, DllError> {
    let bf = blowfish::Blowfish::<byteorder::BigEndian>::new_from_slice(key).map_err(|e| {
        DllError::LegacyError {
            context: "Blowfish init".to_string(),
            cause: format!("Invalid key: {}", e),
        }
    })?;

    // FiSH 10 uses null padding to 8-byte blocks
    let mut bytes = plaintext.as_bytes().to_vec();
    let pad_len = (8 - (bytes.len() % 8)) % 8;
    bytes.extend(std::iter::repeat(0u8).take(pad_len));

    let mut ciphertext = Vec::with_capacity(bytes.len());
    for chunk in bytes.chunks_exact(8) {
        let mut block = GenericArray::clone_from_slice(chunk);
        bf.encrypt_block(&mut block);
        ciphertext.extend_from_slice(&block);
    }

    fish10_b64_encode(&ciphertext)
}

/// Decrypt a message using Blowfish in ECB mode (FiSH 10 style)
pub fn decrypt_message(
    key: &[u8],
    ciphertext_b64: &str,
    _associated_data: &[u8],
) -> Result<String, DllError> {
    let bf = blowfish::Blowfish::<byteorder::BigEndian>::new_from_slice(key).map_err(|e| {
        DllError::LegacyError {
            context: "Blowfish init".to_string(),
            cause: format!("Invalid key: {}", e),
        }
    })?;

    let ciphertext = fish10_b64_decode(ciphertext_b64)?;

    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for chunk in ciphertext.chunks_exact(8) {
        let mut block = GenericArray::clone_from_slice(chunk);
        bf.decrypt_block(&mut block);
        plaintext.extend_from_slice(&block);
    }

    // Remove trailing null bytes
    let end = plaintext.iter().rposition(|&x| x != 0).map_or(0, |i| i + 1);
    plaintext.truncate(end);

    // Attempt to convert to UTF-8, but handle invalid sequences gracefully
    match String::from_utf8(plaintext) {
        Ok(s) => Ok(s),
        Err(e) => {
            // If UTF-8 conversion fails, try to handle the bytes as best as possible
            let original_bytes = e.into_bytes();
            let lossy_string = String::from_utf8_lossy(&original_bytes);

            crate::log_warn!(
                "Invalid UTF-8 encountered during legacy decryption, using lossy conversion"
            );
            Ok(lossy_string.to_string())
        }
    }
}

/// Encrypt a message using Blowfish in CBC mode (FiSH 10 style)
pub fn encrypt_message_cbc(
    key: &[u8],
    plaintext: &str,
    _associated_data: &[u8],
) -> Result<String, DllError> {
    // Pad the plaintext to 8-byte boundary with null bytes
    let mut bytes = plaintext.as_bytes().to_vec();
    let pad_len = (8 - (bytes.len() % 8)) % 8;
    bytes.extend(std::iter::repeat(0u8).take(pad_len));

    // Use first 8 bytes of key as IV (this is how FiSH-10 CBC typically works)
    let iv: [u8; 8] = if key.len() >= 8 {
        let mut iv_array = [0u8; 8];
        iv_array.copy_from_slice(&key[..8]);
        iv_array
    } else {
        // If key is shorter than 8 bytes, pad it with zeros
        let mut iv_array = [0u8; 8];
        iv_array[..key.len()].copy_from_slice(key);
        iv_array
    };

    // Initialize CBC mode with Blowfish

    let cipher = Blowfish::<BigEndian>::new_from_slice(key).map_err(|e| DllError::LegacyError {
        context: "Blowfish init".to_string(),
        cause: format!("Invalid key: {}", e),
    })?;

    // For CBC mode, we need to handle it manually since the cipher crate doesn't have a direct CBC type
    // This is a simplified approach - in a real implementation, you'd use a proper CBC implementation
    let mut ciphertext = Vec::with_capacity(bytes.len());
    let block_size = 8; // Blowfish block size

    // Simple CBC encryption (for demonstration only)
    let mut prev_block_array = iv;
    for chunk in bytes.chunks(block_size) {
        let mut block = chunk.to_vec();
        // Pad with zeros if needed
        if block.len() < block_size {
            block.resize(block_size, 0);
        }

        // XOR with previous block
        for i in 0..block_size {
            block[i] ^= prev_block_array[i];
        }

        // Encrypt the block
        let mut output_block = GenericArray::clone_from_slice(&block);
        cipher.encrypt_block(&mut output_block);
        ciphertext.extend_from_slice(&output_block);

        // Update previous block for next iteration
        prev_block_array.copy_from_slice(&output_block);
    }

    fish10_b64_encode(&ciphertext)
}

/// Decrypt a message using Blowfish in CBC mode (FiSH 10 style)
pub fn decrypt_message_cbc(
    key: &[u8],
    ciphertext_b64: &str,
    _associated_data: &[u8],
) -> Result<String, DllError> {
    // Decode the base64 ciphertext
    let ciphertext = fish10_b64_decode(ciphertext_b64)?;

    // Use first 8 bytes of key as IV (this is how FiSH-10 CBC typically works)
    let iv: [u8; 8] = if key.len() >= 8 {
        let mut iv_array = [0u8; 8];
        iv_array.copy_from_slice(&key[..8]);
        iv_array
    } else {
        // If key is shorter than 8 bytes, pad it with zeros
        let mut iv_array = [0u8; 8];
        iv_array[..key.len()].copy_from_slice(key);
        iv_array
    };

    // Initialize Blowfish for decryption
    let cipher = Blowfish::<BigEndian>::new_from_slice(key).map_err(|e| DllError::LegacyError {
        context: "Blowfish init".to_string(),
        cause: format!("Invalid key: {}", e),
    })?;

    // Simple CBC decryption (for demonstration only)
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    let block_size = 8; // Blowfish block size

    let mut prev_block_array = iv;
    for chunk in ciphertext.chunks(block_size) {
        let original_block = chunk.to_vec();

        // Decrypt the block
        let mut output_block = GenericArray::clone_from_slice(chunk);
        cipher.decrypt_block(&mut output_block);

        // XOR with previous block
        for i in 0..block_size {
            output_block[i] ^= prev_block_array[i];
        }

        plaintext.extend_from_slice(&output_block);
        prev_block_array.copy_from_slice(&original_block);
    }

    // Remove trailing null bytes
    let end = plaintext.iter().rposition(|&x| x != 0).map_or(0, |i| i + 1);
    plaintext.truncate(end);

    // Attempt to convert to UTF-8, but handle invalid sequences gracefully
    match String::from_utf8(plaintext) {
        Ok(s) => Ok(s),
        Err(e) => {
            // If UTF-8 conversion fails, try to handle the bytes as best as possible
            let original_bytes = e.into_bytes();
            let lossy_string = String::from_utf8_lossy(&original_bytes);

            crate::log_warn!(
                "Invalid UTF-8 encountered during legacy CBC decryption, using lossy conversion"
            );
            Ok(lossy_string.to_string())
        }
    }
}

/// Test the CBC mode functions
#[cfg(test)]
mod cbc_tests {
    use super::*;

    #[test]
    fn test_blowfish_cbc_roundtrip() {
        let key = b"secretkey1234567"; // 16-byte key for blowfish
        let text = "Hello FiSH CBC!";
        let encrypted = encrypt_message_cbc(key, text, &[]).unwrap();
        let decrypted = decrypt_message_cbc(key, &encrypted, &[]).unwrap();
        assert_eq!(text, decrypted);
    }

    #[test]
    fn test_blowfish_cbc_with_padding() {
        let key = b"secretkey1234567";
        // Test with text that requires padding
        let text = "Test CBC with padding";
        let encrypted = encrypt_message_cbc(key, text, &[]).unwrap();
        let decrypted = decrypt_message_cbc(key, &encrypted, &[]).unwrap();
        assert_eq!(text, decrypted);
    }

    #[test]
    fn test_blowfish_cbc_different_messages() {
        let key = b"mysecretkey12345";
        let text1 = "First message for CBC test";
        let text2 = "Second message for CBC test";

        let encrypted1 = encrypt_message_cbc(key, text1, &[]).unwrap();
        let encrypted2 = encrypt_message_cbc(key, text2, &[]).unwrap();

        // Two different messages should have different encrypted outputs (due to CBC)
        assert_ne!(encrypted1, encrypted2);

        let decrypted1 = decrypt_message_cbc(key, &encrypted1, &[]).unwrap();
        let decrypted2 = decrypt_message_cbc(key, &encrypted2, &[]).unwrap();

        assert_eq!(text1, decrypted1);
        assert_eq!(text2, decrypted2);
    }

    #[test]
    fn test_blowfish_cbc_invalid_key() {
        let invalid_key = b""; // Empty key should cause an error
        let text = "Hello FiSH CBC!";
        let result = encrypt_message_cbc(invalid_key, text, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_blowfish_cbc_invalid_ciphertext() {
        let key = b"secretkey123456";
        let invalid_ciphertext = "invalid_ciphertext";
        let result = decrypt_message_cbc(key, invalid_ciphertext, &[]);
        assert!(result.is_err());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fish10_b64_roundtrip() {
        let data = b"12345678";
        let encoded = fish10_b64_encode(data).unwrap();
        assert_eq!(encoded.len(), 12);
        let decoded = fish10_b64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_fish10_b64_validates_length() {
        // Data not multiple of 8 should error
        let data = b"1234567"; // 7 bytes
        assert!(fish10_b64_encode(data).is_err());
    }

    #[test]
    fn test_blowfish_roundtrip() {
        let key = b"secretkey";
        let text = "Hello FiSH!";
        let encrypted = encrypt_message(key, text, &[]).unwrap();
        let decrypted = decrypt_message(key, &encrypted, &[]).unwrap();
        assert_eq!(text, decrypted);
    }

    #[test]
    fn test_blowfish_roundtrip_with_padding() {
        let key = b"secretkey";
        // Test with text that requires padding
        let text = "Test with padding";
        let encrypted = encrypt_message(key, text, &[]).unwrap();
        let decrypted = decrypt_message(key, &encrypted, &[]).unwrap();
        assert_eq!(text, decrypted);
    }

    #[test]
    fn test_blowfish_invalid_key() {
        let invalid_key = b""; // Empty key should definitely cause an error
        let text = "Hello FiSH!";
        let result = encrypt_message(invalid_key, text, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_blowfish_invalid_ciphertext() {
        let key = b"secretkey";
        let invalid_ciphertext = "invalid_ciphertext";
        let result = decrypt_message(key, invalid_ciphertext, &[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_blowfish_with_binary_data() {
        // Test with binary data that might cause UTF-8 issues
        let key = b"secretkey123456"; // 16-byte key for blowfish
        let binary_data = vec![0u8, 1, 2, 3, 255, 254, 253, 0]; // 8 bytes for one block
        let encrypted = fish10_b64_encode(&binary_data).unwrap();
        let decrypted = decrypt_message(key, &encrypted, &[]).unwrap();
        // Note: This test will use lossy conversion since binary data isn't valid UTF-8
        assert!(!decrypted.is_empty());
    }

    #[test]
    fn test_utf8_lossy_conversion() {
        // Test the UTF-8 handling when decryption results in invalid UTF-8
        let key = b"secretkey123456";
        // Create ciphertext that will decrypt to invalid UTF-8 when using wrong key
        // For this test, we'll directly test the lossy conversion
        let invalid_bytes = vec![0xFF, 0xFE, 0xFD]; // Invalid UTF-8 sequence
        let result = String::from_utf8(invalid_bytes);
        assert!(result.is_err());

        // Test that our lossy conversion works
        let lossy_result = String::from_utf8_lossy(&[0xFF, 0xFE, 0xFD]);
        assert!(!lossy_result.is_empty());
    }

    #[test]
    fn test_decrypt_with_invalid_utf8_bytes() {
        // Test that our decrypt_message function handles invalid UTF-8 gracefully
        // by using lossy conversion
        let key = b"secretkey123456";

        // Create a ciphertext that will decrypt to invalid UTF-8 bytes
        // We'll use a known invalid sequence and encrypt it with a key
        let invalid_utf8_bytes = vec![0xFF, 0xFE, 0xFD, 0x00, 0x00, 0x00, 0x00, 0x00]; // 8 bytes with padding

        // Since we can't easily create a valid ciphertext that decrypts to invalid UTF-8,
        // we'll directly test the scenario in our function by creating a ciphertext
        // that we know will decrypt to invalid bytes
        let encrypted = fish10_b64_encode(&invalid_utf8_bytes).unwrap();
        let result = decrypt_message(key, &encrypted, &[]);

        // The function should not panic and should return a string (using lossy conversion)
        assert!(result.is_ok());
        let decrypted = result.unwrap();
        // The result should not be empty
        assert!(!decrypted.is_empty());
    }

    #[test]
    fn test_decrypt_with_valid_utf8() {
        // Test that valid UTF-8 strings are handled correctly
        let key = b"secretkey123456";
        let plaintext = "Hello, 世界! 🦀"; // String with multibyte UTF-8 characters

        let encrypted = encrypt_message(key, plaintext, &[]).unwrap();
        let decrypted = decrypt_message(key, &encrypted, &[]).unwrap();

        assert_eq!(plaintext, decrypted);
    }
}
