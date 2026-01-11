//! Blowfish encryption implementation for FiSH 10 compatibility
//!
//! This module provides the Blowfish encryption algorithm used by FiSH 10
//! for legacy compatibility purposes, with the custom base64 alphabet.

use crate::unified_error::DllError;
use blowfish::Blowfish;
use blowfish::cipher::{BlockDecrypt, BlockEncrypt, KeyInit};
use blowfish::cipher::generic_array::GenericArray;

/// FiSH 10 specific Base64 alphabet for encrypted messages
const FISH10_B64_ABC: &[u8] = b"./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// Encode into FiSH 10 specific Base64
fn fish10_b64_encode(data: &[u8]) -> String {
    let mut result = String::new();
    let mut i = 0;
    while i < data.len() {
        let mut left: u32 = (data[i] as u32) << 24;
        left |= (data[i+1] as u32) << 16;
        left |= (data[i+2] as u32) << 8;
        left |= data[i+3] as u32;

        let mut right: u32 = (data[i+4] as u32) << 24;
        right |= (data[i+5] as u32) << 16;
        right |= (data[i+6] as u32) << 8;
        right |= data[i+7] as u32;

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
    result
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
            let val = FISH10_B64_ABC.iter().position(|&x| x == bytes[i+j]).ok_or_else(|| {
                DllError::LegacyError {
                    context: "FiSH 10 Decoding".to_string(),
                    cause: "Invalid character in base64".to_string(),
                }
            })? as u32;
            right |= val << (j * 6);
        }
        for j in 0..6 {
            let val = FISH10_B64_ABC.iter().position(|&x| x == bytes[i+6+j]).ok_or_else(|| {
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
    let bf = blowfish::Blowfish::<byteorder::BigEndian>::new_from_slice(key).map_err(|e| DllError::LegacyError {
        context: "Blowfish init".to_string(),
        cause: format!("Invalid key: {}", e),
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

    Ok(fish10_b64_encode(&ciphertext))
}

/// Decrypt a message using Blowfish in ECB mode (FiSH 10 style)
pub fn decrypt_message(
    key: &[u8],
    ciphertext_b64: &str,
    _associated_data: &[u8],
) -> Result<String, DllError> {
    let bf = blowfish::Blowfish::<byteorder::BigEndian>::new_from_slice(key).map_err(|e| DllError::LegacyError {
        context: "Blowfish init".to_string(),
        cause: format!("Invalid key: {}", e),
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

    String::from_utf8(plaintext).map_err(|e| DllError::LegacyError {
        context: "UTF-8 conversion".to_string(),
        cause: format!("Invalid UTF-8 after decryption: {}", e),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_fish10_b64_roundtrip() {
        let data = b"12345678";
        let encoded = fish10_b64_encode(data);
        assert_eq!(encoded.len(), 12);
        let decoded = fish10_b64_decode(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_blowfish_roundtrip() {
        let key = b"secretkey";
        let text = "Hello FiSH!";
        let encrypted = encrypt_message(key, text, &[]).unwrap();
        let decrypted = decrypt_message(key, &encrypted, &[]).unwrap();
        assert_eq!(text, decrypted);
    }
}
