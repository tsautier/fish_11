//! DH1080 implementation for FiSH 10 compatibility
//!
//! This module provides the DH1080 key exchange protocol used by FiSH 10
//! for secure key exchange.

use crate::unified_error::DllError;
use num_bigint::{BigUint, RandomBits};
use num_traits::Num;
use rand::Rng;
use sha2::{Digest, Sha256};

/// DH1080 prime (1080-bit Sophie Germain prime)
const DH1080_PRIME_HEX: &str = "FBE1022E23D213E8ACFA9AE8B9DFADA3EA6B7AC7A7B7E95AB5EB2DF858921FEADE95E6AC7BE7DE6ADBAB8A783E7AF7A7FA6A2B7BEB1E72EAE2B72F9FA2BFB2A2EFBEFAC868BADB3E828FA8BADFADA3E4CC1BE7E8AFE85E9698A783EB68FA07A77AB6AD7BEB618ACF9CA2897EB28A6189EFA07AB99A8A7FA9AE299EFA7BA66DEAFEFBEFBF0B7D8B";

/// DH1080 generator
const DH1080_GENERATOR: u32 = 2;

/// FiSH 10 specific Base64 alphabet
const FISH10_B16_ABC: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const FISH10_B64_ABC: &[u8] = b"./0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";

/// FiSH 10 specific Base64 encoding for DH keys (1080 bits -> 135 bytes -> 180 chars + 'A')
pub fn dh1080_base64_encode(data: &[u8]) -> String {
    let mut result = String::with_capacity(181);
    let mut i = 0;
    while i < data.len() {
        let b1 = data[i] as u32;
        let b2 = if i + 1 < data.len() { data[i + 1] as u32 } else { 0 };
        let b3 = if i + 2 < data.len() { data[i + 2] as u32 } else { 0 };

        let triple = (b1 << 16) | (b2 << 8) | b3;

        result.push(FISH10_B16_ABC[((triple >> 18) & 0x3F) as usize] as char);
        result.push(FISH10_B16_ABC[((triple >> 12) & 0x3F) as usize] as char);
        if i + 1 < data.len() {
            result.push(FISH10_B16_ABC[((triple >> 6) & 0x3F) as usize] as char);
        }
        if i + 2 < data.len() {
            result.push(FISH10_B16_ABC[(triple & 0x3F) as usize] as char);
        }
        i += 3;
    }

    // FiSH 10 DH keys always end with 'A' and padding is stripped
    result + "A"
}

/// FiSH 10 specific Base64 decoding for DH keys
pub fn dh1080_base64_decode(b64: &str) -> Result<Vec<u8>, DllError> {
    let mut s = b64.to_string();
    if s.ends_with('A') {
        s.pop();
    }

    // Standard base64 decoding but with FISH10_B16_ABC
    // Since we don't have a library that takes a custom alphabet easily for this specific padded format,
    // we implement a simple one.
    let mut bytes = Vec::new();
    let mut current_val = 0u32;
    let mut bits_collected = 0;

    for c in s.chars() {
        let val = FISH10_B16_ABC.iter().position(|&x| x == c as u8).ok_or_else(|| {
            DllError::LegacyError {
                context: "DH1080 Decoding".to_string(),
                cause: format!("Invalid character in base64: {}", c),
            }
        })? as u32;

        current_val = (current_val << 6) | val;
        bits_collected += 6;

        if bits_collected >= 8 {
            bits_collected -= 8;
            bytes.push((current_val >> bits_collected) as u8);
            current_val &= (1 << bits_collected) - 1;
        }
    }

    Ok(bytes)
}

/// DH1080 key pair
pub struct DH1080KeyPair {
    pub private_key: BigUint,
    pub public_key: String, // FiSH 10 base64 encoded
}

/// Generate DH1080 key pair
pub fn generate_dh1080_keypair() -> Result<DH1080KeyPair, DllError> {
    let p = BigUint::from_str_radix(DH1080_PRIME_HEX, 16).map_err(|e| DllError::LegacyError {
        context: "DH1080 Init".to_string(),
        cause: format!("Failed to parse prime: {}", e),
    })?;
    let g = BigUint::from(DH1080_GENERATOR);

    let mut rng = rand::thread_rng();
    let priv_key: BigUint = rng.sample(RandomBits::new(1080));

    // pub = g^priv mod p
    let pub_key_bn = g.modpow(&priv_key, &p);

    let mut pub_bytes = pub_key_bn.to_bytes_be();
    // Ensure it's exactly 135 bytes (prepend zeros if needed)
    if pub_bytes.len() < 135 {
        let mut padded = vec![0u8; 135 - pub_bytes.len()];
        padded.extend(pub_bytes);
        pub_bytes = padded;
    }

    let public_key = dh1080_base64_encode(&pub_bytes);

    Ok(DH1080KeyPair { private_key: priv_key, public_key })
}

/// Compute shared secret using DH1080
pub fn compute_dh1080_shared_secret(
    private_key: &BigUint,
    other_public_key: &str,
) -> Result<String, DllError> {
    let p = BigUint::from_str_radix(DH1080_PRIME_HEX, 16).map_err(|e| DllError::LegacyError {
        context: "DH1080 Init".to_string(),
        cause: format!("Failed to parse prime: {}", e),
    })?;

    let other_pub_bytes = dh1080_base64_decode(other_public_key)?;
    let other_pub_bn = BigUint::from_bytes_be(&other_pub_bytes);

    // shared = other_pub^private mod p
    let shared_secret_bn = other_pub_bn.modpow(private_key, &p);

    let mut shared_bytes = shared_secret_bn.to_bytes_be();
    // Ensure it's exactly 135 bytes
    if shared_bytes.len() < 135 {
        let mut padded = vec![0u8; 135 - shared_bytes.len()];
        padded.extend(shared_bytes);
        shared_bytes = padded;
    }

    // Hash the shared secret with SHA256
    let mut hasher = Sha256::new();
    hasher.update(&shared_bytes);
    let hash = hasher.finalize();

    // The result is base64 encoded using our custom FiSH base64 alphabet (not the one for keys)
    // Actually, FiSH 10 uses FISH10_B16_ABC for the shared secret hash as well, but strips '='
    Ok(fish_b64_encode_hash(&hash))
}

/// FiSH 10 hash encoding (standard base64 table but stripped '=')
fn fish_b64_encode_hash(data: &[u8]) -> String {
    let encoded = base64::encode(data);
    encoded.replace("=", "")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dh1080_key_generation() {
        let keypair = generate_dh1080_keypair().unwrap();
        assert_eq!(keypair.public_key.len(), 181);
        assert!(keypair.public_key.ends_with('A'));
    }

    #[test]
    fn test_dh1080_shared_secret() {
        let kp1 = generate_dh1080_keypair().unwrap();
        let kp2 = generate_dh1080_keypair().unwrap();

        let s1 = compute_dh1080_shared_secret(&kp1.private_key, &kp2.public_key).unwrap();
        let s2 = compute_dh1080_shared_secret(&kp2.private_key, &kp1.public_key).unwrap();

        assert_eq!(s1, s2);
        assert_eq!(s1.len(), 43); // SHA256 is 32 bytes -> 44 chars, stripped '=' -> 43
    }
}
