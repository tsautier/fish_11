//! Memory management module for master key system
//!
//! Handles secure memory operations to prevent sensitive data from being
//! exposed in memory dumps or swap files.
//!
//! This module provides secure data structures that automatically zeroize
//! their contents when dropped, preventing sensitive information from
//! remaining in memory after use.

use secrecy::{ExposeSecret, Secret};
use zeroize::Zeroize;

/// Maximum size for secure allocations to prevent memory exhaustion attacks
const MAX_SECURE_ALLOCATION_SIZE: usize = 1024 * 1024; // 1MB

/// A secure string that automatically clears its contents when dropped
pub struct SecureString {
    inner: Secret<String>,
}

impl std::fmt::Debug for SecureString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureString")
            .field("inner", &"<redacted>")
            .finish()
    }
}

impl SecureString {
    /// Create a new secure string with size validation
    pub fn new(s: String) -> Result<Self, String> {
        // Validate size to prevent memory exhaustion
        if s.len() > MAX_SECURE_ALLOCATION_SIZE {
            return Err(format!(
                "SecureString allocation too large: {} bytes (max: {})",
                s.len(),
                MAX_SECURE_ALLOCATION_SIZE
            ));
        }
        
        Ok(Self { inner: Secret::new(s) })
    }

    /// Create a new secure string without validation (unsafe)
    ///
    /// # Safety
    /// This function does not validate the input size and should only be used
    /// when the caller has already validated the size.
    pub unsafe fn new_unchecked(s: String) -> Self {
        Self { inner: Secret::new(s) }
    }

    /// Get the value (use sparingly and securely)
    pub fn expose(&self) -> &str {
        self.inner.expose_secret()
    }

    /// Clear the contents
    pub fn clear(&mut self) {
        // Zeroize the secret content before clearing
        let mut secret = self.inner.expose_secret().clone();
        secret.zeroize();
        self.inner = Secret::new(String::new());
    }
}

/// A secure byte vector that automatically clears its contents when dropped
pub struct SecureBytes {
    inner: Secret<Vec<u8>>,
}

impl std::fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SecureBytes")
            .field("inner", &"<redacted>")
            .finish()
    }
}

impl SecureBytes {
    /// Create a new secure byte vector with size validation
    pub fn new(bytes: Vec<u8>) -> Result<Self, String> {
        // Validate size to prevent memory exhaustion
        if bytes.len() > MAX_SECURE_ALLOCATION_SIZE {
            return Err(format!(
                "SecureBytes allocation too large: {} bytes (max: {})",
                bytes.len(),
                MAX_SECURE_ALLOCATION_SIZE
            ));
        }
        
        Ok(Self { inner: Secret::new(bytes) })
    }

    /// Create a new secure byte vector without validation (unsafe)
    ///
    /// # Safety
    /// This function does not validate the input size and should only be used
    /// when the caller has already validated the size.
    pub unsafe fn new_unchecked(bytes: Vec<u8>) -> Self {
        Self { inner: Secret::new(bytes) }
    }

    /// Get the value (use sparingly and securely)
    pub fn expose(&self) -> &[u8] {
        self.inner.expose_secret()
    }

    /// Clear the contents
    pub fn clear(&mut self) {
        // Zeroize the secret content before clearing
        let mut secret = self.inner.expose_secret().clone();

        secret.zeroize();

        self.inner = Secret::new(Vec::new());
    }
}

impl Drop for SecureString {
    fn drop(&mut self) {
        // Zeroize the secret content before dropping
        let mut secret = self.inner.expose_secret().clone();

        secret.zeroize();

        self.inner = Secret::new(String::new());
    }
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        // Zeroize the secret content before dropping
        let mut secret = self.inner.expose_secret().clone();

        secret.zeroize();

        self.inner = Secret::new(Vec::new());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_secure_string() {
        let secure_str = SecureString::new("secret_data".to_string()).unwrap();
        assert_eq!(secure_str.expose(), "secret_data");
    }

    #[test]
    fn test_secure_bytes() {
        let secure_bytes = SecureBytes::new(vec![1, 2, 3, 4]).unwrap();
        assert_eq!(secure_bytes.expose(), &[1, 2, 3, 4]);
    }

    #[test]
    fn test_secure_string_size_validation() {
        // Test that large allocations are rejected
        let large_string = "a".repeat(MAX_SECURE_ALLOCATION_SIZE + 1);
        let result = SecureString::new(large_string);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("allocation too large"));
    }

    #[test]
    fn test_secure_bytes_size_validation() {
        // Test that large allocations are rejected
        let large_bytes = vec![0u8; MAX_SECURE_ALLOCATION_SIZE + 1];
        let result = SecureBytes::new(large_bytes);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("allocation too large"));
    }

    #[test]
    fn test_secure_string_max_size() {
        // Test that allocations at the maximum size are allowed
        let max_string = "a".repeat(MAX_SECURE_ALLOCATION_SIZE);
        let result = SecureString::new(max_string);
        assert!(result.is_ok());
    }

    #[test]
    fn test_secure_bytes_max_size() {
        // Test that allocations at the maximum size are allowed
        let max_bytes = vec![0u8; MAX_SECURE_ALLOCATION_SIZE];
        let result = SecureBytes::new(max_bytes);
        assert!(result.is_ok());
    }
}
