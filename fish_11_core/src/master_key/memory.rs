//! Memory management module for master key system
//!
//! Handles secure memory operations to prevent sensitive data from being
//! exposed in memory dumps or swap files.

use secrecy::{ExposeSecret, Secret};
use zeroize::Zeroize;

/// A secure string that automatically clears its contents when dropped
pub struct SecureString {
    inner: Secret<String>,
}

impl SecureString {
    /// Create a new secure string
    pub fn new(s: String) -> Self {
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

impl SecureBytes {
    /// Create a new secure byte vector
    pub fn new(bytes: Vec<u8>) -> Self {
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
        let secure_str = SecureString::new("secret_data".to_string());
        assert_eq!(secure_str.expose(), "secret_data");
    }

    #[test]
    fn test_secure_bytes() {
        let secure_bytes = SecureBytes::new(vec![1, 2, 3, 4]);
        assert_eq!(secure_bytes.expose(), &[1, 2, 3, 4]);
    }
}
