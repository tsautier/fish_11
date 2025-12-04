//! ssl_mapping.rs
//! Thread-safe mapping between SSL contexts and socket file descriptors.
//!
//! This module provides atomic operations for associating SSL* pointers with
//! socket IDs, ensuring thread-safe access without risk of race conditions.

use dashmap::DashMap;
use log::{debug, trace, warn};
use once_cell::sync::Lazy;

use crate::hook_ssl::{SSLWrapper, SSL};

/// Global thread-safe mapping from SSL pointer (as usize) to socket ID
static SSL_TO_SOCKET: Lazy<DashMap<usize, u32>> = Lazy::new(DashMap::new);

/// Global thread-safe mapping from socket ID to SSL wrapper
static SOCKET_TO_SSL: Lazy<DashMap<u32, SSLWrapper>> = Lazy::new(DashMap::new);

/// Thread-safe SSL-Socket mapping operations.
///
/// All operations are atomic and thread-safe, eliminating race conditions
/// between reading and writing the mappings.
pub struct SslSocketMapping;

impl SslSocketMapping {
    /// Associate an SSL context with a socket ID.
    ///
    /// This atomically updates both mappings (SSL->Socket and Socket->SSL).
    ///
    /// # Arguments
    /// * `ssl` - Pointer to the SSL context
    /// * `socket_id` - The socket file descriptor
    ///
    /// # Safety
    /// The caller must ensure `ssl` is a valid SSL* pointer.
    pub fn associate(ssl: *mut SSL, socket_id: u32) {
        if ssl.is_null() {
            warn!("SslSocketMapping::associate called with null SSL pointer");
            return;
        }

        let ssl_id = ssl as usize;

        // Insert into both maps atomically (DashMap handles locking internally)
        SSL_TO_SOCKET.insert(ssl_id, socket_id);
        SOCKET_TO_SSL.insert(socket_id, SSLWrapper { ssl });

        trace!(
            "SslSocketMapping: associated SSL {:p} (id={}) with socket {}",
            ssl,
            ssl_id,
            socket_id
        );
    }

    /// Get the socket ID associated with an SSL context.
    ///
    /// # Arguments
    /// * `ssl` - Pointer to the SSL context
    ///
    /// # Returns
    /// `Some(socket_id)` if the mapping exists, `None` otherwise.
    pub fn get_socket(ssl: *mut SSL) -> Option<u32> {
        if ssl.is_null() {
            return None;
        }

        let ssl_id = ssl as usize;
        SSL_TO_SOCKET.get(&ssl_id).map(|entry| *entry.value())
    }

    /// Get the SSL context associated with a socket ID.
    ///
    /// # Arguments
    /// * `socket_id` - The socket file descriptor
    ///
    /// # Returns
    /// `Some(ssl_ptr)` if the mapping exists, `None` otherwise.
    ///
    /// # Safety
    /// The returned pointer must only be used if it's still valid (i.e., SSL_free
    /// hasn't been called on it).
    pub fn get_ssl(socket_id: u32) -> Option<*mut SSL> {
        SOCKET_TO_SSL.get(&socket_id).map(|entry| entry.value().ssl)
    }

    /// Remove an SSL context from the mappings.
    ///
    /// This atomically removes from both mappings.
    ///
    /// # Arguments
    /// * `ssl` - Pointer to the SSL context
    ///
    /// # Returns
    /// The socket ID that was associated, if any.
    pub fn remove_ssl(ssl: *mut SSL) -> Option<u32> {
        if ssl.is_null() {
            return None;
        }

        let ssl_id = ssl as usize;

        // Remove from SSL_TO_SOCKET and get the socket_id
        if let Some((_, socket_id)) = SSL_TO_SOCKET.remove(&ssl_id) {
            // Also remove from SOCKET_TO_SSL
            SOCKET_TO_SSL.remove(&socket_id);

            debug!(
                "SslSocketMapping: removed SSL {:p} (was mapped to socket {})",
                ssl, socket_id
            );

            Some(socket_id)
        } else {
            trace!("SslSocketMapping: SSL {:p} was not in mapping", ssl);
            None
        }
    }

    /// Remove a socket from the mappings.
    ///
    /// This atomically removes from both mappings.
    ///
    /// # Arguments
    /// * `socket_id` - The socket file descriptor
    ///
    /// # Returns
    /// The SSL pointer that was associated, if any.
    pub fn remove_socket(socket_id: u32) -> Option<*mut SSL> {
        // Remove from SOCKET_TO_SSL and get the SSL pointer
        if let Some((_, wrapper)) = SOCKET_TO_SSL.remove(&socket_id) {
            let ssl = wrapper.ssl;
            let ssl_id = ssl as usize;

            // Also remove from SSL_TO_SOCKET
            SSL_TO_SOCKET.remove(&ssl_id);

            debug!(
                "SslSocketMapping: removed socket {} (was mapped to SSL {:p})",
                socket_id, ssl
            );

            Some(ssl)
        } else {
            trace!("SslSocketMapping: socket {} was not in mapping", socket_id);
            None
        }
    }

    /// Check if an SSL context is currently mapped.
    pub fn contains_ssl(ssl: *mut SSL) -> bool {
        if ssl.is_null() {
            return false;
        }
        SSL_TO_SOCKET.contains_key(&(ssl as usize))
    }

    /// Check if a socket is currently mapped to an SSL context.
    pub fn contains_socket(socket_id: u32) -> bool {
        SOCKET_TO_SSL.contains_key(&socket_id)
    }

    /// Get the current number of active SSL-socket mappings.
    pub fn len() -> usize {
        SSL_TO_SOCKET.len()
    }

    /// Check if there are no active mappings.
    pub fn is_empty() -> bool {
        SSL_TO_SOCKET.is_empty()
    }

    /// Clear all mappings (used during cleanup/unload).
    pub fn clear() {
        let count = SSL_TO_SOCKET.len();
        SSL_TO_SOCKET.clear();
        SOCKET_TO_SSL.clear();
        debug!("SslSocketMapping: cleared {} mappings", count);
    }

    /// Get debug info about current mappings.
    pub fn debug_info() -> String {
        let ssl_count = SSL_TO_SOCKET.len();
        let socket_count = SOCKET_TO_SSL.len();

        if ssl_count != socket_count {
            format!(
                "WARNING: mapping inconsistency - SSL_TO_SOCKET: {}, SOCKET_TO_SSL: {}",
                ssl_count, socket_count
            )
        } else {
            format!("Active SSL-socket mappings: {}", ssl_count)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_associate_and_get() {
        // Use a fake pointer for testing
        let fake_ssl = 0x12345678 as *mut SSL;
        let socket_id = 42u32;

        SslSocketMapping::associate(fake_ssl, socket_id);

        assert_eq!(SslSocketMapping::get_socket(fake_ssl), Some(socket_id));
        assert_eq!(SslSocketMapping::get_ssl(socket_id), Some(fake_ssl));

        // Cleanup
        SslSocketMapping::remove_ssl(fake_ssl);
    }

    #[test]
    fn test_remove_ssl() {
        let fake_ssl = 0xABCDEF00 as *mut SSL;
        let socket_id = 100u32;

        SslSocketMapping::associate(fake_ssl, socket_id);
        assert!(SslSocketMapping::contains_ssl(fake_ssl));
        assert!(SslSocketMapping::contains_socket(socket_id));

        let removed_socket = SslSocketMapping::remove_ssl(fake_ssl);
        assert_eq!(removed_socket, Some(socket_id));
        assert!(!SslSocketMapping::contains_ssl(fake_ssl));
        assert!(!SslSocketMapping::contains_socket(socket_id));
    }

    #[test]
    fn test_remove_socket() {
        let fake_ssl = 0xDEADBEEF as *mut SSL;
        let socket_id = 200u32;

        SslSocketMapping::associate(fake_ssl, socket_id);

        let removed_ssl = SslSocketMapping::remove_socket(socket_id);
        assert_eq!(removed_ssl, Some(fake_ssl));
        assert!(!SslSocketMapping::contains_ssl(fake_ssl));
        assert!(!SslSocketMapping::contains_socket(socket_id));
    }

    #[test]
    fn test_null_ssl_handling() {
        let null_ssl: *mut SSL = std::ptr::null_mut();

        // Should not crash, should return None
        assert_eq!(SslSocketMapping::get_socket(null_ssl), None);
        assert!(!SslSocketMapping::contains_ssl(null_ssl));

        // Associate with null should be a no-op
        SslSocketMapping::associate(null_ssl, 999);
        assert!(!SslSocketMapping::contains_socket(999));
    }
}
