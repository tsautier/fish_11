use std::{fmt, io};

#[derive(Debug)]
pub enum SocketError {
    Utf8Error(std::str::Utf8Error),
    IoError(io::Error),
    ProtocolError(String),
    BufferOverflow,
    // TODO : add more as needed
}

/// Implementing From trait for std::str::Utf8Error to convert it to SocketError
impl From<std::str::Utf8Error> for SocketError {
    fn from(e: std::str::Utf8Error) -> Self {
        SocketError::Utf8Error(e)
    }
}

/// Implementing From trait for io::Error to convert it to SocketError
impl From<io::Error> for SocketError {
    fn from(e: io::Error) -> Self {
        SocketError::IoError(e)
    }
}

/// Represents the current state of a socket connection.
#[derive(PartialEq, Debug, Clone, Copy)]
pub enum SocketState {
    Initializing,
    TlsHandshake,
    Connected,
    IrcIdentified,
    Closed,
}

impl fmt::Display for SocketState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SocketState::Initializing => write!(f, "Initializing"),
            SocketState::TlsHandshake => write!(f, "TlsHandshake"),
            SocketState::Connected => write!(f, "Connected"),
            SocketState::IrcIdentified => write!(f, "IrcIdentified"),
            SocketState::Closed => write!(f, "Closed"),
        }
    }
}

pub struct SocketFlags {
    pub is_ssl: bool,
    pub ssl_handshake_complete: bool,
    pub used_starttls: bool,
}

pub struct SocketStats {
    pub bytes_sent: usize,
    pub lines_sent: usize,
    pub lines_encrypted: usize,
    pub bytes_received: usize,
    pub lines_received: usize,
    pub lines_decrypted: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_socket_state_display() {
        assert_eq!(format!("{}", SocketState::Initializing), "Initializing");
        assert_eq!(format!("{}", SocketState::TlsHandshake), "TlsHandshake");
        assert_eq!(format!("{}", SocketState::Connected), "Connected");
        assert_eq!(format!("{}", SocketState::IrcIdentified), "IrcIdentified");
        assert_eq!(format!("{}", SocketState::Closed), "Closed");
    }

    #[test]
    fn test_socket_state_equality() {
        assert_eq!(SocketState::Initializing, SocketState::Initializing);
        assert_ne!(SocketState::Initializing, SocketState::Connected);
        assert_eq!(SocketState::TlsHandshake, SocketState::TlsHandshake);
        assert_eq!(SocketState::Connected, SocketState::Connected);
        assert_eq!(SocketState::IrcIdentified, SocketState::IrcIdentified);
        assert_eq!(SocketState::Closed, SocketState::Closed);
    }

    #[test]
    fn test_socket_flags_default_values() {
        let flags =
            SocketFlags { is_ssl: false, ssl_handshake_complete: false, used_starttls: false };

        assert!(!flags.is_ssl);
        assert!(!flags.ssl_handshake_complete);
        assert!(!flags.used_starttls);
    }

    #[test]
    fn test_socket_flags_ssl_setting() {
        let mut flags =
            SocketFlags { is_ssl: false, ssl_handshake_complete: false, used_starttls: false };

        // Set SSL flag to true
        flags.is_ssl = true;
        assert!(flags.is_ssl);

        // Set back to false
        flags.is_ssl = false;
        assert!(!flags.is_ssl);
    }

    #[test]
    fn test_socket_stats_initialization() {
        let stats = SocketStats {
            bytes_sent: 0,
            lines_sent: 0,
            lines_encrypted: 0,
            bytes_received: 0,
            lines_received: 0,
            lines_decrypted: 0,
        };

        assert_eq!(stats.bytes_sent, 0);
        assert_eq!(stats.lines_sent, 0);
        assert_eq!(stats.lines_encrypted, 0);
        assert_eq!(stats.bytes_received, 0);
        assert_eq!(stats.lines_received, 0);
        assert_eq!(stats.lines_decrypted, 0);
    }

    #[test]
    fn test_socket_stats_modification() {
        let mut stats = SocketStats {
            bytes_sent: 0,
            lines_sent: 0,
            lines_encrypted: 0,
            bytes_received: 0,
            lines_received: 0,
            lines_decrypted: 0,
        };

        // Update stats
        stats.bytes_sent = 100;
        stats.lines_sent = 5;
        stats.bytes_received = 200;
        stats.lines_received = 10;

        assert_eq!(stats.bytes_sent, 100);
        assert_eq!(stats.lines_sent, 5);
        assert_eq!(stats.bytes_received, 200);
        assert_eq!(stats.lines_received, 10);
    }

    #[test]
    fn test_socket_error_conversions() {
        // Test UTF-8 error conversion
        let utf8_error = std::str::from_utf8(b"\xFF").unwrap_err();
        let socket_error: SocketError = utf8_error.into();
        match socket_error {
            SocketError::Utf8Error(_) => assert!(true), // Expected
            _ => panic!("Expected Utf8Error"),
        }

        // Test IO error conversion
        let io_error = std::io::Error::new(std::io::ErrorKind::Other, "test error");
        let socket_error: SocketError = io_error.into();
        match socket_error {
            SocketError::IoError(_) => assert!(true), // Expected
            _ => panic!("Expected IoError"),
        }
    }
}
