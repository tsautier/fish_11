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
