use std::collections::VecDeque;
use std::sync::Arc;

use parking_lot::{Mutex, RwLock};

use super::state::{SocketFlags, SocketState, SocketStats};
use crate::engines::InjectEngines;

pub struct SocketInfo {
    pub socket: u32,
    pub engines: Arc<InjectEngines>,
    pub network_name: RwLock<Option<String>>,

    // State tracking
    pub state: RwLock<SocketState>,
    pub flags: RwLock<SocketFlags>,
    pub stats: Mutex<SocketStats>,

    // Buffers
    pub received_buffer: Mutex<Vec<u8>>,
    pub processed_incoming_buffer: Mutex<VecDeque<u8>>,
    pub incoming_line_buffer: Mutex<String>,
    pub outgoing_line_buffer: Mutex<String>,
    pub tls_handshake_buffer: Mutex<Vec<u8>>, // buffer to accumulate incoming TLS data
}

impl SocketInfo {
    pub fn new(socket: u32, engines: Arc<InjectEngines>) -> Self {
        SocketInfo {
            socket,
            engines,
            network_name: RwLock::new(None),
            state: RwLock::new(SocketState::Initializing),
            flags: RwLock::new(SocketFlags {
                is_ssl: false,
                ssl_handshake_complete: false,
                used_starttls: false,
            }),
            stats: Mutex::new(SocketStats {
                bytes_sent: 0,
                lines_sent: 0,
                lines_encrypted: 0,
                bytes_received: 0,
                lines_received: 0,
                lines_decrypted: 0,
            }),
            received_buffer: Mutex::new(Vec::new()),
            processed_incoming_buffer: Mutex::new(VecDeque::new()),
            incoming_line_buffer: Mutex::new(String::new()),
            outgoing_line_buffer: Mutex::new(String::new()),
            tls_handshake_buffer: Mutex::new(Vec::new()),
        }
    }

    pub fn set_network_name(&self, name: &str) {
        *self.network_name.write() = Some(name.to_string());
    }

    pub fn set_state(&self, state: SocketState) {
        *self.state.write() = state;
    }

    pub fn get_state(&self) -> SocketState {
        *self.state.read()
    }

    /// Set the SSL flage for socket state
    pub fn set_ssl(&self, is_ssl: bool) {
        let mut flags = self.flags.write();
        flags.is_ssl = is_ssl;

        if is_ssl {
            log::debug!("Socket {}: marked as SSL/TLS connection", self.socket);
        }
    }

    pub fn is_ssl(&self) -> bool {
        self.flags.read().is_ssl
    }

    pub fn is_ssl_handshake_complete(&self) -> bool {
        self.flags.read().ssl_handshake_complete
    }

    /// Set the STARTTLS flag for socket state
    pub fn set_ssl_handshake_complete(&self, complete: bool) {
        let mut flags = self.flags.write();
        flags.ssl_handshake_complete = complete;

        if complete {
            log::debug!("Socket {}: SSL/TLS handshake completed", self.socket);
        }
    }

    /// Check if STARTTLS was sued
    pub fn get_stats(&self) -> String {
        let state_str = self.get_state().to_string();
        let is_ssl = if self.is_ssl() { "SSL" } else { "Plain" };
        let stats = self.stats.lock();
        format!(
            "[Socket {} | {} | {} | Rx: {}b/{}ln | Tx: {}b/{}ln]",
            self.socket,
            state_str,
            is_ssl,
            stats.bytes_received,
            stats.lines_received,
            stats.bytes_sent,
            stats.lines_sent
        )
    }
}
