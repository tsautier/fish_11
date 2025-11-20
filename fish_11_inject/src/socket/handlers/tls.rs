use log::{debug, info, warn};

use super::protocol_detection::{
    extract_sni_from_client_hello, get_tls_handshake_type_string, get_tls_version_string,
    parse_tls_handshake_type, parse_tls_record_info,
};
use crate::socket::info::SocketInfo;
use crate::socket::state::SocketState;

impl SocketInfo {
    /// Called when data is received from the socket
    /// either directly from Winsock or after SSL decryption
    pub fn on_receiving(&self, data: &[u8]) {
        // Using try_lock to handle potential mutex poisoning
        match self.tls_handshake_buffer.try_lock() {
            Some(mut buffer) => {
                buffer.extend_from_slice(data);

                // Process TLS handshake only if buffer has enough data
                while buffer.len() >= 5 {
                    if let Some((record_type, version, length)) = parse_tls_record_info(&buffer) {
                        if buffer.len() >= 5 + length {
                            let record = &buffer[..5 + length];
                            let version_str = get_tls_version_string(version);
                            debug!(
                                "Socket {}: TLS record received: type {} ({}), version: 0x{:04X} ({})",
                                self.socket,
                                record_type,
                                match record_type {
                                    20 => "ChangeCipherSpec",
                                    21 => "Alert",
                                    22 => "Handshake",
                                    23 => "ApplicationData",
                                    _ => "Unknown",
                                },
                                version,
                                version_str
                            );
                            if record_type == 22 {
                                if let Some(handshake_type) = parse_tls_handshake_type(record) {
                                    let hs_str = get_tls_handshake_type_string(handshake_type);
                                    debug!(
                                        "Socket {}: TLS handshake type: {} ({})",
                                        self.socket, handshake_type, hs_str
                                    );
                                    if handshake_type == 1 {
                                        if let Some(sni) = extract_sni_from_client_hello(record) {
                                            info!(
                                                "Socket {}: TLS ClientHello SNI detected: {}",
                                                self.socket, sni
                                            );
                                        }
                                    }
                                }
                                self.set_state(SocketState::TlsHandshake);
                            }
                            buffer.drain(..5 + length);
                        } else {
                            break; // Wait for more data
                        }
                    } else {
                        break; // Not enough data or not a TLS record
                    }
                }
            }
            None => {
                warn!("Socket {}: could not acquire lock on tls_handshake_buffer", self.socket);
            }
        }
    }
}
