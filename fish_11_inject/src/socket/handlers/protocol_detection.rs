
use crate::socket::info::SocketInfo;
use crate::socket::state::{SocketError, SocketState};
use log::{debug, info, trace};

impl SocketInfo {
    /// Handle the first data sent on a connection to identify protocol
    pub fn handle_protocol_detection(&self, data: &[u8]) -> Result<(), SocketError> {
        // Detect if this is likely TLS data based on first bytes
        if data.len() > 0 && (data[0] == 0x16 || data[0] == 0x80) {
            // First byte of SSL/TLS handshake is typically 0x16 (handshake)
            // or 0x80 (SSLv2 compatible client hello)
            trace!(
                "Socket {}: protocol detection - first byte 0x{:02X} suggests SSL/TLS baby",
                self.socket, data[0]
            );

            // Enhanced: Try to parse TLS record info
            if let Some((record_type, version, _len)) = parse_tls_record_info(data) {
                let version_str = get_tls_version_string(version);
                debug!(
                    "Socket {}: detected TLS record type {} ({}), version: 0x{:04X} ({})",
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
                    if let Some(handshake_type) = parse_tls_handshake_type(data) {
                        let hs_str = get_tls_handshake_type_string(handshake_type);
                        debug!(
                            "Socket {}: TLS handshake type: {} ({})",
                            self.socket, handshake_type, hs_str
                        );
                        if handshake_type == 1 {
                            // ClientHello: try to extract SNI
                            if let Some(sni) = extract_sni_from_client_hello(data) {
                                info!(
                                    "Socket {}: TLS ClientHello SNI detected: {}",
                                    self.socket, sni
                                );
                            }
                        }
                    }
                }
            }

            let mut flags = self.flags.write();
            flags.is_ssl = true;
            drop(flags);

            let mut state = self.state.write();
            *state = SocketState::TlsHandshake;

            trace!("Socket {}: state changed to TlsHandshake", self.socket);
            return Ok(());
        } else if data.len() > 4 {
            // Look for common IRC message beginnings like "NICK", "USER", etc.
            // Use a direct comparison with bytes instead of UTF-8 conversion when possible
            // IRC commands should be ASCII, so we can just check bytes directly
            if data[0] == b'N' && data[1] == b'I' && data[2] == b'C' && data[3] == b'K' {
                trace!(
                    "Socket {}: protocol detection - found NICK command, suggests IRC :)",
                    self.socket
                );

                let mut state = self.state.write();
                *state = SocketState::Connected; // Regular IRC connection

                return Ok(());
            } else if data[0] == b'U' && data[1] == b'S' && data[2] == b'E' && data[3] == b'R' {
                trace!(
                    "Socket {}: protocol detection - found USER command, suggests IRC :)",
                    self.socket
                );

                let mut state = self.state.write();
                *state = SocketState::Connected; // Regular IRC connection

                return Ok(());
            } else if data[0] == b'P' && data[1] == b'A' && data[2] == b'S' && data[3] == b'S' {
                trace!(
                    "Socket {}: protocol detection - found PASS command, suggests IRC :)",
                    self.socket
                );

                let mut state = self.state.write();
                *state = SocketState::Connected; // Regular IRC connection

                return Ok(());
            } else if data[0] == b'C' && data[1] == b'A' && data[2] == b'P' && data[3] == b' ' {
                trace!(
                    "Socket {}: protocol detection - found CAP command, suggests IRC :)",
                    self.socket
                );

                let mut state = self.state.write();
                *state = SocketState::Connected; // Regular IRC connection

                return Ok(());
            } else {
                // Fall back to UTF-8 conversion for less common cases
                if let Ok(text) = std::str::from_utf8(&data[0..4]) {
                    let cmd = text.to_ascii_uppercase();

                    if cmd == "NICK" || cmd == "USER" || cmd == "PASS" || cmd == "CAP " {
                        trace!(
                            "Socket {}: protocol detection - text '{}' suggests IRC :)",
                            self.socket, cmd
                        );

                        let mut state = self.state.write();
                        *state = SocketState::Connected; // Regular IRC connection

                        return Ok(());
                    }
                }
            }
        }
        Ok(())
    }
}

/// Check if data is a TLS handshake packet
pub fn is_tls_handshake_packet(data: &[u8]) -> bool {
    // TLS handshake starts with content type 22 (handshake)
    if data.len() >= 5 {
        // First byte is 22 (content type: handshake)
        // Followed by version (3,1 for TLS 1.0, 3,2 for TLS 1.1, 3,3 for TLS 1.2, etc.)
        return data[0] == 22 && (data[1] == 3) && (data[2] >= 1 && data[2] <= 4);
        // TLS versions 1.0-1.3
    }
    false
}

/// Check if data appears to be an initial IRC command
pub fn is_initial_irc_command(data: &[u8]) -> bool {
    // Fast path: check for common IRC commands directly in bytes
    // Most IRC commands are ASCII, so we can avoid UTF-8 validation
    if data.len() >= 5 {
        // Use direct byte comparison for common commands
        match data[0] {
            b'N' => {
                // Check for "NICK "
                if data.len() >= 5
                    && data[1] == b'I'
                    && data[2] == b'C'
                    && data[3] == b'K'
                    && data[4] == b' '
                {
                    return true;
                }
            }
            b'U' => {
                // Check for "USER "
                if data.len() >= 5
                    && data[1] == b'S'
                    && data[2] == b'E'
                    && data[3] == b'R'
                    && data[4] == b' '
                {
                    return true;
                }
            }
            b'P' => {
                // Check for "PASS " or "PING " or "PONG "
                if data.len() >= 5
                    && data[1] == b'A'
                    && data[2] == b'S'
                    && data[3] == b'S'
                    && data[4] == b' '
                {
                    return true;
                }
                if data.len() >= 5
                    && data[1] == b'I'
                    && data[2] == b'N'
                    && data[3] == b'G'
                    && data[4] == b' '
                {
                    return true;
                }
                if data.len() >= 5
                    && data[1] == b'O'
                    && data[2] == b'N'
                    && data[3] == b'G'
                    && data[4] == b' '
                {
                    return true;
                }
            }
            b'C' => {
                // Check for "CAP "
                if data.len() >= 4 && data[1] == b'A' && data[2] == b'P' && data[3] == b' ' {
                    return true;
                }
            }
            _ => {}
        }
    }

    // Fall back to UTF-8 for less common cases or when leading whitespace needs to be skipped
    if let Ok(str_data) = std::str::from_utf8(data) {
        let trimmed = str_data.trim();
        // Common IRC initial commands
        return trimmed.starts_with("NICK ")
            || trimmed.starts_with("USER ")
            || trimmed.starts_with("PASS ")
            || trimmed.starts_with("CAP ")
            || trimmed.starts_with("PONG ")
            || trimmed.starts_with("PING ");
    }

    false
}

/// Parse TLS record info: returns (record_type, version, record_length) if valid TLS record
pub fn parse_tls_record_info(data: &[u8]) -> Option<(u8, u16, usize)> {
    if data.len() >= 5 {
        let record_type = data[0];
        let version = u16::from_be_bytes([data[1], data[2]]);
        let length = u16::from_be_bytes([data[3], data[4]]) as usize;
        // TLS versions 0x0301 (1.0) to 0x0304 (1.3)
        if data[1] == 3 && (1..=4).contains(&data[2]) {
            return Some((record_type, version, length));
        }
    }
    None
}

/// If this is a handshake record, parse the handshake type (first byte after header)
pub fn parse_tls_handshake_type(data: &[u8]) -> Option<u8> {
    // Must be at least 6 bytes: 5 header + 1 handshake type
    if data.len() >= 6 && data[0] == 22 && data[1] == 3 && (1..=4).contains(&data[2]) {
        // Handshake type is the first byte after the 5-byte header
        return Some(data[5]);
    }
    None
}

/// Get a string for the TLS version
pub fn get_tls_version_string(version: u16) -> &'static str {
    match version {
        0x0301 => "TLS 1.0",
        0x0302 => "TLS 1.1",
        0x0303 => "TLS 1.2",
        0x0304 => "TLS 1.3",
        _ => "Unknown",
    }
}

/// Get a string for the TLS handshake type
pub fn get_tls_handshake_type_string(handshake_type: u8) -> &'static str {
    match handshake_type {
        1 => "ClientHello",
        2 => "ServerHello",
        11 => "Certificate",
        12 => "ServerKeyExchange",
        13 => "CertificateRequest",
        14 => "ServerHelloDone",
        15 => "CertificateVerify",
        16 => "ClientKeyExchange",
        20 => "Finished",
        _ => "Unknown",
    }
}

/// Extract SNI (Server Name Indication) from a TLS ClientHello record
/// Returns Some(hostname) if found, else None
pub fn extract_sni_from_client_hello(data: &[u8]) -> Option<String> {
    // Helper to read a u16 from a slice at a given offset
    fn read_u16(data: &[u8], offset: usize) -> Option<u16> {
        data.get(offset..offset + 2).map(|b| u16::from_be_bytes([b[0], b[1]]))
    }

    // Helper to read a u24 (3 bytes) from a slice at a given offset
    fn read_u24(data: &[u8], offset: usize) -> Option<usize> {
        data.get(offset..offset + 3)
            .map(|b| ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | (b[2] as usize))
    }

    // Check for minimum length and correct record type/handshake type
    if data.len() < 6 || data[0] != 22 || data[5] != 1 {
        return None;
    }

    let mut pos = 5;
    pos += 1; // Skip handshake type (already checked)
    let handshake_len = match read_u24(data, pos) {
        Some(len) => len,
        None => return None,
    };
    pos += 3;
    if data.len() < pos + handshake_len {
        return None;
    }

    // Now at ClientHello body
    // Skip: version (2), random (32)
    if data.len() < pos + 2 + 32 + 1 {
        return None;
    }
    pos += 2 + 32;

    // Session ID
    let session_id_len = *data.get(pos)? as usize;
    pos += 1 + session_id_len;
    if data.len() < pos + 2 {
        return None;
    }

    // Cipher suites
    let cipher_suites_len = read_u16(data, pos)? as usize;
    pos += 2 + cipher_suites_len;
    if data.len() < pos + 1 {
        return None;
    }

    // Compression methods
    let compression_methods_len = *data.get(pos)? as usize;
    pos += 1 + compression_methods_len;
    if data.len() < pos + 2 {
        return None;
    }

    // Extensions
    let extensions_len = read_u16(data, pos)? as usize;
    pos += 2;
    let extensions_end = pos + extensions_len;
    if data.len() < extensions_end {
        return None;
    }

    // Parse extensions
    while pos + 4 <= extensions_end {
        let ext_type = read_u16(data, pos)?;
        let ext_len = read_u16(data, pos + 2)? as usize;
        pos += 4;
        if ext_type == 0x00 {
            // SNI extension must be at least 5 bytes (list len + type + name len)
            if ext_len >= 5 && pos + ext_len <= extensions_end {
                let sni_list_len = read_u16(data, pos)? as usize;
                if sni_list_len + 2 > ext_len {
                    // 2 bytes for sni_list_len field
                    return None;
                }
                let sni_type = *data.get(pos + 2)?;
                let sni_len = read_u16(data, pos + 3)? as usize;
                if sni_type == 0 && sni_len > 0 && (pos + 5 + sni_len) <= (pos + ext_len) {
                    let host_bytes = data.get(pos + 5..pos + 5 + sni_len)?;
                    if let Ok(host) = std::str::from_utf8(host_bytes) {
                        return Some(host.to_string());
                    }
                }
            }
        }
        pos += ext_len;
    }
    None
}
