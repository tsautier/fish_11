//! socket_info.rs
//! Written by [GuY], 2025. Licensed under the GPL v3.
//!
//! This file is part of the FiSH_11 project.
use std::collections::VecDeque;
use std::sync::Arc;
use std::{fmt, io};

use log::{debug, info, trace, warn};
use parking_lot::{Mutex, RwLock};
use fish_11_core::globals::{
    CMD_NOTICE, CMD_PRIVMSG, ENCRYPTION_PREFIX_FISH, ENCRYPTION_PREFIX_MCPS,
    ENCRYPTION_PREFIX_OK, KEY_EXCHANGE_INIT, KEY_EXCHANGE_PUBKEY,
};

use crate::engines::InjectEngines;

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

/// SocketInfo struct
impl crate::socket_info::SocketInfo {
    pub fn on_sending(&self, data: &[u8]) -> Result<(), SocketError> {
        // Using a safer pattern with try_lock to handle potential mutex poisoning
        let first_data = match self.stats.try_lock() {
            Some(mut stats) => {
                let is_first = stats.bytes_sent == 0;
                stats.bytes_sent += data.len();
                is_first
            }
            None => {
                warn!(
                    "Socket {}: could not acquire stats lock in on_sending, assuming not first data",
                    self.socket
                );
                false // Conservative assumption if lock is poisoned
            }
        }; // Lock is automatically released here when stats goes out of scope

        // Check for protocol detection if this is the first data being sent
        if first_data {
            self.handle_protocol_detection(data)?;
        }

        // Process the outgoing data through engines
        trace!(
            "Socket {}: [OUT RAW] full outgoing buffer ({} bytes): {:02X?}",
            self.socket,
            data.len(),
            data
        );

        // Single UTF-8 validation for the entire buffer
        match std::str::from_utf8(data) {
            Ok(data_str) => {
                trace!("Socket {}: [OUT RAW] UTF-8: {}", self.socket, data_str.trim_end());
                // Use try_lock to handle potential mutex poisoning gracefully
                let mut should_process_lines = false;
                let mut lines_to_process = String::new();

                // Controlled scope for lock to ensure release
                {
                    // Append to line buffer
                    match self.outgoing_line_buffer.try_lock() {
                        Some(mut line_buf) => {
                            line_buf.push_str(data_str);

                            // Early return if no complete lines to process
                            if !line_buf.contains("\r\n") {
                                return Ok(());
                            }

                            // Copy lines to process and clear buffer
                            // This minimizes the lock duration
                            lines_to_process = line_buf.clone();
                            should_process_lines = true;
                        }
                        None => {
                            // Handle mutex acquisition failure gracefully
                            warn!(
                                "Socket {}: could not acquire lock on outgoing_line_buffer, skipping processing",
                                self.socket
                            );
                            return Ok(());
                        }
                    }
                } // Lock is released here

                if should_process_lines {
                    let mut lines_processed = 0;
                    let mut remaining = String::new();
                    let crlf_count = lines_to_process.matches("\r\n").count();

                    // Pre-allocate a buffer for lines with CRLF
                    // This is more efficient than creating a new String for each line
                    let mut buffer = String::with_capacity(lines_to_process.len());

                    for (i, line) in lines_to_process.split("\r\n").enumerate() {
                        if i == crlf_count {
                            // Last part doesn't end with CRLF, save for next time
                            remaining = line.to_string();
                            break;
                        }

                        // Skip empty lines
                        if !line.is_empty() {
                            debug!("Socket {}: [IRC OUT] {}", self.socket, line.trim());

                            // Process complete line - use scoped block to minimize lock holding time
                            {
                                let mut stats = self.stats.lock();
                                stats.lines_sent += 1;
                                // Lock released here
                            }

                            // Process through engines
                            // Reuse the buffer to avoid allocation
                            buffer.clear();
                            buffer.push_str(line);
                            buffer.push_str("\r\n");

                            // Use the pre-allocated buffer for engine processing
                            if self.engines.on_outgoing_irc_line(self.socket, &mut buffer) {
                                // Another scope to minimize lock time
                                {
                                    let mut stats = self.stats.lock();
                                    stats.lines_encrypted += 1;
                                    // Lock released here
                                }

                                trace!(
                                    "Socket {}: engine modified outgoing line: {}",
                                    self.socket,
                                    buffer.trim_end()
                                );
                            }

                            lines_processed += 1;
                        }
                    }
                    // Store the remaining unprocessed part back to the buffer
                    match self.outgoing_line_buffer.try_lock() {
                        Some(mut line_buf) => {
                            *line_buf = remaining;
                        }
                        None => {
                            warn!(
                                "Socket {}: could not acquire lock to store remaining data",
                                self.socket
                            );
                        }
                    }

                    if lines_processed > 0 {
                        trace!(
                            "Socket {}: processed {} outgoing lines",
                            self.socket, lines_processed
                        );
                    }
                }

                Ok(())
            }
            Err(e) => {
                // Non-UTF8 data, likely binary/encrypted
                trace!("Socket {}: [OUT RAW] non-UTF8 data", self.socket);

                warn!(
                    "Socket {}: failed to interpret outgoing data as UTF-8: {}. First 16 bytes: {:02X?}",
                    self.socket,
                    e,
                    &data.iter().take(16).cloned().collect::<Vec<u8>>()
                );
                if self.is_ssl() && self.get_state() == SocketState::TlsHandshake {
                    trace!(
                        "Socket {}: [SSL OUT] sending TLS handshake data ({} bytes): {:02X?}",
                        self.socket,
                        data.len(),
                        &data.iter().take(16).cloned().collect::<Vec<u8>>()
                    );
                } else {
                    trace!(
                        "Socket {}: [BIN OUT] sending binary data ({} bytes): {:02X?}",
                        self.socket,
                        data.len(),
                        &data.iter().take(16).cloned().collect::<Vec<u8>>()
                    );
                }
                Err(SocketError::Utf8Error(e))
            }
        }
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

struct SocketFlags {
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

pub struct SocketInfo {
    pub socket: u32,
    pub engines: Arc<InjectEngines>,
    pub network_name: RwLock<Option<String>>,

    // State tracking
    pub state: RwLock<SocketState>,
    flags: RwLock<SocketFlags>,
    pub stats: Mutex<SocketStats>,

    // Buffers
    pub received_buffer: Mutex<Vec<u8>>,
    pub processed_incoming_buffer: Mutex<VecDeque<u8>>,
    pub incoming_line_buffer: Mutex<String>,
    pub outgoing_line_buffer: Mutex<String>,
    tls_handshake_buffer: Mutex<Vec<u8>>, // buffer to accumulate incoming TLS data
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

    pub fn write_received_data(&self, data: &[u8]) {
        // Safely handle buffer extension without catch_unwind on the entire operation
        match self.received_buffer.try_lock() {
            Some(mut buffer) => {
                // Check for potential buffer overflows before extending
                if buffer.len() + data.len() > 1_000_000 {
                    // TODO : 1MB limit as an example
                    warn!(
                        "Socket {}: received buffer exceeds 1MB limit, truncating older data to mitigate DoS attack",
                        self.socket
                    );

                    // Calculate how much data we need to drop to make room for new data
                    // Keep some margin (10KB) to avoid having to truncate on every small addition
                    let overflow_amount = (buffer.len() + data.len()) - 990_000;

                    // Drop the oldest data from the front of the buffer
                    if overflow_amount < buffer.len() {
                        // Use AssertUnwindSafe for the drain operation which might panic
                        if let Err(_) =
                            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                                buffer.drain(0..overflow_amount);
                            }))
                        {
                            warn!(
                                "Socket {}: Failed to truncate buffer, clearing instead",
                                self.socket
                            );
                            buffer.clear();
                        }
                    } else {
                        // If the current data is too big, clear the buffer completely
                        buffer.clear();
                    }

                    info!(
                        "Socket {}: buffer truncated, removed {} bytes of older data",
                        self.socket, overflow_amount
                    );
                }

                // Use a separate catch_unwind just for extending the buffer
                let extend_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    buffer.extend_from_slice(data);
                }));

                if extend_result.is_err() {
                    warn!("Socket {}: failed to extend buffer with new data", self.socket);
                } else {
                    debug!(
                        "Socket {}: write_received_data called, {} bytes: {:02X?}",
                        self.socket,
                        data.len(),
                        &data[..std::cmp::min(32, data.len())]
                    );
                }
            }
            None => {
                warn!("Socket {}: could not acquire lock on received_buffer", self.socket);
            }
        }
    }

    pub fn prepare_outgoing_data(&self, data: &[u8]) -> Result<Vec<u8>, SocketError> {
        let mut output = String::from_utf8_lossy(data).into_owned();
        if self.engines.on_outgoing_irc_line(self.socket, &mut output) {
            Ok(output.into_bytes())
        } else {
            Ok(data.to_vec())
        }
    }

    pub fn on_incoming_irc_line(&self, socket: u32, line: &mut String) -> bool {
        let mut modified = false;

        // Process through normal engines first
        for engine in self.engines.get_engines() {
            let before = line.clone();
            if !engine.is_postprocessor {
                if engine.on_incoming_irc_line(socket, line) {
                    modified = true;
                }
            }
            if modified {
                trace!(
                    "Socket {}: engine '{}' modified incoming line:\n  Before: {}\n  After:  {}",
                    socket,
                    engine.engine_name,
                    before.trim_end(),
                    line.trim_end()
                );
            } else {
                trace!(
                    "Socket {}: engine '{}' did not modify incoming line:",
                    socket, engine.engine_name
                );
            }
        }

        // Then through postprocessors
        for engine in self.engines.get_engines() {
            if engine.is_postprocessor {
                if engine.on_incoming_irc_line(socket, line) {
                    modified = true;
                }
            }
        }

        modified
    }

    pub fn on_outgoing_irc_line(&self, socket: u32, line: &mut String) -> bool {
        let mut modified = false;

        // Process through normal engines first
        for engine in self.engines.get_engines() {
            let before = line.clone();
            if !engine.is_postprocessor {
                if engine.on_outgoing_irc_line(socket, line) {
                    modified = true;
                }
            }
            if modified {
                trace!(
                    "Socket {}: engine '{}' modified outgoing line:\n  before: {}\n  After:  {}",
                    socket,
                    engine.engine_name,
                    before.trim_end(),
                    line.trim_end()
                );
            } else {
                trace!(
                    "Socket {}: engine '{}' did not modify outgoing line:",
                    socket, engine.engine_name
                );
            }
        }

        // Then through postprocessors
        for engine in self.engines.get_engines() {
            if engine.is_postprocessor {
                if engine.on_outgoing_irc_line(socket, line) {
                    modified = true;
                }
            }
        }

        modified
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
            debug!("Socket {}: marked as SSL/TLS connection", self.socket);
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
            debug!("Socket {}: SSL/TLS handshake completed", self.socket);
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
            if let Some((record_type, version, _len)) = Self::parse_tls_record_info(data) {
                let version_str = Self::get_tls_version_string(version);
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
                    if let Some(handshake_type) = Self::parse_tls_handshake_type(data) {
                        let hs_str = Self::get_tls_handshake_type_string(handshake_type);
                        debug!(
                            "Socket {}: TLS handshake type: {} ({})",
                            self.socket, handshake_type, hs_str
                        );
                        if handshake_type == 1 {
                            // ClientHello: try to extract SNI
                            if let Some(sni) = Self::extract_sni_from_client_hello(data) {
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

    /// Called when data is received from the socket
    /// either directly from Winsock or after SSL decryption
    pub fn on_receiving(&self, data: &[u8]) {
        // Using try_lock to handle potential mutex poisoning
        match self.tls_handshake_buffer.try_lock() {
            Some(mut buffer) => {
                buffer.extend_from_slice(data);

                // Process TLS handshake only if buffer has enough data
                while buffer.len() >= 5 {
                    if let Some((record_type, version, length)) =
                        Self::parse_tls_record_info(&buffer)
                    {
                        if buffer.len() >= 5 + length {
                            let record = &buffer[..5 + length];
                            let version_str = Self::get_tls_version_string(version);
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
                                if let Some(handshake_type) = Self::parse_tls_handshake_type(record)
                                {
                                    let hs_str =
                                        Self::get_tls_handshake_type_string(handshake_type);
                                    debug!(
                                        "Socket {}: TLS handshake type: {} ({})",
                                        self.socket, handshake_type, hs_str
                                    );
                                    if handshake_type == 1 {
                                        if let Some(sni) =
                                            Self::extract_sni_from_client_hello(record)
                                        {
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

    /// Process received data as UTF-8 lines
    pub fn process_received_lines(&self) -> Result<(), SocketError> {
        // Get data while handling potential mutex poisoning
        let data = match self.received_buffer.try_lock() {
            Some(mut buffer) => {
                if buffer.is_empty() {
                    return Ok(());
                }

                info!("Socket {}: processing {} bytes of received data", self.socket, buffer.len());

                #[cfg(debug_assertions)]
                {
                    debug!(
                        "[PROCESS_LINES DEBUG] socket {}: received_buffer has {} bytes before processing",
                        self.socket,
                        buffer.len()
                    );
                }

                // Clone the data and immediately release the lock
                let data_copy = buffer.clone();

                // Clear buffer now that we've copied the data
                buffer.clear();

                data_copy
            }
            None => {
                // Handle mutex acquisition failure gracefully
                warn!(
                    "Socket {}: could not acquire lock on received_buffer, will retry later",
                    self.socket
                );
                return Ok(()); // Return without error to allow retrying later
            }
        };

        trace!(
            "Socket {}: [IN RAW] full received buffer ({} bytes): {:02X?}",
            self.socket,
            data.len(),
            data
        );

        #[cfg(debug_assertions)]
        {
            debug!(
                "[PROCESS_LINES DEBUG] socket {}: processing buffer of {} bytes",
                self.socket,
                data.len()
            );
            let preview_len = std::cmp::min(128, data.len());
            debug!(
                "[PROCESS_LINES DEBUG] socket {}: hex preview (first {} bytes): {:02X?}",
                self.socket,
                preview_len,
                &data[..preview_len]
            );
        }

        // Single UTF-8 validation for the entire buffer
        match std::str::from_utf8(&data) {
            Ok(data_str) => {
                trace!("Socket {}: [IN RAW] UTF-8: {}", self.socket, data_str.trim_end());

                #[cfg(debug_assertions)]
                {
                    let sanitized: String = data_str
                        .chars()
                        .take(256)
                        .map(|c| {
                            if c.is_control() && c != '\r' && c != '\n' && c != '\t' {
                                '.'
                            } else {
                                c
                            }
                        })
                        .collect();
                    debug!(
                        "[PROCESS_LINES DEBUG] socket {}: UTF-8 content preview (sanitized, first 256 chars): {:?}",
                        self.socket, sanitized
                    );
                }

                let mut lines_processed = 0;
                let mut bytes_processed = 0;

                // Pre-allocate a buffer for lines with CRLF
                let mut line_buffer = String::with_capacity(128);

                // Process each line with controlled lock acquisition
                for line in data_str.split("\r\n") {
                    if line.is_empty() {
                        bytes_processed += 2; // Count the \r\n
                        continue;
                    }

                    debug!("Socket {}: [IRC IN] {}", self.socket, line);

                    #[cfg(debug_assertions)]
                    {
                        // Log details about each IRC line

                        debug!(
                            "[PROCESS_LINES DEBUG] socket {}: processing IRC line ({} bytes): {:?}",
                            self.socket,
                            line.len(),
                            line
                        );

                        // Check for specific IRC commands or FiSH markers
                        if line.contains(CMD_PRIVMSG) || line.contains(CMD_NOTICE) {
                            debug!(
                                "[PROCESS_LINES DEBUG] socket {}: detected IRC message command",
                                self.socket
                            );

                            // Check for encrypted content markers
                            if line.contains(ENCRYPTION_PREFIX_OK)
                                || line.contains(ENCRYPTION_PREFIX_FISH)
                                || line.contains(ENCRYPTION_PREFIX_MCPS)
                            {
                                debug!(
                                    "[PROCESS_LINES DEBUG] socket {}: detected encrypted FiSH message",
                                    self.socket
                                );
                            }
                        }

                        if line.contains(KEY_EXCHANGE_INIT) || line.contains(KEY_EXCHANGE_PUBKEY) {
                            debug!(
                                "[PROCESS_LINES DEBUG] socket {}: detected FiSH key exchange",
                                self.socket
                            );
                        }
                    }

                    // Reuse the buffer instead of allocating a new string
                    line_buffer.clear();
                    line_buffer.push_str(line);
                    line_buffer.push_str("\r\n");

                    // Process the line through the engines (decryption happens here)
                    self.on_incoming_irc_line(self.socket, &mut line_buffer);

                    bytes_processed += line_buffer.len();

                    // Robust lock handling for stats with recovery strategy
                    match self.stats.try_lock() {
                        Some(mut stats) => {
                            stats.lines_received += 1;
                        }
                        None => {
                            // Log but continue processing
                            warn!(
                                "Socket {}: could not update stats, mutex unavailable",
                                self.socket
                            );
                        }
                    }

                    // Robust lock handling for processed buffer with recovery strategy
                    match self.processed_incoming_buffer.try_lock() {
                        Some(mut buffer) => {
                            buffer.extend(line_buffer.as_bytes());

                            #[cfg(debug_assertions)]
                            {
                                debug!(
                                    "[PROCESS_LINES DEBUG] socket {}: added {} bytes to processed_incoming_buffer (total now: {} bytes)",
                                    self.socket,
                                    line_buffer.len(),
                                    buffer.len()
                                );
                            }
                        }
                        None => {
                            // Log but continue with next line
                            warn!(
                                "Socket {}: could not update processed buffer, mutex unavailable",
                                self.socket
                            );
                        }
                    }

                    lines_processed += 1;
                }

                info!(
                    "Socket {}: processed {} lines ({} bytes)",
                    self.socket, lines_processed, bytes_processed
                );

                #[cfg(debug_assertions)]
                {
                    debug!(
                        "[PROCESS_LINES DEBUG] socket {}: finished processing, {} lines total",
                        self.socket, lines_processed
                    );
                }

                Ok(())
            }
            Err(e) => {
                trace!("Socket {}: [IN RAW] Non-UTF8 data", self.socket);
                warn!("Socket {}: received data contains invalid UTF-8: {}", self.socket, e);

                Err(SocketError::ProtocolError(format!("FromUtf8Error: {}", e)))
            }
        }
    }

    /// Read data from the processed buffer for mIRC    
    pub fn read_processed_data(&self, buffer: &mut [u8]) -> usize {
        // Safely handle potential lock issues without catch_unwind
        // which avoids the UnwindSafe requirement
        match self.processed_incoming_buffer.try_lock() {
            Some(mut processed) => {
                let bytes_to_copy = std::cmp::min(buffer.len(), processed.len());

                if bytes_to_copy == 0 {
                    return 0; // Nothing to copy
                }

                // Use a safer approach with try/catch pattern
                let copy_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    let (slice1, slice2) = processed.as_slices();
                    let total_bytes = slice1.len() + slice2.len();

                    // Additional validation to prevent potential out-of-bounds access
                    if total_bytes < bytes_to_copy {
                        warn!(
                            "Socket {}: buffer inconsistency detected in read_processed_data: expected at least {} bytes but found {}",
                            self.socket, bytes_to_copy, total_bytes
                        );
                        return 0;
                    }

                    if bytes_to_copy <= slice1.len() {
                        buffer[..bytes_to_copy].copy_from_slice(&slice1[..bytes_to_copy]);
                    } else {
                        buffer[..slice1.len()].copy_from_slice(slice1);
                        let second_part_size = bytes_to_copy - slice1.len();

                        // Validate second_part_size is not larger than slice2
                        if second_part_size > slice2.len() {
                            warn!(
                                "Socket {}: buffer inconsistency detected: trying to copy {} bytes from slice2 but only {} available",
                                self.socket,
                                second_part_size,
                                slice2.len()
                            );
                            return slice1.len(); // Return only what we copied successfully
                        }

                        buffer[slice1.len()..bytes_to_copy]
                            .copy_from_slice(&slice2[..second_part_size]);
                    }

                    bytes_to_copy
                }));

                match copy_result {
                    Ok(bytes_copied) => {
                        // Only drain if the copy was successful
                        if bytes_copied > 0 {
                            processed.drain(..bytes_copied);
                        }
                        bytes_copied
                    }
                    Err(_) => {
                        warn!(
                            "Socket {}: panic occurred while copying from processed buffer",
                            self.socket
                        );
                        0 // Return 0 bytes read on error
                    }
                }
            }
            None => {
                warn!(
                    "Socket {}: could not acquire lock on processed_incoming_buffer",
                    self.socket
                );
                0 // Return zero bytes read if lock cannot be acquired
            }
        }
    }

    /// Called when the socket is closed
    pub fn _notify_close(&self) {
        // Set state first to prevent further processing attempts
        self.set_state(SocketState::Closed);

        // Store the socket ID for logging
        let socket_id = self.socket;

        // Notify engines about the closure
        // We use a direct call instead of catch_unwind due to UnwindSafe constraints
        // This is safe because engine callbacks should be designed to handle errors internally
        self.engines.on_socket_closed(socket_id);

        // Clear buffers with simple error logging
        // For each buffer, we get a lock and clear it directly
        // These operations are unlikely to fail since parking_lot mutexes are robust

        // Clear received buffer
        {
            let mut buffer = self.received_buffer.lock();
            buffer.clear();
        }

        // Clear processed buffer
        {
            let mut buffer = self.processed_incoming_buffer.lock();
            buffer.clear();
        }

        // Clear incoming line buffer
        {
            let mut buffer = self.incoming_line_buffer.lock();
            buffer.clear();
        }

        // Clear outgoing line buffer
        {
            let mut buffer = self.outgoing_line_buffer.lock();
            buffer.clear();
        }

        log::info!("Socket {}: notified engines and cleaned up state.", socket_id);
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

    pub fn get_processed_buffer(&self) -> Vec<u8> {
        self.processed_incoming_buffer.lock().iter().cloned().collect()
    }

    pub fn clear_processed_buffer(&self) {
        self.processed_incoming_buffer.lock().clear();
    }
}
