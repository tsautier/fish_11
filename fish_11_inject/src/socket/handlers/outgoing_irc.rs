use log::{debug, trace, warn};

use crate::socket::info::SocketInfo;
use crate::socket::state::{SocketError, SocketState};

impl SocketInfo {
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

                            let mut lines_processed = 0;
                            let mut remaining = String::new();
                            let lines_to_process = line_buf.clone(); // Clone the full content for processing
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
                            *line_buf = remaining;

                            if lines_processed > 0 {
                                trace!(
                                    "Socket {}: processed {} outgoing lines",
                                    self.socket, lines_processed
                                );
                            }
                        }
                        None => {
                            // Handle mutex acquisition failure gracefully
                            warn!(
                                "Socket {}: could not acquire lock on outgoing_line_buffer, skipping processing",
                                self.socket
                            );
                        }
                    }
                } // Lock is released here.
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

    pub fn prepare_outgoing_data(&self, data: &[u8]) -> Result<Vec<u8>, SocketError> {
        let mut output = String::from_utf8_lossy(data).into_owned();
        if self.engines.on_outgoing_irc_line(self.socket, &mut output) {
            Ok(output.into_bytes())
        } else {
            Ok(data.to_vec())
        }
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
}
