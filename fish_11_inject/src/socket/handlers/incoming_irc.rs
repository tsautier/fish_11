use fish_11_core::globals::{
    CMD_NOTICE, CMD_PRIVMSG, ENCRYPTION_PREFIX_FISH, ENCRYPTION_PREFIX_MCPS, ENCRYPTION_PREFIX_OK,
    KEY_EXCHANGE_INIT, KEY_EXCHANGE_PUBKEY,
};
use log::{debug, info, trace, warn};

use crate::socket::info::SocketInfo;
use crate::socket::state::SocketError;

impl SocketInfo {
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

                // Process data in chunks to avoid large memory allocations
                // and release the lock as soon as possible
                let data_copy = if buffer.len() > 4096 {
                    // For large buffers, process in chunks
                    let mut result = Vec::with_capacity(buffer.len());

                    // Process in 4KB chunks
                    const CHUNK_SIZE: usize = 4096;
                    for chunk in buffer.chunks(CHUNK_SIZE) {
                        result.extend_from_slice(chunk);
                    }

                    // Compact memory to save space
                    result.shrink_to_fit();
                    result
                } else {
                    // For small buffers, clone is efficient enough
                    buffer.clone()
                };

                // Clear buffer now that we've processed the data
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

                // Pre-allocate a buffer for lines with adaptive capacity
                // Estimate initial capacity based on data size
                let estimated_capacity = std::cmp::min(4096, data.len().saturating_add(64));
                let mut line_buffer = String::with_capacity(estimated_capacity);

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
}
