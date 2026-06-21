use fish_11_core::globals::{
    CMD_NOTICE, CMD_PRIVMSG, ENCRYPTION_PREFIX_FISH, ENCRYPTION_PREFIX_MCPS, ENCRYPTION_PREFIX_OK,
    KEY_EXCHANGE_INIT, KEY_EXCHANGE_PUBKEY,
};
use log::{debug, info, trace, warn};

use crate::socket::info::SocketInfo;
use crate::socket::state::SocketError;

impl SocketInfo {
    /// Process received data as UTF-8 lines.
    ///
    /// Only complete lines (ending with `\r\n`) are passed to the engine for decryption.
    /// Any trailing partial data (incomplete line) is preserved in `received_buffer` so
    /// it can be completed by the next `recv()` call, preventing protocol corruption
    /// from truncated messages.
    pub fn process_received_lines(&self) -> Result<(), SocketError> {
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

                let data_copy = buffer.clone();

                // Clear buffer : only consumed bytes will be restored below if partial data remains
                buffer.clear();

                data_copy
            }
            None => {
                warn!(
                    "Socket {}: could not acquire lock on received_buffer, will retry later",
                    self.socket
                );
                return Ok(());
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

                let estimated_capacity = std::cmp::min(4096, data.len().saturating_add(64));
                let mut line_buffer = String::with_capacity(estimated_capacity);

                // Split into lines. The last element may be a partial line (no trailing \r\n).
                // We only pass complete lines to the engine; partial data is restored into
                // received_buffer so it survives for the next recv() call.
                let segments: Vec<&str> = data_str.split("\r\n").collect();
                let last_segment = segments.last().copied().unwrap_or("");

                for line in segments.iter() {
                    if line.is_empty() && *line == last_segment && !data_str.ends_with("\r\n") {
                        // This is a trailing partial line : do NOT process it
                        break;
                    }

                    if line.is_empty() {
                        continue;
                    }

                    debug!("Socket {}: [IRC IN] {}", self.socket, line);

                    #[cfg(debug_assertions)]
                    {
                        debug!(
                            "[PROCESS_LINES DEBUG] socket {}: processing IRC line ({} bytes): {:?}",
                            self.socket,
                            line.len(),
                            line
                        );

                        if line.contains(CMD_PRIVMSG) || line.contains(CMD_NOTICE) {
                            debug!(
                                "[PROCESS_LINES DEBUG] socket {}: detected IRC message command",
                                self.socket
                            );

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

                    line_buffer.clear();
                    line_buffer.push_str(line);
                    line_buffer.push_str("\r\n");

                    // Process the line through the engines (decryption happens here)
                    self.on_incoming_irc_line(self.socket, &mut line_buffer);

                    bytes_processed += line_buffer.len();

                    match self.stats.try_lock() {
                        Some(mut stats) => {
                            stats.lines_received += 1;
                        }
                        None => {
                            warn!(
                                "Socket {}: could not update stats, mutex unavailable",
                                self.socket
                            );
                        }
                    }

                    // Use blocking lock to prevent silent data loss.
                    // This is safe because processed_incoming_buffer is only locked here
                    // and in get_processed_buffer/clear_processed_buffer which run on the
                    // same thread (recv call stack), so no cross-thread deadlock can occur.
                    {
                        let mut buffer = self.processed_incoming_buffer.lock();
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

                    lines_processed += 1;
                }

                // Restore any trailing partial data into received_buffer so it
                // survives for the next recv() call and avoids protocol corruption.
                if !data_str.ends_with("\r\n") && !last_segment.is_empty() {
                    if let Some(mut buffer) = self.received_buffer.try_lock() {
                        buffer.extend_from_slice(last_segment.as_bytes());
                        #[cfg(debug_assertions)]
                        {
                            debug!(
                                "[PROCESS_LINES DEBUG] socket {}: restored {} bytes of partial data to received_buffer",
                                self.socket,
                                last_segment.len()
                            );
                        }
                    } else {
                        warn!(
                            "Socket {}: could not restore partial data to received_buffer",
                            self.socket
                        );
                    }
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

                // Try to salvage what we can: split on \r\n boundaries and process
                // each segment with lossy UTF-8 conversion. This prevents losing the
                // entire buffer when a single byte is invalid.
                let mut lines_processed = 0;
                let mut line_buffer = String::with_capacity(4096);
                let segments: Vec<&[u8]> = data.split(|&b| b == b'\r').collect();
                let last_segment = segments.last().copied().unwrap_or(&[]);

                for segment in segments.iter() {
                    if segment.is_empty() {
                        continue;
                    }

                    // Skip the trailing \n after \r if present
                    let line_bytes = if segment.last() == Some(&b'\n') {
                        &segment[..segment.len() - 1]
                    } else {
                        segment
                    };

                    if line_bytes.is_empty() {
                        continue;
                    }

                    line_buffer.clear();
                    line_buffer.push_str(&String::from_utf8_lossy(line_bytes));
                    line_buffer.push_str("\r\n");

                    self.on_incoming_irc_line(self.socket, &mut line_buffer);

                    if let Some(mut buffer) = self.processed_incoming_buffer.try_lock() {
                        buffer.extend(line_buffer.as_bytes());
                    }

                    lines_processed += 1;
                }

                // Preserve any trailing data that didn't end with \r\n
                if !data.ends_with(b"\r\n") && !last_segment.is_empty() {
                    if let Some(mut buffer) = self.received_buffer.try_lock() {
                        buffer.extend_from_slice(last_segment);
                    }
                }

                warn!(
                    "Socket {}: salvaged {} lines from non-UTF8 data",
                    self.socket, lines_processed
                );

                Ok(())
            }
        }
    }

    pub fn on_incoming_irc_line(&self, socket: u32, line: &mut String) -> bool {
        self.engines.on_incoming_irc_line(socket, line)
    }
}
