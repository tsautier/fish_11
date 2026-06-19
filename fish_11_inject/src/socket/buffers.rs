use super::info::SocketInfo;
use log::{debug, info, warn};

impl SocketInfo {
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

    pub fn get_processed_buffer(&self) -> Vec<u8> {
        self.processed_incoming_buffer.lock().iter().cloned().collect()
    }

    pub fn clear_processed_buffer(&self) {
        self.processed_incoming_buffer.lock().clear();
    }
}
