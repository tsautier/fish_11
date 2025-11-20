use crate::socket::info::SocketInfo;
use crate::socket::state::SocketState;

impl SocketInfo {
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
}
