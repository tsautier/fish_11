use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

#[derive(Debug, Default)]
pub struct LogMetrics {
    pub log_count: AtomicU64,
    pub error_count: AtomicU64,
    pub current_loggers: AtomicUsize,
    pub disk_usage: AtomicU64,
}

impl LogMetrics {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn increment_log_count(&self) {
        self.log_count.fetch_add(1, Ordering::SeqCst);
    }

    pub fn increment_error_count(&self) {
        self.error_count.fetch_add(1, Ordering::SeqCst);
    }

    pub fn add_disk_usage(&self, bytes: u64) {
        self.disk_usage.fetch_add(bytes, Ordering::SeqCst);
    }
}
