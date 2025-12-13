use log::{Log, LevelFilter, Metadata, Record};
use std::sync::Arc;
use std::time::Duration;

use crate::logging::writers::{FileWriter, ConsoleWriter};
use crate::logging::context::LogContext;
use crate::logging::security;
use crate::logging::errors::LogError;
use crate::logging::config::LogConfig;

pub struct UnifiedLogger {
    file_writer: Arc<FileWriter>,
    console_writer: Option<ConsoleWriter>,
    config: LogConfig,
    context_enabled: bool,
    mask_sensitive: bool,
}

impl UnifiedLogger {
    pub fn new(config: LogConfig) -> Self {
        let file_writer = Arc::new(FileWriter::new(&config.file_path, config.max_file_size, config.max_files));
        let console_writer = if config.console_output {
            Some(ConsoleWriter::new(config.console_level))
        } else {
            None
        };

        Self {
            file_writer,
            console_writer,
            config,
            context_enabled: config.enable_context,
            mask_sensitive: config.mask_sensitive,
        }
    }

    pub fn log_with_context(&self, record: &Record, context: &LogContext) -> Result<(), LogError> {
        let mut message = format!("{}", record.args());

        // Apply security filtering if enabled
        if self.mask_sensitive {
            message = self.apply_security_filter(&message);
        }

        // Add context if enabled
        if self.context_enabled {
            message = self.add_context(&message, context);
        }

        // Write to file
        self.file_writer.write_record(record)?;

        // Write to console if enabled
        if let Some(ref console_writer) = self.console_writer {
            if record.level() <= self.config.console_level {
                console_writer.write_record(record)?;
            }
        }

        Ok(())
    }

    fn apply_security_filter(&self, message: &str) -> String {
        security::mask_sensitive_data(message)
    }

    fn add_context(&self, message: &str, context: &LogContext) -> String {
        // In a full implementation, this would add context information to the message
        // For now, placeholder implementation
        message.to_string()
    }

    pub fn flush_with_timeout(&self, timeout: Duration) -> Result<(), LogError> {
        // Attempt to flush with a timeout
        let start = std::time::Instant::now();

        // We'll implement a timeout mechanism for flushing
        while start.elapsed() < timeout {
            if self.file_writer.flush().is_ok() {
                if let Some(ref console_writer) = self.console_writer {
                    let _ = console_writer.flush(); // Ignore console flush errors
                }
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        Err(LogError::FlushTimeout)
    }
    
    pub fn max_level(&self) -> LevelFilter {
        self.config.level
    }
}

impl Log for UnifiedLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.config.level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            // Create a default context for logs without explicit context
            let default_context = crate::logging::context::LogContext::default();
            if let Err(e) = self.log_with_context(record, &default_context) {
                eprintln!("Failed to log record: {:?}", e);
            }
        }
    }

    fn flush(&self) {
        let _ = self.flush_with_timeout(Duration::from_millis(100)); // 100ms timeout
    }
}