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
        let mut formatted_record = record.clone();

        // Apply security filtering if enabled
        if self.mask_sensitive {
            formatted_record = self.apply_security_filter(formatted_record);
        }

        // Add context if enabled
        if self.context_enabled {
            formatted_record = self.add_context(formatted_record, context);
        }

        // Write to file
        self.file_writer.write_record(&formatted_record)?;

        // Write to console if enabled
        if let Some(ref console_writer) = self.console_writer {
            if record.level() <= self.config.console_level {
                console_writer.write_record(&formatted_record)?;
            }
        }

        Ok(())
    }

    fn apply_security_filter(&self, mut record: Record) -> Record {
        // This is a simplified version - in practice, you'd need to clone the record properly
        // which requires some more complex implementation for the Record type
        // For now, we'll just use the log function to apply the mask
        let args = format!("{}", record.args());
        let masked_args = security::mask_sensitive_data(&args);
        // Note: In full implementation, would need to properly recreate the Record with masked args
        record
    }

    fn add_context(&self, mut record: Record, context: &LogContext) -> Record {
        // In a full implementation, this would add context information to the record
        // For now, placeholder implementation
        record
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