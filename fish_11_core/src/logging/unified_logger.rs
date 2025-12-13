use log::{LevelFilter, Log, Metadata, Record};
use std::sync::Arc;
use std::time::Duration;

use crate::logging::config::LogConfig;
use crate::logging::context;
use crate::logging::context::LogContext;
use crate::logging::errors::LogError;
use crate::logging::writers::console_writer::ConsoleWriter;
use crate::logging::writers::file_writer::FileWriter;

pub struct UnifiedLogger {
    file_writer: Option<Arc<FileWriter>>,
    console_writer: Option<ConsoleWriter>,
    config: LogConfig,
    context_enabled: bool,
    mask_sensitive: bool,
}

impl UnifiedLogger {
    pub fn new(config: LogConfig) -> Result<Self, LogError> {
        let file_writer = if !config.file_path.to_string_lossy().is_empty() {
            Some(Arc::new(FileWriter::new(
                &config.file_path,
                config.max_file_size,
                config.max_files,
            )?))
        } else {
            None
        };

        let console_writer = if config.console_output {
            Some(ConsoleWriter::new(config.console_level))
        } else {
            None
        };

        let context_enabled = config.enable_context;
        let mask_sensitive = config.mask_sensitive;

        Ok(Self { file_writer, console_writer, config, context_enabled, mask_sensitive })
    }

    /// Attempt to log with context, returns Result for error handling
    fn try_log_with_context(&self, record: &Record, context: &LogContext) -> Result<(), LogError> {
        // Write to file with error handling
        if let Some(ref file_writer) = self.file_writer {
            if let Err(e) =
                file_writer.write_record(record, context, self.mask_sensitive, self.context_enabled)
            {
                eprintln!("[LOGGER ERROR] Failed to write to file: {}", e);
                return Err(e);
            }
        }

        // Write to console if enabled
        if let Some(ref console_writer) = self.console_writer {
            if record.level() <= self.config.console_level {
                if let Err(e) = console_writer.write_record(
                    record,
                    context,
                    self.mask_sensitive,
                    self.context_enabled,
                ) {
                    eprintln!("[LOGGER ERROR] Failed to write to console: {}", e);
                    // Don't return error for console failures
                }
            }
        }

        Ok(())
    }

    pub fn flush_with_timeout(&self, timeout: Duration) -> Result<(), LogError> {
        // Attempt to flush with a timeout
        let start = std::time::Instant::now();

        if let Some(ref file_writer) = self.file_writer {
            while start.elapsed() < timeout {
                if file_writer.flush().is_ok() {
                    break;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        if let Some(ref console_writer) = self.console_writer {
            let _ = console_writer.flush(); // Ignore console flush errors
        }

        Ok(())
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
            let context = context::get_current_context()
                .unwrap_or_else(crate::logging::context::LogContext::default);
            if let Err(e) = self.try_log_with_context(record, &context) {
                eprintln!("Failed to log with context: {:?}", e);
            }
        }
    }

    fn flush(&self) {
        let _ = self.flush_with_timeout(Duration::from_millis(100)); // 100ms timeout
    }
}
