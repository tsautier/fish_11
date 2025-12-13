use log::{LevelFilter, Log, Metadata, Record};
use std::sync::Arc;
use std::time::Duration;

use crate::logging::config::LogConfig;
use crate::logging::context::LogContext;
use crate::logging::errors::LogError;
use crate::logging::security;
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
        let file_writer =
            FileWriter::new(&config.file_path, config.max_file_size, config.max_files).ok();
        let console_writer = if config.console_output {
            Some(ConsoleWriter::new(config.console_level))
        } else {
            None
        };

        Ok(Self {
            file_writer: file_writer.map(Arc::new),
            console_writer,
            config,
            context_enabled: config.enable_context,
            mask_sensitive: config.mask_sensitive,
        })
    }

    /// Attempt to log with context, returns Result for error handling
    fn try_log_with_context(&self, record: &Record, context: &LogContext) -> Result<(), LogError> {
        // Apply security filtering if enabled by creating a new record with masked args
        let processed_record = if self.mask_sensitive {
            let original_args = format!("{}", record.args());
            let masked_args = self.apply_security_filter(&original_args);

            // Create a new record with the masked arguments
            Record::builder()
                .level(record.level())
                .target(record.target())
                .file(record.file())
                .line(record.line())
                .module_path(record.module_path())
                .args(format_args!("{}", masked_args))
                .build()
        } else {
            // If no masking needed, use the original record
            record.clone()
        };

        // Add context if enabled
        let final_record = if self.context_enabled {
            // For context, we need to modify the message again
            let original_args = format!("{}", processed_record.args());
            let contextualized_message = self.add_context(&original_args, context);

            Record::builder()
                .level(processed_record.level())
                .target(processed_record.target())
                .file(processed_record.file())
                .line(processed_record.line())
                .module_path(processed_record.module_path())
                .args(format_args!("{}", contextualized_message))
                .build()
        } else {
            processed_record
        };

        // Determine which record to write based on whether masking is enabled
        if self.mask_sensitive {
            // Create a new record with masked arguments
            let original_args = format!("{}", final_record.args());
            let masked_args = crate::logging::security::mask_sensitive_data(&original_args);

            let record_to_mask = log::Record::builder()
                .level(final_record.level())
                .target(final_record.target())
                .file(final_record.file())
                .line(final_record.line())
                .module_path(final_record.module_path())
                .args(format_args!("{}", masked_args))
                .build();

            // Write to file with error handling
            if let Some(ref file_writer) = self.file_writer {
                if let Err(e) = file_writer.write_record(&record_to_mask) {
                    // Log the write error to stderr as fallback
                    eprintln!("[LOGGER ERROR] Failed to write to file: {}", e);
                    return Err(e);
                }
            }

            // Write to console if enabled
            if let Some(ref console_writer) = self.console_writer {
                if record_to_mask.level() <= self.config.console_level {
                    if let Err(e) = console_writer.write_record(&record_to_mask) {
                        eprintln!("[LOGGER ERROR] Failed to write to console: {}", e);
                        // Don't return error for console failures - they're less critical
                    }
                }
            }
        } else {
            // Write the original record without masking
            if let Some(ref file_writer) = self.file_writer {
                if let Err(e) = file_writer.write_record(&final_record) {
                    // Log the write error to stderr as fallback
                    eprintln!("[LOGGER ERROR] Failed to write to file: {}", e);
                    return Err(e);
                }
            }

            // Write to console if enabled
            if let Some(ref console_writer) = self.console_writer {
                if final_record.level() <= self.config.console_level {
                    if let Err(e) = console_writer.write_record(&final_record) {
                        eprintln!("[LOGGER ERROR] Failed to write to console: {}", e);
                        // Don't return error for console failures - they're less critical
                    }
                }
            }
        }

        Ok(())
    }

    /// Main logging method with fallback error handling
    pub fn log_with_context(&self, record: &Record, context: &LogContext) {
        // Attempt to log normally
        if let Err(e) = self.try_log_with_context(record, context) {
            // Fallback logging to stderr if primary logging fails
            eprintln!("[LOGGER FALLBACK] {}: {}", record.level(), record.args());

            // Log the error to a separate error log if possible
            if let Err(_) = self.log_fallback_error(&e, record) {
                // Final fallback - just print to stderr
                eprintln!("[CRITICAL LOG FAILURE] Could not log error: {}", e);
            }
        }
    }

    /// Log errors to a separate error log file
    fn log_fallback_error(
        &self,
        error: &LogError,
        original_record: &Record,
    ) -> Result<(), LogError> {
        use std::fs::OpenOptions;
        use std::io::Write;

        let error_log_path = self.config.file_path.with_extension("errors.log");
        let mut error_file = OpenOptions::new().create(true).append(true).open(error_log_path)?;

        writeln!(
            error_file,
            "[{}][ERROR] Logging failed: {}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            error
        )?;

        writeln!(
            error_file,
            "[{}][ORIGINAL] {}",
            chrono::Local::now().format("%Y-%m-%d %H:%M:%S"),
            original_record.args()
        )?;

        error_file.flush()?;

        Ok(())
    }

    fn apply_security_filter(&self, message: &str) -> String {
        security::mask_sensitive_data(message)
    }

    fn add_context(&self, message: &str, context: &LogContext) -> String {
        // Format the context information and prepend it to the message
        format!(
            "[{}:{}:{} {}:{} {}] {}",
            context.timestamp.format("%Y-%m-%d %H:%M:%S%.3f"),
            context.module,
            context.function,
            context.thread_id,
            context.trace_id,
            context.file.map_or_else(
                || "".to_string(),
                |f| {
                    let filename =
                        std::path::Path::new(f).file_name().and_then(|n| n.to_str()).unwrap_or(f);
                    format!("{}:{}", filename, context.line.unwrap_or(0))
                }
            ),
            message
        )
    }

    pub fn flush_with_timeout(&self, timeout: Duration) -> Result<(), LogError> {
        // Attempt to flush with a timeout
        let start = std::time::Instant::now();

        // We'll implement a timeout mechanism for flushing
        while start.elapsed() < timeout {
            let file_ok = if let Some(ref file_writer) = self.file_writer {
                file_writer.flush().is_ok()
            } else {
                true
            };
            if file_ok {
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
            self.log_with_context(record, &default_context);
        }
    }

    fn flush(&self) {
        let _ = self.flush_with_timeout(Duration::from_millis(100)); // 100ms timeout
    }
}
