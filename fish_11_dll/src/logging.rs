//! Logging module for FiSH_11

use log::{LevelFilter, SetLoggerError};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;
use crate::{log_info, log_debug};

// Ensure initialization happens only once
static LOGGER_INIT: Once = Once::new();
static mut LOGGER_INITIALIZED: bool = false;

/// A simple logger that writes to both a file and the standard output
pub struct FileLogger {
    level: LevelFilter,
    file: Arc<Mutex<std::fs::File>>,
}

impl FileLogger {
    /// Create a new file logger with the given log level
    pub fn new(level: LevelFilter, log_file: std::fs::File) -> Self {
        FileLogger {
            level,
            file: Arc::new(Mutex::new(log_file)),
        }
    }

    // Helper method to handle writing to the log file with timeout
    fn write_to_file(&self, log_message: &str) {
        // Use a larger timeout for logging to prevent blocking issues
        let lock_timeout = Duration::from_millis(2000); // Increased from 500ms to 2000ms
        let start = std::time::Instant::now();

        // Try to get the lock with timeout
        while start.elapsed() < lock_timeout {
            match self.file.try_lock() {
                Ok(mut file) => {
                    // Successfully got the lock, write the message
                    if let Err(_e) = file.write_all(log_message.as_bytes()) {
                        // Don't use eprintln in a DLL - it can cause issues
                        // Just silently ignore errors
                    } else if let Err(_e) = file.flush() {
                        // Also ignore flush errors silently
                    }
                    return; // We're done, exit the loop
                },
                Err(_) => {
                    // Give other threads a chance and then retry
                    // Increase the sleep time to reduce CPU usage
                    std::thread::yield_now();
                    std::thread::sleep(Duration::from_millis(20)); 
                }
            }
        }

        // If we reached here, we failed to acquire the lock
        // For DLL safety, we'll silently drop the message
    }
}

impl log::Log for FileLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
            let log_message = format!(
                "[{}] {} [{}:{}] {}\n",
                timestamp,
                record.level(),
                record.file().unwrap_or("<unknown>"),
                record.line().unwrap_or(0),
                record.args()
            );



            self.write_to_file(&log_message);
        }
    }

    fn flush(&self) {
        // Try to get the lock with a short timeout to avoid blocking
        if let Ok(mut file) = self.file.try_lock() {
            let _ = file.flush();
        }
    }
}

/// Get the path to the log file
///
/// Returns a path to the log file in a guaranteed writable location.
/// The log file will be named fish_11_dll_YYYY-MM-DD.log where YYYY-MM-DD is the current date.
pub fn get_log_file_path() -> io::Result<PathBuf> {
    // Create log filename with date
    let log_filename = format!(
        "fish_11_dll_{}.log",
        chrono::Local::now().format("%Y-%m-%d")
    );

    // Always use the current directory for logs
    match std::env::current_dir() {
        Ok(current_dir) => Ok(current_dir.join(log_filename)),
        Err(_) => {
            // Last resort fallback to just the filename (which will go in the current directory)
            Ok(PathBuf::from(log_filename))
        }
    }
}

/// Initialize the logger
pub fn init_logger(level: LevelFilter) -> Result<(), SetLoggerError> {
    // Use thread-safe initialization
    unsafe {
        let mut result = Ok(());

        // If the runtime requests debug logging via env var, promote the level
        // Force DEBUG level for troubleshooting
        let effective_level = LevelFilter::Debug;

        LOGGER_INIT.call_once(|| {
            if LOGGER_INITIALIZED {
                return;
            }

            match get_log_file_path() {
                Ok(log_path) => {                        match OpenOptions::new().create(true).append(true).open(&log_path) {
                        Ok(log_file) => {
                            let logger = Box::new(FileLogger::new(effective_level, log_file));

                            match log::set_boxed_logger(logger) {
                                Ok(_) => {                                    log::set_max_level(level);                                    LOGGER_INITIALIZED = true;
                                    // If effective level differs from requested, set max level accordingly
                                    log::set_max_level(effective_level);
                                    
                                    // Log to file only, no console output
                                    log_info!("*********** *********** FiSH_11 core DLL logger initialized *************** ***********");

                                    // Log the initialization
                                    log_info!(
                                        "Logger initialized - writing to: {}",
                                        log_path.display()
                                    );
                                    
                                    // Log current working directory in the log file too
                                    if let Ok(cwd) = std::env::current_dir() {
                                        log_info!("Current working directory: {}", cwd.display());
                                    }
                                    log_info!("FiSH_11 DLL version: {}", crate::FISH_11_VERSION);
                                    log_info!(
                                        "Build date: {}, Build time: {}",
                                        crate::FISH_11_BUILD_DATE,
                                        crate::FISH_11_BUILD_TIME
                                    );
                                }                                Err(e) => {
                                    // Don't output to console, just return error
                                    result = Err(e);
                                }
                            }
                        }                        Err(_) => {
                            // Log to file only, initialization errors are handled silently
                            // to avoid console output
                        }
                    }
                }
                Err(_) => {
                    // Log to file only, initialization errors are handled silently
                    // to avoid console output
                }
            }
        });

        result
    }
}

/// Check if the logger has been initialized
pub fn is_logger_initialized() -> bool {
    unsafe { LOGGER_INITIALIZED }
}

/// Log a module initialization event
pub fn log_module_init(module_name: &str, version: &str) {
    if is_logger_initialized() {
        log_info!("Module initialized: {} (version: {})", module_name, version);
        log_debug!(
            "Module initialization details - Build date: {}, Build time: {}",
            crate::FISH_11_BUILD_DATE,
            crate::FISH_11_BUILD_TIME
        );
    }
}

/// Log a module shutdown event
pub fn log_module_shutdown(module_name: &str) {
    if is_logger_initialized() {
        log_info!("Module shutdown: {}", module_name);
    }
}

/// Log a function entry with parameters
pub fn log_function_entry<T: std::fmt::Debug>(function_name: &str, params: Option<T>) {
    if is_logger_initialized() {
        match params {
            Some(p) => log_debug!("ENTER: {} - params: {:?}", function_name, p),
            None => log_debug!("ENTER: {}", function_name),
        }
    }
}

/// Log a function exit with optional return value
pub fn log_function_exit<T: std::fmt::Debug>(function_name: &str, return_value: Option<T>) {
    if is_logger_initialized() {
        match return_value {
            Some(r) => log_debug!("EXIT: {} - returned: {:?}", function_name, r),
            None => log_debug!("EXIT: {}", function_name),
        }
    }
}

/// Log a configuration update or reading
pub fn log_config(context: &str, key: &str, value: &dyn std::fmt::Debug) {
    if is_logger_initialized() {
        log_debug!("CONFIG [{}]: {} = {:?}", context, key, value);
    }
}
