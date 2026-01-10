//! Logging module for FiSH_11
use crate::{log_debug, log_info};
use base64::{Engine as _, engine::general_purpose};
use chacha20poly1305::{
    ChaCha20Poly1305,
    aead::{Aead, KeyInit, OsRng},
};
use fish_11_core::globals::LOGGING_KEY;
use fish_11_core::globals::{BUILD_DATE, BUILD_TIME, BUILD_VERSION};
use log::{LevelFilter, SetLoggerError};
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, Once};
use std::time::Duration;

// Ensure initialization happens only once
static LOGGER_INIT: Once = Once::new();
static mut LOGGER_INITIALIZED: bool = false;

/// A simple logger that writes to a file, with automatic recreation if deleted
pub struct FileLogger {
    level: LevelFilter,
    log_path: PathBuf,
    file: Arc<Mutex<Option<std::fs::File>>>,
}

impl FileLogger {
    /// Create a new file logger with the given log level and path
    pub fn new(level: LevelFilter, log_path: PathBuf, log_file: std::fs::File) -> Self {
        FileLogger { level, log_path, file: Arc::new(Mutex::new(Some(log_file))) }
    }

    /// Try to open or reopen the log file
    fn open_log_file(&self) -> Option<std::fs::File> {
        OpenOptions::new().create(true).append(true).open(&self.log_path).ok()
    }

    // Helper method to handle writing to the log file with timeout
    // Automatically recreates the file if it was deleted
    fn write_to_file(&self, log_message: &str) {
        // Use a larger timeout for logging to prevent blocking issues
        let lock_timeout = Duration::from_millis(2000);
        let start = std::time::Instant::now();

        // Try to get the lock with timeout
        while start.elapsed() < lock_timeout {
            match self.file.try_lock() {
                Ok(mut file_opt) => {
                    // Check if we need to reopen the file (file was deleted or not open)
                    let needs_reopen = match &*file_opt {
                        Some(_) => !self.log_path.exists(),
                        None => true,
                    };

                    if needs_reopen {
                        // Try to reopen/recreate the file
                        *file_opt = self.open_log_file();
                    }

                    // Now try to write
                    if let Some(ref mut file) = *file_opt {
                        if let Err(_e) = file.write_all(log_message.as_bytes()) {
                            // Write failed - file might have been deleted between check and write
                            // Try reopening once more
                            if let Some(mut new_file) = self.open_log_file() {
                                let _ = new_file.write_all(log_message.as_bytes());
                                let _ = new_file.flush();
                                *file_opt = Some(new_file);
                            }
                        } else {
                            let _ = file.flush();
                        }
                    }
                    return; // We're done, exit the loop
                }
                Err(_) => {
                    // Give other threads a chance and then retry
                    std::thread::yield_now();
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }

        // If we reached here, we failed to acquire the lock
        // For DLL safety, we'll silently drop the message
    }
}

impl FileLogger {
    fn encrypt_log_message(
        &self,
        key: &[u8; 32],
        plaintext: &str,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let cipher = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|e| format!("Invalid key length: {}", e))?;

        let nonce =
            <ChaCha20Poly1305 as chacha20poly1305::aead::AeadCore>::generate_nonce(&mut OsRng);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext.as_bytes())
            .map_err(|e| format!("Encryption failed: {}", e))?;

        // Combine nonce and ciphertext, then encode as base64
        let mut result = nonce.to_vec();
        result.extend_from_slice(&ciphertext);

        Ok(general_purpose::STANDARD.encode(&result))
    }
}

impl log::Log for FileLogger {
    fn enabled(&self, metadata: &log::Metadata) -> bool {
        metadata.level() <= self.level
    }

    fn log(&self, record: &log::Record) {
        if self.enabled(record.metadata()) {
            let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");

            let plaintext_message = format!(
                "[{}] {} [{}:{}] {}\n",
                timestamp,
                record.level(),
                record.file().unwrap_or("<unknown>"),
                record.line().unwrap_or(0),
                record.args()
            );

            // Check if logging encryption is enabled by checking for a key
            let encrypted_message = {
                let key_guard = match LOGGING_KEY.lock() {
                    Ok(guard) => guard,
                    Err(_) => {
                        // If we can't acquire the lock, log unencrypted
                        self.write_to_file(&plaintext_message);
                        return;
                    }
                };

                if let Some(ref key_bytes) = *key_guard {
                    // Encrypt the log message
                    match self.encrypt_log_message(key_bytes, &plaintext_message) {
                        Ok(encrypted_data) => {
                            // Prefix encrypted logs with a special marker
                            format!("[ENCRYPTED] {}\n", encrypted_data)
                        }
                        Err(_) => {
                            // If encryption fails, log unencrypted as fallback
                            plaintext_message.clone()
                        }
                    }
                } else {
                    // No key set, log unencrypted
                    plaintext_message.clone()
                }
            };

            self.write_to_file(&encrypted_message);
        }
    }

    fn flush(&self) {
        // Try to get the lock with a short timeout to avoid blocking
        if let Ok(mut file_opt) = self.file.try_lock() {
            if let Some(ref mut file) = *file_opt {
                let _ = file.flush();
            }
        }
    }
}

/// Get the path to the log file
///
/// Returns a path to the log file in a guaranteed writable location.
/// The log file will be named fish_11_dll_YYYY-MM-DD.log where YYYY-MM-DD is the current date.
pub fn get_log_file_path() -> io::Result<PathBuf> {
    // Create log filename with date
    let log_filename = format!("fish_11_dll_{}.log", chrono::Local::now().format("%Y-%m-%d"));

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
                Ok(log_path) => {
                    match OpenOptions::new().create(true).append(true).open(&log_path) {
                        Ok(log_file) => {
                            let logger = Box::new(FileLogger::new(effective_level, log_path.clone(), log_file));

                            match log::set_boxed_logger(logger) {
                                Ok(_) => {
                                    log::set_max_level(level);                                    LOGGER_INITIALIZED = true;
                                    // If effective level differs from requested, set max level accordingly
                                    log::set_max_level(effective_level);

                                    // Log to file only, no console output
                                    log_info!("*********** *********** FiSH_11 : core dll logger initialized *************** ***********");

                                    // Log the initialization
                                    log_info!(
                                        "Logger initialized - writing to: {}",
                                        log_path.display()
                                    );

                                    // Log current working directory in the log file too
                                    if let Ok(cwd) = std::env::current_dir() {
                                        log_info!("Current working directory: {}", cwd.display());
                                    }
                                    log_info!("FiSH_11 DLL version: {}", BUILD_VERSION);

                                    log_info!(
                                        "Build date: {}, Build time: {}",
                                        BUILD_DATE.as_str(),
                                        BUILD_TIME.as_str()
                                    );
                                }

                                Err(e) => {
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
        log_info!(
            "Module initialized: {} (version: {} - build date: {} - build time: {}",
            module_name,
            version,
            BUILD_DATE.as_str(),
            BUILD_TIME.as_str()
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
            Some(p) => {
                #[cfg(debug_assertions)]
                log_debug!("ENTER: {} - params: {:?}", function_name, p);
            }
            None => {
                #[cfg(debug_assertions)]
                log_debug!("ENTER: {}", function_name);
            }
        }
    }
}

/// Log a function exit with optional return value
pub fn log_function_exit<T: std::fmt::Debug>(function_name: &str, return_value: Option<T>) {
    if is_logger_initialized() {
        match return_value {
            Some(r) => {
                #[cfg(debug_assertions)]
                log_debug!("EXIT: {} - returned: {:?}", function_name, r);
            }
            None => {
                #[cfg(debug_assertions)]
                log_debug!("EXIT: {}", function_name);
            }
        }
    }
}

/// Log a configuration update or reading
pub fn log_config(context: &str, key: &str, value: &dyn std::fmt::Debug) {
    if is_logger_initialized() {
        #[cfg(debug_assertions)]
        log_debug!("CONFIG [{}]: {} = {:?}", context, key, value);
    }
}
