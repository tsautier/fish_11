//! Logging module for FiSH_11
use std::io;
use std::path::PathBuf;

use fish_11_core::globals::{BUILD_DATE, BUILD_TIME, BUILD_VERSION};
use fish_11_core::logging::config::LogConfig;
use fish_11_core::logging::errors::LogError;
use log::LevelFilter;

use crate::{log_debug, log_info};

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

fn build_dll_log_config(_level: LevelFilter) -> Result<LogConfig, LogError> {
    let mut config = LogConfig::for_dll();
    config.file_path = get_log_file_path().map_err(LogError::IoError)?;

    // Preserve previous behavior: the DLL logger always promoted itself to debug verbosity
    // for troubleshooting, even if callers asked for a lower level.
    config.level = LevelFilter::Debug;

    Ok(config)
}

/// Initialize the logger
pub fn init_logger(level: LevelFilter) -> Result<(), LogError> {
    let config = build_dll_log_config(level)?;
    let log_path = config.file_path.clone();

    fish_11_core::logging::init_logging(config)?;

    if is_logger_initialized() {
        log_info!("*********** *********** FiSH_11 : core dll logger initialized *************** ***********");
        log_info!("Logger initialized - writing to: {}", log_path.display());

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

    Ok(())
}

/// Check if the logger has been initialized
pub fn is_logger_initialized() -> bool {
    fish_11_core::logging::is_initialized()
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
