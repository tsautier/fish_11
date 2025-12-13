//use log::Log;
//use std::sync::Mutex;

pub mod config;
pub mod context;
pub mod errors;
pub mod filters;
pub mod formatter;
pub mod metrics;
pub mod security;
pub mod unified_logger;
pub mod writers;

use config::LogConfig;
use unified_logger::UnifiedLogger;

// Global logger instance
use log::LevelFilter;
use std::sync::atomic::{AtomicBool, Ordering};

static LOGGER_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init_logging(config: LogConfig) -> Result<(), errors::LogError> {
    if LOGGER_INITIALIZED.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err()
    {
        // Already initialized
        return Ok(());
    }

    let max_level = config.level;
    let logger = UnifiedLogger::new(config)?;

    log::set_boxed_logger(Box::new(logger))
        .map(|()| log::set_max_level(max_level))
        .map_err(|_| errors::LogError::InitializationFailed)
}

pub fn is_initialized() -> bool {
    LOGGER_INITIALIZED.load(Ordering::SeqCst)
}
