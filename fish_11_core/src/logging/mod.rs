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

use std::sync::atomic::{AtomicBool, Ordering};

use config::{LogConfig, LoggingProfile};
// Global logger instance
use unified_logger::UnifiedLogger;

static LOGGER_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init_logging(config: LogConfig) -> Result<(), errors::LogError> {
    if LOGGER_INITIALIZED.load(Ordering::SeqCst) {
        // Already initialized
        return Ok(());
    }

    let max_level = config.level;
    let logger = UnifiedLogger::new(config)?;

    log::set_boxed_logger(Box::new(logger))
        .map(|()| {
            log::set_max_level(max_level);
            LOGGER_INITIALIZED.store(true, Ordering::SeqCst);
        })
        .map_err(|_| errors::LogError::InitializationFailed)
}

pub fn init_logging_for_profile(profile: LoggingProfile) -> Result<(), errors::LogError> {
    init_logging(LogConfig::for_profile(profile))
}

pub fn init_inject_logging() -> Result<(), errors::LogError> {
    init_logging_for_profile(LoggingProfile::Inject)
}

pub fn init_dll_logging() -> Result<(), errors::LogError> {
    init_logging_for_profile(LoggingProfile::Dll)
}

pub fn is_initialized() -> bool {
    LOGGER_INITIALIZED.load(Ordering::SeqCst)
}
