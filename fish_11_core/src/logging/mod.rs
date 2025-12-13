//use log::Log;
//use std::sync::Mutex;

pub mod config;
pub mod context;
pub mod errors;
pub mod filters;
pub mod metrics;
pub mod security;
pub mod unified_logger;
pub mod writers;

use config::LogConfig;
use unified_logger::UnifiedLogger;

// Global logger instance
static mut LOGGER: Option<UnifiedLogger> = None;
static LOGGER_INIT: std::sync::Once = std::sync::Once::new();

pub fn init_logging(config: LogConfig) -> Result<(), errors::LogError> {
    let result = std::panic::catch_unwind(|| {
        LOGGER_INIT.call_once(|| unsafe {
            LOGGER = Some(UnifiedLogger::new(config).expect("Failed to create logger"));
            let logger_ref = LOGGER.as_ref().unwrap();
            log::set_logger(logger_ref)
                .map(|()| log::set_max_level(logger_ref.max_level()))
                .expect("Failed to initialize logger");
        });
    });

    match result {
        Ok(()) => Ok(()),
        Err(_) => Err(errors::LogError::InitializationFailed),
    }
}

pub fn is_initialized() -> bool {
    unsafe { LOGGER.is_some() }
}

// Helper function for logging with context
pub fn log_with_context(record: &log::Record, _context: &context::LogContext) {
    log::logger().log(record);
}
