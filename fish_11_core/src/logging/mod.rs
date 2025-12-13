//use log::Log;
//use std::sync::Mutex;

pub mod config;
pub mod unified_logger;
pub mod writers;
pub mod context;
pub mod security;
pub mod errors;
pub mod filters;
pub mod metrics;

use unified_logger::UnifiedLogger;
use config::LogConfig;

// Global logger instance
static mut LOGGER: Option<UnifiedLogger> = None;
static LOGGER_INIT: std::sync::Once = std::sync::Once::new();

pub fn init_logging(config: LogConfig) -> Result<(), errors::LogError> {
    let result = std::panic::catch_unwind(|| {
        LOGGER_INIT.call_once(|| {
            unsafe {
                LOGGER = Some(UnifiedLogger::new(config));
                log::set_logger(&LOGGER.as_ref().unwrap())
                    .map(|()| log::set_max_level(LOGGER.as_ref().unwrap().max_level()))
                    .expect("Failed to initialize logger");
            }
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