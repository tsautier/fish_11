//! Logging macros to eliminate redundant is_logger_initialized() checks
// TODO : remove this file once all logging is converted to use these macros

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => {
        if crate::logging::is_logger_initialized() {
            log::info!($($arg)*);
        }
    };
}

#[cfg(debug_assertions)]
#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {
        if crate::logging::is_logger_initialized() {
            log::debug!($($arg)*);
        }
    };
}

#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => {};
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => {
        if crate::logging::is_logger_initialized() {
            log::warn!($($arg)*);
        }
    };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => {
        if crate::logging::is_logger_initialized() {
            log::error!($($arg)*);
        }
    };
}

#[cfg(debug_assertions)]
#[macro_export]
macro_rules! log_trace {
    ($($arg:tt)*) => {
        if crate::logging::is_logger_initialized() {
            log::trace!($($arg)*);
        }
    };
}

#[cfg(not(debug_assertions))]
#[macro_export]
macro_rules! log_trace {
    ($($arg:tt)*) => {};
}
