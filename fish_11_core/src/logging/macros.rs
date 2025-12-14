/// Macro de log avec contexte - la plus importante
#[macro_export]
macro_rules! log_with_context {
    ($level:expr, $function:expr, $($arg:tt)+) => {
        if log::log_enabled!($level) {
            let context = $crate::logging::context::LogContext::new(
                module_path!(),
                $function,
                file!(),
                line!(),
            );
            $crate::logging::context::with_context(context, || {
                log::log!(
                    target: module_path!(),
                    $level,
                    $($arg)+
                );
            });
        }
    };
}

/// Version simplifiée pour les logs sans contexte explicite
#[macro_export]
macro_rules! log_simple {
    ($level:expr, $($arg:tt)+) => {
        log::log!(
            target: module_path!(),
            $level,
            $($arg)+
        );
    };
}

/// Macros spécifiques avec contexte
#[macro_export]
macro_rules! log_debug_with_context {
    ($function:expr, $($arg:tt)+) => {
        $crate::log_with_context!(log::Level::Debug, $function, $($arg)+);
    };
}

#[macro_export]
macro_rules! log_info_with_context {
    ($function:expr, $($arg:tt)+) => {
        $crate::log_with_context!(log::Level::Info, $function, $($arg)+);
    };
}

#[macro_export]
macro_rules! log_warn_with_context {
    ($function:expr, $($arg:tt)+) => {
        $crate::log_with_context!(log::Level::Warn, $function, $($arg)+);
    };
}

#[macro_export]
macro_rules! log_error_with_context {
    ($function:expr, $($arg:tt)+) => {
        $crate::log_with_context!(log::Level::Error, $function, $($arg)+);
    };
}

/// Macros conditionnelles pour les builds de debug
#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)+) => {
        #[cfg(debug_assertions)]
        {
            $crate::log_simple!(log::Level::Debug, $($arg)+);
        }
    };
}

#[macro_export]
macro_rules! log_trace {
    ($($arg:tt)+) => {
        #[cfg(debug_assertions)]
        {
            $crate::log_simple!(log::Level::Trace, $($arg)+);
        }
    };
}
