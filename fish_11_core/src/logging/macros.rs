/// Macro de log avec contexte - la plus importante
#[macro_export]
macro_rules! log_with_context {
    ($level:expr, $ctx:expr, $($arg:tt)+) => {
        if log::log_enabled!($level) {
            let record = log::Record::builder()
                .level($level)
                .target(module_path!())
                .args(format_args!($($arg)+))
                .file(file!())
                .line(line!())
                .build();
                
            $crate::logging::log_with_context(&record, $ctx);
        }
    };
}

/// Version simplifiée pour les logs sans contexte explicite
#[macro_export]
macro_rules! log_simple {
    ($level:expr, $($arg:tt)+) => {
        if log::log_enabled!($level) {
            log::log!(
                target: module_path!(),
                $level,
                $($arg)+
            );
        }
    };
}

/// Macros spécifiques avec contexte
#[macro_export]
macro_rules! log_debug_with_context {
    ($ctx:expr, $($arg:tt)+) => {
        $crate::log_with_context!(log::Level::Debug, $ctx, $($arg)+);
    };
}

#[macro_export]
macro_rules! log_info_with_context {
    ($ctx:expr, $($arg:tt)+) => {
        $crate::log_with_context!(log::Level::Info, $ctx, $($arg)+);
    };
}

#[macro_export]
macro_rules! log_warn_with_context {
    ($ctx:expr, $($arg:tt)+) => {
        $crate::log_with_context!(log::Level::Warn, $ctx, $($arg)+);
    };
}

#[macro_export]
macro_rules! log_error_with_context {
    ($ctx:expr, $($arg:tt)+) => {
        $crate::log_with_context!(log::Level::Error, $ctx, $($arg)+);
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