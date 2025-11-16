//
// >> FiSH_11 logging_macros.rs
// >> k3rn3l p4n1c l0gg1ng m0dul3
// >>
// >> nfo: this macro helps add functional context to log lines,
// >> making it easier to trace operations like FFI calls.
//
#[macro_export]
macro_rules! log_ctx {
    ($ctx:expr, $level:ident, $($arg:tt)+) => {
        // Pass the target explicitly to the log macro.
        // The target is where the log appears to come from (the module path).
        // Then, we prepend our custom context `[CTX:...]` to the actual message.
        log::log!(target: module_path!(), log::Level::$level, "[CTX:{}] {}", $ctx, format!($($arg)+));
    };
}
