use crate::logging::context::LogContext;
use crate::logging::security;
use log::Record;

pub fn format_record(
    record: &Record,
    context: &LogContext,
    mask_sensitive: bool,
    context_enabled: bool,
) -> String {
    let mut message = format!("{}", record.args());

    if mask_sensitive {
        message = security::mask_sensitive_data(&message);
    }

    if context_enabled {
        message = add_context(&message, context);
    }

    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
    format!("[{}] {} [{}] {}\n", timestamp, record.level(), record.target(), message)
}

fn add_context(message: &str, context: &LogContext) -> String {
    format!("[CTX:{}:{}] {}", context.module, context.function, message)
}
