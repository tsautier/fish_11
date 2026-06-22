use log::Record;

use crate::logging::config::LogConfig;
use crate::logging::context::LogContext;
use crate::logging::security;

pub fn format_record(record: &Record, context: &LogContext, config: &LogConfig) -> String {
    let mut message = format!("{}", record.args());

    if config.mask_sensitive {
        message = security::mask_sensitive_data(&message);
    }

    if config.enable_context {
        message = add_context(&message, context);
    }

    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");

    let mut metadata = Vec::new();
    metadata.push(format!("{}", record.level()));

    if config.include_target {
        metadata.push(record.target().to_string());
    }

    if config.include_source_location {
        let file = record.file().unwrap_or("<unknown>");
        let line = record.line().unwrap_or(0);
        metadata.push(format!("{}:{}", file, line));
    }

    let metadata =
        metadata.into_iter().map(|segment| format!("[{}]", segment)).collect::<Vec<_>>().join(" ");

    format!("[{}] {} {}\n", timestamp, metadata, message)
}

fn add_context(message: &str, context: &LogContext) -> String {
    format!("[CTX:{}:{}] {}", context.module, context.function, message)
}

#[cfg(test)]
mod tests {
    use log::{Level, Record};

    use super::*;

    #[test]
    fn inject_profile_formats_with_source_location() {
        let config = LogConfig::for_inject();
        let context = LogContext::default();
        let record = Record::builder()
            .args(format_args!("hello"))
            .level(Level::Info)
            .target("ignored.target")
            .file(Some("src/test.rs"))
            .line(Some(42))
            .build();

        let formatted = format_record(&record, &context, &config);

        assert!(formatted.contains("[INFO]"));
        assert!(formatted.contains("[src/test.rs:42]"));
        assert!(!formatted.contains("ignored.target"));
        assert!(formatted.contains("hello"));
    }
}
