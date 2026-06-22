use std::io::{self, Write};

use log::{LevelFilter, Record};

use crate::logging::config::LogConfig;
use crate::logging::context::LogContext;
use crate::logging::errors::LogError;
use crate::logging::formatter;

pub struct ConsoleWriter {
    level: LevelFilter,
}

impl ConsoleWriter {
    pub fn new(level: LevelFilter) -> Self {
        Self { level }
    }

    pub fn write_record(
        &self,
        record: &Record,
        context: &LogContext,
        config: &LogConfig,
    ) -> Result<(), LogError> {
        if record.level() <= self.level {
            let formatted = formatter::format_record(record, context, config);
            let mut stdout = io::stdout();
            stdout.write_all(formatted.as_bytes()).map_err(|e| LogError::WriteError(e))?;
            stdout.flush().map_err(|e| LogError::WriteError(e))?;
        }
        Ok(())
    }

    pub fn flush(&self) -> Result<(), LogError> {
        let mut stdout = io::stdout();
        stdout.flush().map_err(|e| LogError::WriteError(e))?;
        Ok(())
    }
}
