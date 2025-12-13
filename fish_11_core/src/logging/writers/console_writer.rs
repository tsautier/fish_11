use crate::logging::errors::LogError;
use log::{LevelFilter, Record};
use std::io::{self, Write};

pub struct ConsoleWriter {
    level: LevelFilter,
}

impl ConsoleWriter {
    pub fn new(level: LevelFilter) -> Self {
        Self { level }
    }

    pub fn write_record(&self, record: &Record) -> Result<(), LogError> {
        if record.level() <= self.level {
            let formatted = self.format_record(record);
            let mut stdout = io::stdout();
            stdout.write_all(formatted.as_bytes()).map_err(|e| LogError::WriteError(e))?;
            stdout.flush().map_err(|e| LogError::WriteError(e))?;
        }
        Ok(())
    }

    fn format_record(&self, record: &Record) -> String {
        use chrono::Local;

        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
        let level = record.level();
        let target = record.target();
        let args = record.args();

        format!("[{}] {} [{}] {}\n", timestamp, level, target, args)
    }

    pub fn flush(&self) -> Result<(), LogError> {
        let mut stdout = io::stdout();
        stdout.flush().map_err(|e| LogError::WriteError(e))?;
        Ok(())
    }
}
