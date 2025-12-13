use std::io::{self, Write};
use log::{Record, LevelFilter};
use crate::logging::errors::LogError;

pub struct NullWriter;

impl NullWriter {
    pub fn new(_level: LevelFilter) -> Self {
        Self
    }

    pub fn write_record(&self, _record: &Record) -> Result<(), LogError> {
        // Do nothing - this is a null writer
        Ok(())
    }

    pub fn flush(&self) -> Result<(), LogError> {
        // Do nothing
        Ok(())
    }
}