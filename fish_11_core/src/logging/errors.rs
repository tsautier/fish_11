use std::io;

#[derive(Debug)]
pub enum LogError {
    InitializationFailed,
    WriteError(io::Error),
    IoError(io::Error),
    MutexPoisoned,
    WriteTimeout,
    FlushTimeout,
    ConfigurationError(String),
}

impl std::fmt::Display for LogError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogError::InitializationFailed => write!(f, "Logger initialization failed"),
            LogError::WriteError(e) => write!(f, "Write error: {}", e),
            LogError::IoError(e) => write!(f, "IO error: {}", e),
            LogError::MutexPoisoned => write!(f, "Mutex poisoned"),
            LogError::WriteTimeout => write!(f, "Write timeout"),
            LogError::FlushTimeout => write!(f, "Flush timeout"),
            LogError::ConfigurationError(msg) => write!(f, "Configuration error: {}", msg),
        }
    }
}

impl std::error::Error for LogError {}

impl From<io::Error> for LogError {
    fn from(err: io::Error) -> Self {
        LogError::IoError(err)
    }
}
