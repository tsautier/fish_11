use once_cell::sync::Lazy;
use regex::Regex;
use std::ffi::c_int;
use std::sync::Mutex;
use std::time::Duration;

pub const MIRC_HALT: c_int = 0;
pub const MIRC_CONTINUE: c_int = 1;
pub const MIRC_COMMAND: c_int = 2;
pub const MIRC_IDENTIFIER: c_int = 3;
pub const MIRC_ERROR: c_int = 4;

// Default maximum bytes that can be returned to mIRC
// Default maximum bytes that can be returned to mIRC. We still cap
// the runtime-reported buffer size to a safe maximum below.
pub const DEFAULT_MIRC_BUFFER_SIZE: usize = 4096;
// Maximum buffer size we will ever report to callers (including content, we'll
// subtract one for the null terminator in get_buffer_size()). This prevents
// accidentally writing too much to caller buffers; mIRC historically uses 900.
pub const MAX_MIRC_BUFFER_SIZE: usize = 900;

/// Timeout duration for key exchange operations in seconds
pub const KEY_EXCHANGE_TIMEOUT_SECONDS: u64 = 10;

// Typical buffer size for mIRC, used for initial allocation
pub const MIRC_TYPICAL_BUFFER_SIZE: usize = 20480;

pub const CRATE_VERSION: &str = env!("CARGO_PKG_VERSION");
pub const CURRENT_YEAR: &str = "2025";

pub const FUNCTION_TIMEOUT_SECONDS: Duration = Duration::from_secs(5);

pub static NICK_VALIDATOR: Lazy<Regex> = Lazy::new(|| {
    // RFC 1459 compliant nickname validation
    Regex::new(r"^[a-zA-Z\[\]\\`_^{|}][a-zA-Z0-9\[\]\\`_^{|}-]{0,15}$")
        .expect("Hardcoded RFC 1459 nickname regex should always be valid")
});

// Mutex for accessing/modifying the maximum buffer size
// This value can be changed at runtime based on mIRC buffer settings
pub static MIRC_BUFFER_SIZE: Mutex<usize> = Mutex::new(DEFAULT_MIRC_BUFFER_SIZE);
