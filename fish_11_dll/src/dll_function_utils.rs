//! Common utilities for DLL function implementations

use std::ffi::{CStr, c_char};
use std::os::raw::c_int;
use std::time::SystemTime;

use crate::buffer_utils::{BufferError, write_error_to_buffer};
use crate::dll_interface::{MIRC_COMMAND, MIRC_HALT, get_buffer_size};
use crate::{log_debug, log_error, log_info};

/// Result type for DLL function operations
pub type DllResult<T> = Result<T, DllError>;

/// Common DLL function errors
#[derive(Debug)]
pub enum DllError {
    InvalidInput(String),
    BufferError(BufferError),
    ProcessingError(String),
    TimeoutError,
}

impl std::fmt::Display for DllError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DllError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            DllError::BufferError(err) => write!(f, "Buffer error: {}", err),
            DllError::ProcessingError(msg) => write!(f, "Processing error: {}", msg),
            DllError::TimeoutError => write!(f, "Operation timed out"),
        }
    }
}

impl std::error::Error for DllError {}

impl From<BufferError> for DllError {
    fn from(err: BufferError) -> Self {
        DllError::BufferError(err)
    }
}

/// Standard DLL function context containing common data
pub struct DllFunctionContext {
    pub trace_id: String,
    pub buffer_size: usize,
    pub function_name: &'static str,
}

impl DllFunctionContext {
    /// Create a new DLL function context
    pub fn new(function_name: &'static str) -> Self {
        let trace_id = generate_trace_id();
        let buffer_size = get_buffer_size();

        log_info!("{}[{}]: Starting with buffer size {}", function_name, trace_id, buffer_size);
        crate::logging::log_function_entry::<&str>(function_name, None);

        Self { trace_id, buffer_size, function_name }
    }

    /// Log function completion
    pub fn log_completion(&self, return_code: c_int) {
        log_info!(
            "{}[{}]: Function completed with return code {}",
            self.function_name,
            self.trace_id,
            return_code
        );
        crate::logging::log_function_exit(self.function_name, Some(return_code));
    }

    /// Log an error with trace ID
    pub fn log_error(&self, message: &str) {
        log_error!("{}[{}]: {}", self.function_name, self.trace_id, message);
    }

    /// Log debug information with trace ID
    pub fn log_debug(&self, message: &str) {
        log_debug!("{}[{}]: {}", self.function_name, self.trace_id, message);
    }

    /// Log info with trace ID
    pub fn log_info(&self, message: &str) {
        log_info!("{}[{}]: {}", self.function_name, self.trace_id, message);
    }

    /// Log warning with trace ID
    pub fn log_warn(&self, message: &str) {
        crate::log_warn!("{}[{}]: {}", self.function_name, self.trace_id, message);
    }
}

/// Generate a unique trace ID for function call tracking
pub fn generate_trace_id() -> String {
    format!(
        "{:x}",
        SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap_or_default().as_secs()
    )
}

/// Validate basic DLL function parameters
pub fn validate_dll_params(
    data: *mut c_char,
    buffer_size: usize,
    ctx: &DllFunctionContext,
) -> DllResult<()> {
    if data.is_null() {
        ctx.log_error("Data buffer pointer is null");
        return Err(DllError::InvalidInput("Data pointer is null".to_string()));
    }

    if buffer_size <= 1 {
        ctx.log_error(&format!("Invalid buffer size: {}", buffer_size));
        return Err(DllError::InvalidInput(format!("Invalid buffer size: {}", buffer_size)));
    }

    Ok(())
}

/// Safely extract input string from mIRC data buffer
pub fn extract_input_string(data: *mut c_char, ctx: &DllFunctionContext) -> DllResult<String> {
    let input = unsafe {
        match CStr::from_ptr(data).to_str() {
            Ok(s) => s.to_owned(),
            Err(e) => {
                ctx.log_error(&format!("Invalid ANSI input: {}", e));
                return Err(DllError::InvalidInput("Invalid ANSI input".to_string()));
            }
        }
    };

    ctx.log_debug(&format!("Extracted input: '{}'", input));
    Ok(input)
}

/// Handle panic in DLL function and write error to buffer
pub fn handle_dll_panic(
    data: *mut c_char,
    buffer_size: usize,
    ctx: &DllFunctionContext,
    panic_info: Box<dyn std::any::Any + Send>,
) -> c_int {
    ctx.log_error("Panic occurred in function handler");

    let panic_message = if let Some(s) = panic_info.downcast_ref::<&str>() {
        format!("Critical error: {}", s)
    } else if let Some(s) = panic_info.downcast_ref::<String>() {
        format!("Critical error: {}", s)
    } else {
        "Critical error in function".to_string()
    };

    unsafe {
        write_error_to_buffer(data, buffer_size, &panic_message, Some(&ctx.trace_id));
    }

    ctx.log_completion(MIRC_COMMAND);
    MIRC_COMMAND
}

/// Standard DLL function wrapper that handles common patterns
pub fn dll_function_wrapper<F, T>(
    data: *mut c_char,
    function_name: &'static str,
    operation: F,
) -> c_int
where
    F: FnOnce(*mut c_char, &DllFunctionContext) -> DllResult<T> + std::panic::UnwindSafe,
{
    let ctx = DllFunctionContext::new(function_name);
    let buffer_size = ctx.buffer_size;

    // Validate basic parameters
    if let Err(e) = validate_dll_params(data, buffer_size, &ctx) {
        unsafe {
            write_error_to_buffer(data, buffer_size, &e.to_string(), Some(&ctx.trace_id));
        }
        ctx.log_completion(MIRC_HALT);
        return MIRC_HALT;
    }

    // Execute operation with panic handling
    let result = std::panic::catch_unwind(|| operation(data, &ctx));

    match result {
        Ok(Ok(_)) => {
            ctx.log_completion(MIRC_COMMAND);
            MIRC_COMMAND
        }
        Ok(Err(e)) => {
            ctx.log_error(&e.to_string());
            unsafe {
                write_error_to_buffer(data, buffer_size, &e.to_string(), Some(&ctx.trace_id));
            }
            ctx.log_completion(MIRC_COMMAND);
            MIRC_COMMAND
        }
        Err(panic_info) => handle_dll_panic(data, buffer_size, &ctx, panic_info),
    }
}

/// Timeout checking utility
pub struct TimeoutChecker {
    start_time: std::time::Instant,
    timeout_duration: std::time::Duration,
    ctx: String, // Context for logging
}

impl TimeoutChecker {
    pub fn new(timeout_secs: u64, context: &str) -> Self {
        Self {
            start_time: std::time::Instant::now(),
            timeout_duration: std::time::Duration::from_secs(timeout_secs),
            ctx: context.to_string(),
        }
    }

    pub fn check_timeout(&self, stage: &str) -> DllResult<()> {
        if self.start_time.elapsed() > self.timeout_duration {
            let msg = format!("Function timed out at stage: {}", stage);
            log_error!("{}: {}", self.ctx, msg);
            return Err(DllError::TimeoutError);
        }
        Ok(())
    }
}
