use chrono::{DateTime, Local};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

// Global counter for unique trace IDs
static TRACE_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
pub struct LogContext {
    pub module: &'static str,
    pub function: &'static str,
    pub trace_id: String,
    pub timestamp: DateTime<Local>,
    pub thread_id: u64,
    pub file: Option<&'static str>,
    pub line: Option<u32>,
}

impl LogContext {
    pub fn new(module: &'static str, function: &'static str) -> Self {
        Self {
            module,
            function,
            trace_id: generate_trace_id(),
            timestamp: Local::now(),
            thread_id: get_thread_id(),
            file: None,
            line: None,
        }
    }

    pub fn with_location(mut self, file: &'static str, line: u32) -> Self {
        self.file = Some(file);
        self.line = Some(line);
        self
    }

    pub fn with_trace_id(mut self, trace_id: String) -> Self {
        self.trace_id = trace_id;
        self
    }
}

impl Default for LogContext {
    fn default() -> Self {
        Self {
            module: "unknown",
            function: "unknown",
            trace_id: generate_trace_id(),
            timestamp: Local::now(),
            thread_id: get_thread_id(),
            file: None,
            line: None,
        }
    }
}

fn generate_trace_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let counter = TRACE_ID_COUNTER.fetch_add(1, Ordering::SeqCst);

    format!("{:016x}{:016x}", now, counter)
}

fn get_thread_id() -> u64 {
    use std::thread;
    // A simple hash of the thread id for consistent identification
    let id = format!("{:?}", thread::current().id());
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    id.hash(&mut hasher);
    hasher.finish()
}

impl fmt::Display for LogContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}::{}[{}]", self.module, self.function, self.trace_id)
    }
}
