//! Configuration access patterns for FiSH 11

use parking_lot::MutexGuard;

use crate::config::CONFIG;
use crate::config::file_storage::save_config;
use crate::config::models::FishConfig;
use crate::error::{FishError, Result};
use crate::{log_debug, log_warn, log_info, log_error};

/// A read-only guard for the configuration
pub struct ConfigReadGuard<'a> {
    guard: MutexGuard<'a, FishConfig>,
}

/// A read-write guard for the configuration
pub struct ConfigWriteGuard<'a> {
    guard: MutexGuard<'a, FishConfig>,
    modified: bool,
}

impl<'a> ConfigReadGuard<'a> {
    /// Get a reference to the inner configuration
    pub fn config(&self) -> &FishConfig {
        &self.guard
    }
}

impl<'a> ConfigWriteGuard<'a> {
    /// Get a mutable reference to the inner configuration
    pub fn config_mut(&mut self) -> &mut FishConfig {
        self.modified = true;
        self.guard.mark_dirty();
        &mut self.guard
    }

    /// Get a reference to the inner configuration
    pub fn config(&self) -> &FishConfig {
        &self.guard
    }

    /// Mark the configuration as modified
    pub fn mark_modified(&mut self) {
        self.modified = true;
        self.guard.mark_dirty();
    }
    /// Save the configuration if it has been modified
    pub fn save_if_modified(&mut self) -> Result<()> {
        if self.modified || self.guard.is_dirty() {
            log_debug!("ConfigWriteGuard::save_if_modified - saving config due to modifications");
            save_config(&self.guard, None)?;
            self.modified = false;
            // Note: save_config already calls mark_clean() internally
        } else {
            log_debug!("ConfigWriteGuard::save_if_modified - no modifications, skipping save");
        }
        Ok(())
    }
}

impl<'a> Drop for ConfigWriteGuard<'a> {
    fn drop(&mut self) {
        if self.modified || self.guard.is_dirty() {
            // Add logging to track potential double-save issues
            log_debug!("ConfigWriteGuard::drop - attempting to save modified config");
            // Try to save, but ignore errors since we're in a destructor
            match save_config(&self.guard, None) {
                Ok(_) => log_debug!("ConfigWriteGuard::drop - config saved successfully"),
                Err(e) => log_warn!("ConfigWriteGuard::drop - failed to save config: {}", e),
            }
        } else {
            log_debug!("ConfigWriteGuard::drop - config not modified, skipping save");
        }
    }
}

/// Get read-only access to the configuration
pub fn read_config() -> Result<ConfigReadGuard<'static>> {
    let guard = CONFIG.lock();
    Ok(ConfigReadGuard { guard })
}

/// Get read-write access to the configuration
pub fn write_config() -> Result<ConfigWriteGuard<'static>> {
    let guard = CONFIG.lock();
    Ok(ConfigWriteGuard { guard, modified: false })
}
pub fn with_config<F, T>(f: F) -> Result<T>
where
    F: FnOnce(&FishConfig) -> Result<T>,
{
    #[cfg(debug_assertions)]
    log_info!("with_config: Attempting to acquire read lock on CONFIG...");

    // Add timeout to prevent deadlocks
    let timeout = std::time::Duration::from_secs(10); // Increased to 10 seconds
    let start_time = std::time::Instant::now();
    // Try to get the lock with a simple timeout check
    let mut attempts = 0;
    const MAX_ATTEMPTS: usize = 30; // Increased to 30 attempts

    #[cfg(debug_assertions)]
    log_info!("with_config: Starting lock acquisition loop (max attempts: {})...", MAX_ATTEMPTS);

    while attempts < MAX_ATTEMPTS {
        #[cfg(debug_assertions)]
        if attempts == 0 {
            log_info!(
                "with_config: Attempt {} - About to call CONFIG.try_lock()...",
                attempts + 1
            );
        }

        // Check if we've already timed out
        if start_time.elapsed() > timeout {
            log_error!("with_config: operation timed out after {} attempts", attempts);
            return Err(FishError::ConfigError("Config lock timed out".to_string()));
        }

        // Try to get the lock - parking_lot::Mutex doesn't poison and returns Option
        #[cfg(debug_assertions)]
        {
            // Capture some context for debugging: PID, TID, timestamp, attempt
            let pid = std::process::id();
            let tid = std::thread::current().id();
            let now = chrono::Local::now();
            log_debug!(
                "with_config: before try_lock - pid={}, tid={:?}, attempt={}, time={}",
                pid,
                tid,
                attempts + 1,
                now.to_rfc3339()
            );
        }

        match CONFIG.try_lock() {
            Some(guard) => {
                #[cfg(debug_assertions)]
                {
                    let pid = std::process::id();
                    let tid = std::thread::current().id();
                    let now = chrono::Local::now();
                    log_debug!(
                        "with_config: acquired lock - pid={}, tid={:?}, attempts={}, time={}",
                        pid,
                        tid,
                        attempts + 1,
                        now.to_rfc3339()
                    );
                }

                let guard = ConfigReadGuard { guard };
                return f(guard.config());
            }
            None => {
                #[cfg(debug_assertions)]
                {
                    let pid = std::process::id();
                    let tid = std::thread::current().id();
                    let now = chrono::Local::now();
                    log_debug!(
                        "with_config: try_lock WOULD_BLOCK - pid={}, tid={:?}, attempt={}, time={}",
                        pid,
                        tid,
                        attempts + 1,
                        now.to_rfc3339()
                    );

                    // Optional small backtrace to help diagnose where threads are
                    if std::env::var("FISH11_DEBUG_BACKTRACE").is_ok() {
                        let bt = std::backtrace::Backtrace::capture();
                        log_debug!("with_config: backtrace:\n{:?}", bt);
                    }
                }

                // Lock is busy, wait and retry with exponential backoff
                attempts += 1;
                let backoff_ms = 10 + (attempts as u64 * 15); // Base 10ms + 15ms per attempt (up to ~310ms max)
                if attempts % 3 == 0 {
                    log_warn!(
                        "with_config: failed to acquire lock, attempt {}/{}, waiting {}ms",
                        attempts,
                        MAX_ATTEMPTS,
                        backoff_ms
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
            }
        }
    }

    log_error!("with_config: failed to acquire lock after {} attempts", MAX_ATTEMPTS);
    Err(FishError::ConfigError("Failed to acquire config lock".to_string()))
}

/// Run a function with read-write access to the configuration
pub fn with_config_mut<F, T>(f: F) -> Result<T>
where
    F: FnOnce(&mut FishConfig) -> Result<T>,
{
    #[cfg(debug_assertions)]
    log_info!("with_config_mut: Attempting to acquire write lock on CONFIG...");

    // Add timeout to prevent deadlocks
    let timeout = std::time::Duration::from_secs(10); // Increased to 10 seconds
    let start_time = std::time::Instant::now();
    // Try to get the lock with a simple timeout check
    let mut attempts = 0;
    const MAX_ATTEMPTS: usize = 30; // Increased to 30 attempts

    #[cfg(debug_assertions)]
    log_info!(
        "with_config_mut: Starting lock acquisition loop (max attempts: {})...",
        MAX_ATTEMPTS
    );

    while attempts < MAX_ATTEMPTS {
        #[cfg(debug_assertions)]
        if attempts == 0 {
            log_info!(
                "with_config_mut: Attempt {} - About to call CONFIG.try_lock()...",
                attempts + 1
            );
        }

        // Check if we've already timed out
        if start_time.elapsed() > timeout {
            log_error!("with_config_mut: operation timed out after {} attempts", attempts);
            return Err(FishError::ConfigError("Config write lock timed out".to_string()));
        }

        // Try to get the lock - parking_lot::Mutex doesn't poison and returns Option
        #[cfg(debug_assertions)]
        {
            let pid = std::process::id();
            let tid = std::thread::current().id();
            let now = chrono::Local::now();
            log_debug!(
                "with_config_mut: before try_lock - pid={}, tid={:?}, attempt={}, time={}",
                pid,
                tid,
                attempts + 1,
                now.to_rfc3339()
            );
        }

        match CONFIG.try_lock() {
            Some(guard) => {
                #[cfg(debug_assertions)]
                {
                    let pid = std::process::id();
                    let tid = std::thread::current().id();
                    let now = chrono::Local::now();
                    log_debug!(
                        "with_config_mut: acquired lock - pid={}, tid={:?}, attempts={}, time={}",
                        pid,
                        tid,
                        attempts + 1,
                        now.to_rfc3339()
                    );
                }

                log_debug!("with_config_mut: acquired lock after {} attempts", attempts);
                let mut guard = ConfigWriteGuard { guard, modified: false };
                let result = f(guard.config_mut());

                // Check if saving would time out
                if start_time.elapsed() > timeout {
                    log_error!("with_config_mut: timed out before saving");
                    return result;
                }

                // Only save if the operation was successful
                match &result {
                    Ok(_) => {
                        if let Err(e) = guard.save_if_modified() {
                            log_error!("with_config_mut: Error saving config: {}", e);
                            // Mark as not modified to prevent double-save in Drop
                            guard.modified = false;
                        } else {
                            // Successfully saved, mark as not modified to prevent double-save in Drop
                            guard.modified = false;
                        }
                    }
                    Err(_) => {
                        // Operation failed, don't save changes
                        log_debug!("with_config_mut: operation failed, not saving config");
                        guard.modified = false; // Prevent save in Drop
                    }
                }

                return result;
            }
            None => {
                #[cfg(debug_assertions)]
                {
                    let pid = std::process::id();
                    let tid = std::thread::current().id();
                    let now = chrono::Local::now();
                    log_debug!(
                        "with_config_mut: try_lock WOULD_BLOCK - pid={}, tid={:?}, attempt={}, time={}",
                        pid,
                        tid,
                        attempts + 1,
                        now.to_rfc3339()
                    );

                    if std::env::var("FISH11_DEBUG_BACKTRACE").is_ok() {
                        let bt = std::backtrace::Backtrace::capture();
                        log_debug!("with_config_mut: backtrace:\n{:?}", bt);
                    }
                }

                // Lock is busy, wait and retry with exponential backoff
                attempts += 1;
                let backoff_ms = 10 + (attempts as u64 * 15); // Base 10ms + 15ms per attempt (up to ~310ms max)
                if attempts % 3 == 0 {
                    log_warn!(
                        "with_config_mut: failed to acquire lock, attempt {}/{}, waiting {}ms",
                        attempts,
                        MAX_ATTEMPTS,
                        backoff_ms
                    );
                }
                std::thread::sleep(std::time::Duration::from_millis(backoff_ms));
            }
        }
    }

    log_error!("with_config_mut: failed to acquire lock after {} attempts", MAX_ATTEMPTS);
    Err(FishError::ConfigError("Failed to acquire config write lock".to_string()))
}