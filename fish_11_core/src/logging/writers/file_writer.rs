use crate::logging::errors::LogError;
use log::Record;
use rand::Rng;
use std::fs::{File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub struct FileWriter {
    file: Arc<Mutex<BufWriter<File>>>,
    path: std::path::PathBuf,
    max_size: u64,
    max_files: usize,
    current_size: std::sync::atomic::AtomicU64,
}

impl FileWriter {
    pub fn new(path: &Path, max_size: u64, max_files: usize) -> Result<Self, LogError> {
        let file = Self::open_file(path)?;
        let initial_size = file.metadata().map(|m| m.len()).unwrap_or(0);

        Ok(Self {
            file: Arc::new(Mutex::new(BufWriter::new(file))),
            path: path.to_path_buf(),
            max_size,
            max_files,
            current_size: std::sync::atomic::AtomicU64::new(initial_size),
        })
    }

    fn open_file(path: &Path) -> Result<File, LogError> {
        OpenOptions::new().create(true).append(true).open(path).map_err(LogError::IoError)
    }

    pub fn write_record(&self, record: &Record) -> Result<(), LogError> {
        // Create a timeout mechanism for write operations
        let start_time = std::time::Instant::now();
        let timeout = Duration::from_millis(100); // 100ms timeout

        // Exponential backoff configuration
        let mut sleep_duration = Duration::from_micros(10); // Start with 10 microseconds
        let max_sleep_duration = Duration::from_millis(10); // Max 10ms between retries

        // Attempt to acquire lock with exponential backoff
        while start_time.elapsed() < timeout {
            match self.file.try_lock() {
                Ok(mut guard) => {
                    // Format the log record
                    let formatted = self.format_record(record);

                    // Check size before writing
                    let current_size = self.current_size.load(std::sync::atomic::Ordering::Relaxed);
                    if formatted.len() as u64 + current_size > self.max_size {
                        drop(guard); // Release lock before rotation
                        self.rotate_files()?;
                        // Re-acquire lock with timeout
                        guard = match std::time::Instant::now()
                            .checked_add(Duration::from_millis(50))
                            .and_then(|deadline| {
                                while std::time::Instant::now() < deadline {
                                    if let Ok(g) = self.file.try_lock() {
                                        return Some(g);
                                    }
                                    std::thread::sleep(Duration::from_micros(100));
                                }
                                None
                            }) {
                            Some(g) => g,
                            None => return Err(LogError::WriteTimeout),
                        };
                    }

                    // Write the record
                    match guard.write_all(formatted.as_bytes()) {
                        Ok(_) => {
                            // Update size counter
                            self.current_size.fetch_add(
                                formatted.len() as u64,
                                std::sync::atomic::Ordering::Relaxed,
                            );

                            // Attempt to flush but don't fail if flush fails
                            let _ = guard.flush();

                            return Ok(());
                        }
                        Err(e) => {
                            // Release the lock before returning error
                            drop(guard);
                            return Err(LogError::WriteError(e));
                        }
                    }
                }
                Err(_) => {
                    // Exponential backoff with jitter
                    std::thread::sleep(sleep_duration);

                    // Double the sleep time for next attempt, but cap at max
                    sleep_duration = std::cmp::min(sleep_duration * 2, max_sleep_duration);

                    // Add some randomness to avoid synchronization issues
                    if sleep_duration > Duration::from_micros(100) {
                        let jitter_val = rand::thread_rng().gen_range(0..(sleep_duration.as_micros() / 2) as u64);
                        std::thread::sleep(Duration::from_micros(jitter_val));
                    }
                }
            }
        }

        // Timeout reached
        Err(LogError::WriteTimeout)
    }

    fn format_record(&self, record: &Record) -> String {
        use chrono::Local;

        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
        let level = record.level();
        let target = record.target();
        let args = record.args();

        format!("[{}] {} [{}] {}\n", timestamp, level, target, args)
    }

    fn rotate_files(&self) -> Result<(), LogError> {
        use std::fs;
        use std::io::Write;
        use std::path::Path;

        // Create a rotation lock file to prevent concurrent rotations
        let rotation_lock_path = self.path.with_extension("rotating.lock");
        let mut rotation_lock =
            match OpenOptions::new().create_new(true).write(true).open(&rotation_lock_path) {
                Ok(lock_file) => lock_file,
                Err(_) => {
                    // Rotation already in progress by another thread/process
                    return Err(LogError::IoError(std::io::Error::new(
                        std::io::ErrorKind::WouldBlock,
                        "Rotation already in progress",
                    )));
                }
            };

        // Write our process ID to the lock file for debugging
        let _ = writeln!(rotation_lock, "{}", std::process::id());
        let _ = rotation_lock.flush();

        // Close the current file
        let mut current_file = self.file.lock().map_err(|_| LogError::MutexPoisoned)?;
        current_file.flush().map_err(|e| LogError::WriteError(e))?;

        // Check if we need to rotate
        let metadata = fs::metadata(&self.path).map_err(|e| LogError::IoError(e))?;
        if metadata.len() <= self.max_size {
            // Clean up lock file and return
            let _ = fs::remove_file(&rotation_lock_path);
            return Ok(()); // No need to rotate
        }

        drop(current_file); // Release the lock before file operations

        // Perform atomic rotation with proper error handling
        for i in (1..=self.max_files).rev() {
            let ext = self.path.extension().unwrap_or_default().to_string_lossy();
            let old_path = self.path.with_extension(format!("{}.{}", ext, i));
            let new_path = self.path.with_extension(format!("{}.{}", ext, i + 1));

            // Check if old file exists before attempting rename
            if old_path.exists() {
                // Remove target file if it exists
                if new_path.exists() {
                    fs::remove_file(&new_path).map_err(|e| {
                        LogError::IoError(std::io::Error::new(
                            std::io::ErrorKind::Other,
                            format!("Failed to remove {}: {}", new_path.display(), e),
                        ))
                    })?;
                }

                // Perform the rename
                fs::rename(&old_path, &new_path).map_err(|e| {
                    LogError::IoError(std::io::Error::new(
                        std::io::ErrorKind::Other,
                        format!(
                            "Failed to rename {} to {}: {}",
                            old_path.display(),
                            new_path.display(),
                            e
                        ),
                    ))
                })?;
            }
        }

        // Move current log to .1 extension
        let ext = self.path.extension().unwrap_or_default().to_string_lossy();
        let backup_path =
            self.path.with_extension(format!("{}.1", ext));

        // Remove existing backup if it exists
        if backup_path.exists() {
            fs::remove_file(&backup_path).map_err(|e| {
                LogError::IoError(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    format!("Failed to remove existing backup {}: {}", backup_path.display(), e),
                ))
            })?;
        }

        // Rename current log file
        fs::rename(&self.path, &backup_path).map_err(|e| {
            LogError::IoError(std::io::Error::new(
                std::io::ErrorKind::Other,
                format!(
                    "Failed to rename {} to {}: {}",
                    self.path.display(),
                    backup_path.display(),
                    e
                ),
            ))
        })?;

        // Reopen the file
        let new_file = Self::open_file(&self.path)?;
        let mut new_writer = BufWriter::new(new_file);

        // Update our internal state
        let mut guard = self.file.lock().map_err(|_| LogError::MutexPoisoned)?;
        *guard = new_writer;
        self.current_size.store(0, std::sync::atomic::Ordering::Relaxed);

        // Clean up rotation lock file
        let _ = fs::remove_file(&rotation_lock_path);

        Ok(())
    }

    pub fn flush(&self) -> Result<(), LogError> {
        let mut guard = self.file.lock().map_err(|_| LogError::MutexPoisoned)?;
        guard.flush().map_err(|e| LogError::WriteError(e))
    }
}
