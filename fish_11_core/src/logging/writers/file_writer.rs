use std::fs::{File, OpenOptions};
use std::io::{Write, BufWriter};
use std::path::Path;
use std::sync::{Arc, Mutex};
use log::Record;
use std::time::Duration;
use crate::logging::errors::LogError;

pub struct FileWriter {
    file: Arc<Mutex<BufWriter<File>>>,
    path: std::path::PathBuf,
    max_size: u64,
    max_files: usize,
    current_size: std::sync::atomic::AtomicU64,
}

impl FileWriter {
    pub fn new(path: &Path, max_size: u64, max_files: usize) -> Self {
        let file = Self::open_file(path);
        let initial_size = file.metadata().map(|m| m.len()).unwrap_or(0);
        
        Self {
            file: Arc::new(Mutex::new(BufWriter::new(file))),
            path: path.to_path_buf(),
            max_size,
            max_files,
            current_size: std::sync::atomic::AtomicU64::new(initial_size),
        }
    }

    fn open_file(path: &Path) -> File {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("Failed to open log file")
    }

    pub fn write_record(&self, record: &Record) -> Result<(), LogError> {
        // Create a timeout mechanism for write operations
        let start_time = std::time::Instant::now();
        let timeout = Duration::from_millis(100); // 100ms timeout

        // Attempt to acquire lock with timeout-like behavior
        loop {
            if start_time.elapsed() > timeout {
                return Err(LogError::WriteTimeout);
            }

            match self.file.try_lock() {
                Ok(mut guard) => {
                    // Format the log record
                    let formatted = self.format_record(record);
                    
                    // Check size before writing
                    let current_size = self.current_size.load(std::sync::atomic::Ordering::Relaxed);
                    if formatted.len() as u64 + current_size > self.max_size {
                        drop(guard); // Release lock before rotation
                        self.rotate_files()?;
                        guard = self.file.lock().map_err(|_| LogError::MutexPoisoned)?; // Re-acquire lock
                    }
                    
                    // Write the record
                    guard.write_all(formatted.as_bytes())
                        .map_err(|e| LogError::WriteError(e))?;
                    
                    // Update size counter
                    self.current_size.fetch_add(formatted.len() as u64, 
                                               std::sync::atomic::Ordering::Relaxed);
                    
                    // Attempt to flush but don't fail if flush fails
                    let _ = guard.flush();
                    
                    return Ok(());
                }
                Err(_) => {
                    // Brief pause before trying again
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
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
        use std::path::Path;

        // Close the current file
        let mut current_file = self.file.lock().map_err(|_| LogError::MutexPoisoned)?;
        
        // Flush and close the current file
        current_file.flush().map_err(|e| LogError::WriteError(e))?;
        
        // Check if we need to rotate
        let metadata = fs::metadata(&self.path).map_err(|e| LogError::IoError(e))?;
        if metadata.len() <= self.max_size {
            return Ok(()); // No need to rotate
        }
        
        drop(current_file); // Release the lock before file operations
        
        // Perform rotation: log.4 -> log.5, log.3 -> log.4, etc.
        for i in (1..=self.max_files).rev() {
            let old_path = self.path.with_extension(format!("{}.{}", self.path.extension().unwrap_or_default(), i));
            let new_path = self.path.with_extension(format!("{}.{}", self.path.extension().unwrap_or_default(), i + 1));
            
            if Path::exists(&old_path) {
                let _ = fs::rename(&old_path, &new_path); // Ignore errors for non-existent files
            }
        }
        
        // Move current log to .1 extension
        let backup_path = self.path.with_extension(format!("{}.1", self.path.extension().unwrap_or_default()));
        let _ = fs::rename(&self.path, &backup_path); // Ignore errors
        
        // Reopen the file
        let new_file = Self::open_file(&self.path);
        let mut new_writer = BufWriter::new(new_file);
        
        // Update our internal state
        let mut guard = self.file.lock().map_err(|_| LogError::MutexPoisoned)?;
        *guard = new_writer;
        self.current_size.store(0, std::sync::atomic::Ordering::Relaxed);
        
        Ok(())
    }

    pub fn flush(&self) -> Result<(), LogError> {
        let mut guard = self.file.lock().map_err(|_| LogError::MutexPoisoned)?;
        guard.flush().map_err(|e| LogError::WriteError(e))
    }
}