//! Logging module for FiSH_11
//! >> l0gg1ng m0dul3 -- pr3p4r3 ur 4nuz
//

use log::{Level, LevelFilter, Log, Metadata, Record, SetLoggerError};
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::Once;
use std::thread;

// Ensure initialization happens only once
static LOGGER_INIT: Once = Once::new();

/// The one and only logger for the DLL
struct EliteLogger;

impl Log for EliteLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        // We set the max level on the global logger, so this check is sufficient
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        if !self.enabled(record.metadata()) {
            return;
        }

        let log_message = format!(
            "[{}] [{:<5}] [{}] [{:?}] {}\n",
            chrono::Local::now().format("%H:%M:%S%.3f"), // timestamp
            record.level(),                              // level (padded)
            record.target(),                             // module path
            thread::current().id(),                      // thread id
            record.args()                                // the actual message
        );

        // Send to the void, or in this case, a file
        write_to_log_file(&log_message);
    }

    fn flush(&self) {
        // The file is flushed after each write, so this is not strictly necessary,
        // but we'll keep it for compliance.
    }
}

static ELITE_LOGGER: EliteLogger = EliteLogger;

/// Get the path to the log file.
/// The log file will be named fish_11_dll_YYYY-MM-DD.log.
pub fn get_log_file_path() -> io::Result<PathBuf> {
    let log_filename = format!(
        "fish_11_dll_{}.log",
        chrono::Local::now().format("%Y-%m-%d")
    );
    // Safer to use a known writable location if possible, but for a DLL,
    // current directory is often the most reliable place.
    let current_dir = std::env::current_dir()?;
    Ok(current_dir.join(log_filename))
}

/// Helper function to write to the log file.
fn write_to_log_file(message: &str) {
    if let Ok(log_path) = get_log_file_path() {
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(log_path) {
            let _ = file.write_all(message.as_bytes());
            let _ = file.flush();
        }
    }
}

/// Initialize the logger. This can only be called once.
pub fn init_logger() -> Result<(), SetLoggerError> {
    LOGGER_INIT.call_once(|| {
        // Set the global logger
        log::set_logger(&ELITE_LOGGER).expect("!!! critical: could not set logger");
        // Set max level. We can make this configurable later.
        log::set_max_level(LevelFilter::Trace);

        // >> the sacred texts <<
        let header = r#"
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=//
//                                                                                     //
//                   .::.  F i S H _ 1 1  -  l 0 g  i n i t i a l i z e d  .::.          //
//           ..:                                                                 :..   //
//      ..::.   w3lc0m3 t0 th3 m4tr1x, n30. r3l4x & 3nj0y th3 r1d3.              .::..   //
//  ..::.                                                                         .::..//
//-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=//
"#;
        write_to_log_file(header);

        log::log!(target: "fish_11_dll::logging", Level::Info, "FiSH_11 DLL version..: {}", crate::FISH_11_VERSION);
        log::log!(target: "fish_11_dll::logging", Level::Info, "Build date...........: {}", crate::FISH_11_BUILD_DATE);
        if let Ok(p) = get_log_file_path() {
            log::log!(target: "fish_11_dll::logging", Level::Info, "l0g f1l3 l0c4t10n...: {}", p.display());
        }
    });
    Ok(())
}
