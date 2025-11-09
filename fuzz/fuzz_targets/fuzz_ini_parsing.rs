#![no_main]

use std::io::Write;

use libfuzzer_sys::fuzz_target;
use tempfile::NamedTempFile;

fuzz_target!(|data: &[u8]| {
    // Create a temporary INI file with fuzzer data
    if let Ok(mut temp_file) = NamedTempFile::new() {
        if temp_file.write_all(data).is_ok() {
            let path = temp_file.path().to_path_buf();

            // Try to load the malformed INI
            // This should never panic
            let _ = fish_11::config::load_config(Some(path));
        }
    }
});
