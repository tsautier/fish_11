use std::io::Read;
use std::path::Path;

#[cfg(windows)]
use crate::DllFunctionFn;
use crate::{OutputFormat, QUIET_MODE, display_help};

// Macro for conditional printing based on quiet mode
// Macro for conditional printing based on quiet mode
// Note: This needs to match the behavior of the macro in main.rs
// We assume QUIET_MODE is available via crate::QUIET_MODE
macro_rules! info_print {
    ($($arg:tt)*) => {
        if !unsafe { crate::QUIET_MODE.load(std::sync::atomic::Ordering::Relaxed) } {
            println!($($arg)*);
        }
    };
}

/// Helper function to process mIRC-formatted output into CLI-friendly format
pub fn process_mirc_output(output: &str, format: OutputFormat) -> String {
    // Only log debug info if output is not empty
    if !output.is_empty() {
        info_print!("Processing output in format: {:?}", format);
    }

    // Special case for listkeys when no output is returned
    if output.is_empty() && format == OutputFormat::KeyList {
        return "No keys found or function execution failed. Try checking the ini file path."
            .to_string();
    }
    match format {
        OutputFormat::Standard => output.to_string(),

        OutputFormat::MircEcho => {
            // Handle simple /echo -a commands
            if output.starts_with("/echo -a ") {
                output.trim_start_matches("/echo -a ").to_string()
            } else if output.starts_with("/echo") {
                // Handle other echo variants
                let parts: Vec<&str> = output.splitn(3, ' ').collect();
                if parts.len() >= 3 { parts[2].to_string() } else { output.to_string() }
            } else {
                output.to_string()
            }
        }

        OutputFormat::KeyList => {
            // Process multiline output with multiple /echo commands (like from FiSH11_FileListKeys)
            info_print!("DEBUG - Processing as KeyList format");

            // Special case for empty or whitespace-only output
            if output.trim().is_empty() {
                return "No keys found or invalid config path provided.".to_string();
            }

            // Try both Windows and Unix line endings
            let lines = if output.contains("\r\n") {
                output.split("\r\n").collect::<Vec<&str>>()
            } else {
                output.split('\n').collect::<Vec<&str>>()
            };

            info_print!("DEBUG - Split into {} lines", lines.len());

            if lines.is_empty() {
                return "No keys found.".to_string();
            }

            // Check for error messages in the first few lines
            for line in lines.iter().take(3) {
                if line.contains("Error") || line.contains("error") || line.contains("failed") {
                    // If we find an error message, return it directly
                    return line.trim_start_matches("/echo -a ").to_string();
                }
            }

            let mut formatted_output = String::new();
            let mut keys_found = false;

            for line in lines.iter() {
                // Remove debug printing for each line to reduce noise
                if line.starts_with("/echo -a ") {
                    let content = line.trim_start_matches("/echo -a ");

                    // Check for key-specific content to flag if we actually found keys
                    if content.contains("Key:") {
                        keys_found = true;
                    }

                    // Don't add separator lines as-is
                    if content.contains("------------------------") {
                        formatted_output.push('\n');
                    } else {
                        formatted_output.push_str(&format!("{}\n", content));
                    }
                } else if !line.is_empty() {
                    formatted_output.push_str(&format!("{}\n", line));
                }
            }

            // If we never found keys but had output, it's probably an error message
            if !keys_found && !formatted_output.trim().is_empty() {
                // Look for any error message that might be embedded
                if formatted_output.contains("Error")
                    || formatted_output.contains("error")
                    || formatted_output.contains("failed")
                {
                    // Found error message, return just that part
                    return formatted_output.trim().to_string();
                }
            }

            // Return the formatted output, ensuring it's not empty
            if formatted_output.trim().is_empty() && !output.is_empty() {
                output.to_string()
            } else {
                formatted_output
            }
        }
    }
}

/// Helper function to determine which output format to use based on function name
pub fn get_output_format(function_name: &str) -> OutputFormat {
    info_print!("DEBUG - Selecting output format for function: {}", function_name);
    match function_name {
        "FiSH11_FileListKeys" => OutputFormat::KeyList,
        "FiSH11_Help" => OutputFormat::MircEcho,
        "FiSH11_GetVersion" => OutputFormat::MircEcho,
        "FiSH11_GenKey" => OutputFormat::MircEcho,
        "FiSH11_TestCrypt" => OutputFormat::MircEcho,
        "FiSH11_ImportKey" => OutputFormat::MircEcho,
        "FiSH11_ExportKey" => OutputFormat::MircEcho,
        "FiSH11_SetKey" => OutputFormat::MircEcho,
        "FiSH11_GetKeyInfo" => OutputFormat::MircEcho,
        _ => OutputFormat::Standard,
    }
}

/// Validates that a config file exists and is accessible
/// Returns true if the file can be accessed, false if there's a problem
pub fn validate_config_file(file_path: &str) -> bool {
    let path = Path::new(file_path);

    if !path.exists() {
        // Errors should always be printed
        println!("Error: config file '{}' does not exist", file_path);
        return false;
    }

    if !path.is_file() {
         // Errors should always be printed
        println!("Error: '{}' is not a file", file_path);
        return false;
    }

    // Check if the file has a valid extension (.ini)
    let extension = path.extension().and_then(|ext| ext.to_str()).unwrap_or("");
    if extension.to_lowercase() != "ini" {
        info_print!("Warning: config file '{}' does not have .ini extension", file_path);
        // Continue anyway, it might still work
    }

    // Try to read a few bytes to verify we have read access
    match std::fs::File::open(path) {
        Ok(mut file) => {
            // Try to read the first few bytes to confirm readability
            let mut buffer = [0u8; 10];
            match file.read(&mut buffer) {
                Ok(bytes_read) => {
                    if bytes_read > 0 {
                        info_print!("Config file '{}' exists and is readable", file_path);
                        true
                    } else {
                        info_print!("Warning: Config file '{}' is empty", file_path);
                        true
                    }
                }
                Err(e) => {
                    println!("Error: cannot read from config file '{}': {}", file_path, e);
                    false
                }
            }
        }
        Err(e) => {
            println!("Error: cannot open config file '{}': {}", file_path, e);
            false
        }
    }
}


