//! A simple CLI tool to:
//!   - test FiSH 11 DLL functions
//!   - use the dll in command line
//!
//! This file is part of the FiSH_11 project.
//! Written by [GuY], 2025. Licenced under GPL v3.

mod platform_types;
use std::env;
use std::ffi::CString;
use std::os::raw::{c_char, c_int};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use platform_types::{BOOL, DWORD, HWND, LIB_NAME};

mod helpers_cli;
use crate::helpers_cli::{get_output_format, process_mirc_output, validate_config_file};

// Default timeout for DLL operations in seconds
const DEFAULT_TIMEOUT_SECONDS: u64 = 5;

// Special timeout for listkeys command (which may take longer with large key databases)
const DEFAULT_LISTKEYS_TIMEOUT_SECONDS: u64 = 10;

pub const FISH_11_VERSION: &str = env!("CARGO_PKG_VERSION");

// Global flag to control output verbosity
static QUIET_MODE: AtomicBool = AtomicBool::new(false);

// Macro for conditional printing based on quiet mode
macro_rules! info_print {
    ($($arg:tt)*) => {
        if !unsafe { QUIET_MODE.load(Ordering::Relaxed) } {
            println!($($arg)*);
        }
    };
}

// Define the LoadInfo structure that mIRC passes to our DLL
// Updated to match the actual structure in dll_interface.rs
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[allow(non_snake_case)]
struct LoadInfo {
    m_version: DWORD,
    m_hwnd: HWND,
    m_keep: BOOL, // BOOL is c_int (i32)
    m_unicode: BOOL,
    m_beta: DWORD,
    m_bytes: DWORD,
}

// Function signatures for the DLL functions
type DllLoadFn = extern "system" fn(*mut LoadInfo) -> c_int;
type DllFunctionFn =
    extern "system" fn(HWND, HWND, *mut c_char, *mut c_char, c_int, c_int) -> c_int;

/// Helper enum to specify different output formatting styles
#[derive(Debug, Clone, Copy, PartialEq)]
enum OutputFormat {
    /// Standard output - just print the string as-is
    Standard,

    /// Format mIRC /echo commands - extract and format the message part
    MircEcho,

    /// Format output from FiSH11_FileListKeys - handle multiple echo commands
    KeyList,
}

/// Enhanced version of call_dll_function that handles timeouts and detects hanging operations
/// This is used when the direct DLL call might hang (like FiSH11_FileListKeys with large DBs)
fn call_dll_function(
    dll: &libloading::Library,
    function_name: &str,
    params: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Get the function from the DLL
    let function: libloading::Symbol<DllFunctionFn> = unsafe { dll.get(function_name.as_bytes())? };

    // Create buffers for the function call
    // Data buffer that can be used for both input and output
    let c_params = CString::new(params)?;

    // We need to copy the parameters to a mutable buffer since many functions
    // both read from and write to the data parameter
    let buffer_size = fish_11_core::globals::DLL_BUFFER_SIZE;
    let mut data_buffer = vec![0u8; buffer_size];

    // Copy parameters to data buffer
    let param_bytes = c_params.as_bytes_with_nul();
    if !param_bytes.is_empty() && param_bytes.len() < buffer_size {
        data_buffer[..param_bytes.len()].copy_from_slice(param_bytes);
    }

    let data_ptr = data_buffer.as_mut_ptr() as *mut c_char;

    // Secondary parameters buffer (some functions use both data and parms)
    let mut parms_buffer = vec![0u8; buffer_size];
    let parms_ptr = parms_buffer.as_mut_ptr() as *mut c_char;

    // Determine which timeout to use based on the function
    // Use a longer timeout (10s) for potentially slow key-exchange operations
    let timeout = if function_name == "FiSH11_FileListKeys"
        || function_name == "FiSH11_ExchangeKey"
        || function_name == "FiSH11_ProcessPublicKey"
    {
        Duration::from_secs(DEFAULT_LISTKEYS_TIMEOUT_SECONDS)
    } else {
        Duration::from_secs(DEFAULT_TIMEOUT_SECONDS)
    };

    info_print!("Starting function call (timeout set to {:?})...", timeout);
    let start_time = Instant::now();
    // Use a separate thread to detect and report potential hangs
    let is_complete = Arc::new(AtomicBool::new(false));
    let is_complete_clone = is_complete.clone();

    let _timer_handle = std::thread::spawn(move || {
        let start = Instant::now();
        let mut last_report = Instant::now();

        // Loop until timeout or function completes
        while start.elapsed() < timeout && !is_complete_clone.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(100));

            // Report progress every second for long-running operations
            if last_report.elapsed() > Duration::from_secs(1) {
                last_report = Instant::now();
                let elapsed = start.elapsed();
                if elapsed > Duration::from_secs(2) {

                     if !unsafe { QUIET_MODE.load(Ordering::Relaxed) } {
                        println!(
                            "Still waiting... ({:.1?} elapsed, timeout at {:?})",
                            elapsed, timeout
                        );
                     }
                }
            }
        }

        // If we reach here and the operation isn't complete, the timeout has been reached
        if !is_complete_clone.load(Ordering::SeqCst) {
            println!("WARNING : function execution timed out after {:?}.", timeout);
            println!("The DLL function may have hung, press Ctrl+c to break.");
        }
    });
    // Call the function
    info_print!("Calling DLL function {} with parameters : '{}'", function_name, params);

    let result = function(
        std::ptr::null_mut(), // mWnd
        std::ptr::null_mut(), // aWnd
        data_ptr,             // data (input/output)
        parms_ptr,            // parms (additional params)
        1,                    // show (1 = show output, 0 = don't show)
        0,                    // nopause (0 = normal pause behavior)
    );

    // Mark operation as complete to stop the timer thread
    is_complete.store(true, Ordering::SeqCst);

    // Report how long it took
    let elapsed = start_time.elapsed();

    // Log the result and buffer info
    info_print!("DLL function returned code : {}", result);

    // For debugging, examine the first few bytes of the buffer
    unsafe {
        let preview_size = 20.min(buffer_size);
        if preview_size > 0 {
            let bytes: Vec<u8> = std::slice::from_raw_parts(data_ptr as *const u8, preview_size).to_vec();
            
            if !QUIET_MODE.load(Ordering::Relaxed) {
                println!("Buffer first {} bytes : {:?}", preview_size, bytes);

                // Try to convert to string
                if let Ok(preview) = std::str::from_utf8(&bytes) {
                     println!("Buffer preview as string : {}", preview);
                }
            }
        }
    }

    if elapsed > Duration::from_secs(1) {
        info_print!("Function call completed in {:.2?}", elapsed);

        // Special handling for potentially slow operations
        if function_name == "FiSH11_FileListKeys" {
            info_print!("Note : processing large key databases can take time.");
        }
    } // Check the result based on actual mIRC return codes
    if result != 3 && result != 2 && result != 0 && result != 1 {
        info_print!("Warning: DLL function returned unusual value: {}", result);
        // Continue anyway - some functions might use different return codes
    } // Convert buffer to String (handle null terminator)
    let output = if result == 3 || result == 2 || result == 0 || result == 1 {
        // Process any valid return code - the buffer may still contain useful data
        // Find the length of the string (up to null terminator)
        let mut len = 0;
        while len < buffer_size && data_buffer[len] != 0 {
            len += 1;
        }
        // We now handle the DLL output directly without relying on debug logs

        // Check if we have any content
        if len == 0 || (len == 1 && data_buffer[0] == 0) {
            // For listkeys specifically, check the secondary buffer
            if function_name == "FiSH11_FileListKeys" {
                // Check parms buffer as well
                let mut parms_len = 0;
                while parms_len < buffer_size && parms_buffer[parms_len] != 0 {
                    parms_len += 1;
                }

                if parms_len > 0 {
                    match std::str::from_utf8(&parms_buffer[..parms_len]) {
                        Ok(s) => {
                            if !s.is_empty() {
                                return Ok(s.to_string());
                            }
                        }
                        Err(_) => {
                            // Ignore errors in secondary buffer
                        }
                    }
                }

                // If we couldn't get data from the buffers but know the response from the DLL,
                // use a hardcoded message
                return Ok("/echo -a FiSH: No keys stored.".to_string());
            } else {
                "Function completed but returned no output.".to_string()
            }
        } else {
            // Convert to string
            match std::str::from_utf8(&data_buffer[..len]) {
                Ok(s) => {
                    if s.is_empty() && function_name == "FiSH11_FileListKeys" {
                        "No keys found or invalid config path specified.".to_string()
                    } else {
                        s.to_string()
                    }
                }
                Err(e) => {
                    info_print!("Warning : failed to decode result: {}", e);
                    format!("Function completed but returned invalid UTF-8 data (length: {})", len)
                }
            }
        }
    } else {
        format!("Function completed with result code: {}", result)
    };

    Ok(output)
}

/// List all exported functions from the specified DLL
fn list_exports(dll_path: &str) -> Result<(), Box<dyn std::error::Error>> {
    info_print!("Loading DLL: {}", dll_path);

    // Try to load the DLL
    let dll = match unsafe { libloading::Library::new(dll_path) } {
        Ok(dll) => dll,
        Err(e) => {
            println!("Failed to load DLL '{}': {}", dll_path, e);
            println!("Make sure the DLL exists and is compatible with this application.");
            return Err("DLL load failed".into());
        }
    };

    println!("Available FiSH_11 functions :");
    println!("----------------------------");

    // Manually try to get handle for known FiSH11 functions and print which ones are available
    for func_name in [
        "FiSH11_GetVersion",
        "FiSH11_GenKey",
        "FiSH11_FileDelKey",  // Changed from FiSH11_DelKey
        "FiSH11_SetKey",
        "FiSH11_FileGetKey",
        "FiSH11_FileListKeys",
        "FiSH11_ExchangeKey",
        "FiSH11_ProcessPublicKey",
        "FiSH11_EncryptMsg",
        "FiSH11_DecryptMsg",
        "FiSH11_TestCrypt",
        "FiSH11_GetConfigPath",
        "FiSH11_Help",
        "FiSH11_SetMircDir",
        "FiSH11_FileListKeysItem",
        "FiSH11_GetKeyFingerprint",
        "INI_GetBool",
        "INI_GetString",
        "INI_GetInt",
        "FiSH11_InitChannelKey",
        "FiSH11_ProcessChannelKey",
        "FiSH11_GetKeyTTL",
        "FiSH11_GetRatchetState",
        "FiSH11_SetManualChannelKey",
        "FiSH11_SetNetwork",
        "FiSH11_SetKeyFromPlaintext",
        // Functions that were in CLI but not found in DLL:
        // "FiSH11_ImportKey",  // Not in DLL
        // "FiSH11_ExportKey",  // Not in DLL
        // "FiSH11_SetPasswordHash",  // Not in DLL
        // "FiSH11_VerifyPasswordHash",  // Not in DLL
        // "FiSH11_GetKeyInfo",  // Not in DLL
        // "FiSH11_ReKeyAll",  // Not in DLL
    ] {
        let found = unsafe {
            dll.get::<DllFunctionFn>(func_name.as_bytes()).is_ok()
                || dll.get::<DllFunctionFn>(format!("_{}@24", func_name).as_bytes()).is_ok()
        };

        if found {
            println!("✓ {}", func_name);
        } else {
            println!("✗ {} (not available)", func_name);
        }
    }

    println!("\nUse these function names with the fish_11_cli command.");

    Ok(())
}

/// Display a help message with command usage information
fn display_help() {
    println!("FiSH_11 CLI v{} - Command line interface for FiSH_11 DLL", FISH_11_VERSION);
    println!("Usage:");
    println!("  fish_11_cli [options] <dll_path> <command> [parameters...]");
    println!();
    println!("Options:");
    println!("  -q, --quiet     Minimize output messages (useful for scripts)");
    println!();
    println!("Commands:");
    println!("  help                    Show this help message");
    println!("  list                    List available functions in the DLL");
    println!("  getversion              Get the DLL version");
    println!("  genkey                  Generate a new encryption key for a target");
    println!("  setkey                  Set a specific key for a target");
    println!("  getkey                  Get the key for a target");
    println!("  delkey                  Delete a key for a target");
    println!("  listkeys                List all stored keys");
    println!("  listkeysitem            List a specific key item");
    println!("  encrypt                 Encrypt a message");
    println!("  decrypt                 Decrypt a message");
    println!("  testcrypt               Test encryption/decryption cycle");
    println!("  getconfigpath           Get the configuration file path");
    println!("  setmircdir              Set the mIRC directory");
    println!("  ini_getbool             Get a boolean value from the config file");
    println!("  ini_getstring           Get a string value from the config file");
    println!("  ini_getint              Get an integer value from the config file");
    println!("  initchannelkey          Initialize a channel encryption key");
    println!("  processchannelkey       Process a received channel key");
    println!("  getkeyttl               Get the time-to-live for a key");
    println!("  getratchetstate         Get the ratchet state for a channel");
    println!("  setmanualchannelkey     Set a manual channel encryption key");
    println!("  setnetwork              Set the current IRC network");
    println!("  getkeyfingerprint       Get the fingerprint of a key");
    println!("  setkeyfromplaintext     Set a key from plaintext");
    println!();
    println!("Examples:");
    println!("  fish_11_cli fish_11.dll getversion");
    println!("  fish_11_cli fish_11.dll genkey #channel");
    println!("  fish_11_cli fish_11.dll encrypt #channel \"Secret message\"");
    println!("  fish_11_cli fish_11.dll decrypt #channel \"+OK abcdef1234\"");
    println!("  fish_11_cli fish_11.dll listkeys c:\\path\\to\\fish_11.ini");
    println!("  fish_11_cli fish_11.dll ini_getbool process_incoming 1");
    println!("  fish_11_cli fish_11.dll ini_getstring plain_prefix \"\"");
    println!("  fish_11_cli fish_11.dll ini_getint mark_position 0");
    println!("  fish_11_cli fish_11.dll initchannelkey #secret Alice Bob");
    println!("  fish_11_cli fish_11.dll setkeyttl Alice");
    println!("  fish_11_cli fish_11.dll getkeyfingerprint Alice");
    println!("  fish_11_cli fish_11.dll setnetwork EFNet");
}

/// Validate that the command has the required arguments
fn validate_command_args(command: &str, args: &[String]) -> Result<(), String> {
    let arg_count = args.len();
    match command {
        "genkey" | "delkey" | "getkey" | "getkeyfingerprint" | "getkeyttl" | "setkeyttl" | "exchangekey" | "processkey" => {
            if arg_count < 1 {
                let mut msg = format!("Command '{}' requires a target (channel or nickname).", command);
                if command == "genkey" || command == "delkey" || command == "getkey" {
                     msg.push_str("\nTip: if you are specifying a channel (e.g. #channel) in PowerShell, invoke it with quotes (\"#channel\") to prevent it from being treated as a comment (duh).");
                }
                return Err(msg);
            }
        }
        "setkey" | "setkeyfromplaintext" => {
            if arg_count < 2 {
                return Err(format!("Command '{}' requires a target and a key.", command));
            }
        }
        "encrypt" | "decrypt" => {
            if arg_count < 2 {
                return Err(format!("Command '{}' requires a target and a message.", command));
            }
        }
        "initchannelkey" => {
             if arg_count < 1 {
                return Err(format!("Command '{}' requires a channel.", command));
            }
        }
        "setmanualchannelkey" => {
             if arg_count < 2 {
                return Err(format!("Command '{}' requires a channel and a key.", command));
            }
        }
        "ini_getbool" | "ini_getstring" | "ini_getint" => {
             if arg_count < 1 {
                return Err(format!("Command '{}' requires a config key name.", command));
            }
        }
        _ => {}
    }
    Ok(())
}

fn main() {
    // Create debug log
    let debug_log_path = std::path::Path::new("fish11_cli_debug.log");
    if let Ok(mut debug_log) = std::fs::File::create(debug_log_path) {
        use std::io::Write;
        let _ = writeln!(debug_log, "=== CLI DEBUG LOG ===");
        let _ =
            writeln!(debug_log, "Command arguments: {:?}", std::env::args().collect::<Vec<_>>());
    }

    // Get command line arguments
    let args: Vec<String> = env::args().collect();

    // Handle empty arguments
    if args.len() < 2 {
        display_help();
        return;
    }

    // Check for options in the arguments
    let mut processed_args = Vec::new();
    let mut arg_index = 1;

    while arg_index < args.len() {
        match args[arg_index].as_str() {
            "-q" | "--quiet" => {
                // Set quiet mode
                QUIET_MODE.store(true, Ordering::Relaxed);
                arg_index += 1;
            }
            _ => {
                // Not an option, add to processed args
                processed_args.push(args[arg_index].clone());
                arg_index += 1;
            }
        }
    }

    // Handle special help command
    if processed_args.is_empty() || processed_args[0] == "help" {
        display_help();
        return;
    }

    // At this point we should have at least the DLL path and command
    if processed_args.len() < 2 {
        println!("Error : missing required arguments");
        display_help();
        return;
    }

    // Extract the DLL path and command
    let dll_path = &processed_args[0];
    let command = processed_args[1].to_lowercase();

    // Special command to display help
    if command == "help" {
        display_help();
        return;
    }

    // Special command to list exports
    if command == "list" {
        match list_exports(dll_path) {
            Ok(()) => return,
            Err(e) => {
                println!("Error listing exports: {}", e);
                return;
            }
        }
    }

    // Load the DLL
    let dll = match unsafe { libloading::Library::new(dll_path) } {
        Ok(dll) => dll,
        Err(e) => {
            println!("Failed to load DLL '{}' : {}", dll_path, e);
            println!("Make sure the DLL exists and is compatible with this version of FiSH_11 CLI.");
            return;
        }
    };

    info_print!("Successfully loaded DLL: {}", dll_path);

    // Try to find LoadDll with different name patterns (matching the interface)
    // Since we're only going to call FiSH functions, we only need LoadDll for initialization
    let load_dll = unsafe {
        match dll.get::<DllLoadFn>(b"LoadDll") {
            Ok(func) => {
                info_print!("Found LoadDll function");
                Some(func)
            }
            Err(_) => match dll.get::<DllLoadFn>(b"_LoadDll@4") {
                Ok(func) => {
                    info_print!("Found LoadDll() with mangled name '_LoadDll@4'");
                    Some(func)
                }
                Err(_) => {
                    info_print!("Warning : LoadDll() not found with expected name patterns");
                    None
                }
            },
        }
    };

    // Prepare the LOADINFO structure (updated to match actual structure)
    let mut load_info = LoadInfo {
        m_version: 0x00370007, // mIRC version as DWORD
        m_hwnd: std::ptr::null_mut(),
        m_keep: 1,    // BOOL (TRUE)
        m_unicode: 0, // BOOL (FALSE)
        m_beta: 0,
        m_bytes: fish_11_core::globals::DLL_BUFFER_SIZE as DWORD,
    };

    // Call LoadDll if found
    if let Some(load_fn) = load_dll {
        let result = load_fn(&mut load_info);

        if result != 1 {
            info_print!("Warning: LoadDll() returned unexpected value: {}", result);
        } else {
            info_print!("Successfully initialized DLL with LoadDll");
        }
    }

    // Map CLI commands to the appropriate DLL function
    let function_name = match command.as_str() {
        "getversion" => "FiSH11_GetVersion",
        "genkey" => "FiSH11_GenKey",
        "delkey" => "FiSH11_FileDelKey",  // Changed from FiSH11_DelKey
        "setkey" => "FiSH11_SetKey",
        "getkey" => "FiSH11_FileGetKey",
        "listkeys" => "FiSH11_FileListKeys",
        "listfiles" => "FiSH11_FileListKeys",
        "listkeysitem" => "FiSH11_FileListKeysItem",
        "exchangekey" => "FiSH11_ExchangeKey",
        "processkey" => "FiSH11_ProcessPublicKey",
        "encrypt" => "FiSH11_EncryptMsg",
        "decrypt" => "FiSH11_DecryptMsg",
        "testcrypt" => "FiSH11_TestCrypt",
        "getconfigpath" => "FiSH11_GetConfigPath",
        "setmircdir" => "FiSH11_SetMircDir",
        "help" => "FiSH11_Help",
        "ini_getbool" => "INI_GetBool",
        "ini_getstring" => "INI_GetString",
        "ini_getint" => "INI_GetInt",
        "initchannelkey" => "FiSH11_InitChannelKey",
        "processchannelkey" => "FiSH11_ProcessChannelKey",
        "getkeyttl" => "FiSH11_GetKeyTTL",
        "getratchetstate" => "FiSH11_GetRatchetState",
        "setmanualchannelkey" => "FiSH11_SetManualChannelKey",
        "setnetwork" => "FiSH11_SetNetwork",
        "getkeyfingerprint" => "FiSH11_GetKeyFingerprint",
        "setkeyfromplaintext" => "FiSH11_SetKeyFromPlaintext",
        // Removed functions that don't exist in the DLL:
        // "importkey" => "FiSH11_ImportKey",  // Not in DLL
        // "exportkey" => "FiSH11_ExportKey",  // Not in DLL
        // "setpassword" => "FiSH11_SetPasswordHash",  // Not in DLL
        // "verifypassword" => "FiSH11_VerifyPasswordHash",  // Not in DLL
        // "getkeyinfo" => "FiSH11_GetKeyInfo",  // Not in DLL
        // "rekeyall" => "FiSH11_ReKeyAll",  // Not in DLL
        _ => {
            println!("Unknown command: {}", command);
            display_help();
            return;
        }
    };

    info_print!("Calling function: {}", function_name);

    // Validate arguments
    let cmd_args = if processed_args.len() > 2 { &processed_args[2..] } else { &[] };
    if let Err(e) = validate_command_args(&command, cmd_args) {
        println!("Error: {}", e);
        return;
    }

    // Special case for listkeys to validate config file first
    if function_name == "FiSH11_FileListKeys" && processed_args.len() > 2 {
        let config_path = &processed_args[2];
        if !validate_config_file(config_path) {
            println!("Warning : the config file may not be valid or accessible.");
            println!("Continuing with the operation, but it may fail.");
        }
    }

    // Use our enhanced call_dll_function
    let params = if processed_args.len() > 2 {
        processed_args[2..].join(" ").replace('$', "$$")
    } else {
        String::new()
    };

    // Call the DLL function using our enhanced helper that handles timeouts
    match call_dll_function(&dll, function_name, &params) {
        Ok(output) => {
            // For listkeys, directly process the mIRC-formatted output for simplicity
            if function_name == "FiSH11_FileListKeys" {
                // Process the output
                if output.is_empty() {
                    println!("No keys found or empty configuration.");
                } else {
                    // Split by lines and display each line properly
                    let lines = if output.contains("\r\n") {
                        output.split("\r\n").collect::<Vec<&str>>()
                    } else {
                        output.split('\n').collect::<Vec<&str>>()
                    };

                    // Process each line
                    let mut displayed_something = false;

                    for line in lines {
                        // Handle mIRC-style /echo commands
                        if line.starts_with("/echo -a ") {
                            let content = line.trim_start_matches("/echo -a ");

                            // Skip duplicating header if we already printed it
                            if content == "FiSH Keys :" && displayed_something {
                                continue;
                            }

                            println!("{}", content);
                            displayed_something = true;
                        } else if !line.trim().is_empty() {
                            println!("{}", line);
                            displayed_something = true;
                        }
                    }

                if !displayed_something && !output.is_empty() {
                        println!("Raw output: {}", output);
                    }
                }
            } else if function_name == "FiSH11_GenKey" {
                 // For genkey, we want to display the generated key if in quiet mode, 
                 // or include it in the output otherwise.
                 
                 // First, display the success message if NOT in quiet mode
                 if !unsafe { QUIET_MODE.load(Ordering::Relaxed) } {
                     let format = get_output_format(function_name);
                     let formatted_output = process_mirc_output(&output, format);
                     println!("{}", formatted_output);
                 }

                 // Now retrieve the key
                 // The params for genkey are "target [network]", for getkey it's "target"
                 // We need to extract just the target
                 let target = params.split_whitespace().next().unwrap_or(&params);
                 
                 match call_dll_function(&dll, "FiSH11_FileGetKey", target) {
                     Ok(key_output) => {
                         let valid_key = key_output.contains("+OK ") || key_output.len() > 10; // Simple validation check
                         
                         if unsafe { QUIET_MODE.load(Ordering::Relaxed) } {
                             // quiet mode: print ONLY the key
                             if valid_key {
                                 // The output might be formatted, clean it up if needed.
                                 // FiSH11_FileGetKey usually returns just the key string or similar.
                                 // But let's check if it's mIRC formatted.
                                 let clean_key = process_mirc_output(&key_output, get_output_format("FiSH11_FileGetKey"));
                                 println!("{}", clean_key.trim());
                             } else {
                                 // If we couldn't get the key, print nothing or error?
                                 // User requested "ONLY the key", so maybe stderr if failed?
                                 eprintln!("Error: Failed to retrieve generated key.");
                             }
                         } else {
                             // Normal mode: print the key clearly
                             let clean_key = process_mirc_output(&key_output, get_output_format("FiSH11_FileGetKey"));
                             println!("Key: {}", clean_key.trim());
                         }
                     },
                     Err(e) => {
                         println!("Error retrieving generated key: {}", e);
                     }
                 }

            } else {
                // For other functions, use the normal formatter
                
                // If quiet mode is on, we print ONLY the RESULT, not the formatting
                if unsafe { QUIET_MODE.load(Ordering::Relaxed) } {
                     let format = get_output_format(function_name);
                     let formatted_output = process_mirc_output(&output, format);
                     println!("{}", formatted_output.trim());
                } else {
                    let format = get_output_format(function_name);
                    let formatted_output = process_mirc_output(&output, format);
                    println!("{}", formatted_output);
                }
            }
        }
        Err(e) => {
            // Always show errors even in quiet mode
            println!("Error calling function : {}", e);
            println!("Try using the 'list' command to see available functions.");
        }
    }
    // Debug file handling removed - we now directly process output from the DLL
}
