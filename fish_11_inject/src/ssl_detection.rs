use std::ffi::CString;
use std::ptr;

use log::{debug, info, trace, warn};
use winapi::ctypes::c_char;
use winapi::shared::minwindef::{DWORD, HMODULE};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::psapi::{EnumProcessModules, GetModuleFileNameExA};

#[derive(Debug, Clone)]
pub struct OpenSslInfo {
    pub module_handle: HMODULE,
    pub dll_name: String,
    pub version: String,
    pub ssl_read_addr: *const u8,
    pub ssl_write_addr: *const u8,
}

/// List of possible OpenSSL DLL names to check
const OPENSSL_DLL_NAMES: &[&str] = &[
    // OpenSSL 3.x
    "libssl-3.dll",
    "libssl-3-x64.dll",
    "ssleay32.dll",
    // OpenSSL 1.1.x
    "libssl-1_1.dll",
    "libssl-1_1-x64.dll",
    // OpenSSL 1.0.x (legacy)
    "libeay32.dll",
    "ssleay32.dll",
    // Custom builds
    "ssl.dll",
    "openssl.dll",
    // Application-specific
    "libssl.dll",
    "openssl32.dll",
    "openssl64.dll",
];

/// Get OpenSSL version string from loaded module
unsafe fn get_openssl_version(module: HMODULE) -> Option<String> {
    // Try different version function names
    let version_functions = [
        "OpenSSL_version",      // OpenSSL 1.1.0+
        "SSLeay_version",       // OpenSSL 1.0.x
        "OPENSSL_VERSION_TEXT", // Fallback
    ];

    for func_name in &version_functions {
        let func_name_cstr = CString::new(*func_name).ok()?;
        let version_fn = GetProcAddress(module, func_name_cstr.as_ptr());

        if !version_fn.is_null() {
            if func_name == &"OPENSSL_VERSION_TEXT" {
                // This is a string constant
                let version_ptr = version_fn as *const c_char;
                if !version_ptr.is_null() {
                    let version_cstr = std::ffi::CStr::from_ptr(version_ptr);
                    if let Ok(version_str) = version_cstr.to_str() {
                        return Some(version_str.to_string());
                    }
                }
            } else {
                // This is a function
                type VersionFn = unsafe extern "C" fn(i32) -> *const c_char;
                let version_fn: VersionFn = std::mem::transmute(version_fn);
                let version_ptr = version_fn(0); // OPENSSL_VERSION

                if !version_ptr.is_null() {
                    let version_cstr = std::ffi::CStr::from_ptr(version_ptr);
                    if let Ok(version_str) = version_cstr.to_str() {
                        return Some(version_str.to_string());
                    }
                }
            }
        }
    }

    None
}

/// Find SSL functions in the given module
unsafe fn find_ssl_functions(module: HMODULE) -> Option<(*const u8, *const u8)> {
    let ssl_read = GetProcAddress(module, b"SSL_read\0".as_ptr() as *const i8);
    let ssl_write = GetProcAddress(module, b"SSL_write\0".as_ptr() as *const i8);

    if ssl_read.is_null() || ssl_write.is_null() {
        debug!("SSL functions not found in module {:p}", module);
        return None;
    }

    Some((ssl_read as *const u8, ssl_write as *const u8))
}

/// Get module file name
unsafe fn get_module_filename(module: HMODULE) -> Option<String> {
    let mut filename = vec![0u8; 260]; // MAX_PATH
    let len = GetModuleFileNameExA(
        GetCurrentProcess(),
        module,
        filename.as_mut_ptr() as *mut c_char,
        filename.len() as DWORD,
    );

    if len > 0 {
        filename.truncate(len as usize);
        if let Ok(name) = String::from_utf8(filename) {
            // Extract just the filename
            if let Some(filename_only) = name.split('\\').last() {
                return Some(filename_only.to_string());
            }
        }
    }

    None
}

/// Detect OpenSSL in the current process
pub unsafe fn detect_openssl() -> Option<OpenSslInfo> {
    info!("Scanning for OpenSSL libraries...");

    // Method 1: Try known DLL names
    for &dll_name in OPENSSL_DLL_NAMES {
        let dll_name_cstr = CString::new(dll_name).ok()?;
        let module = GetModuleHandleA(dll_name_cstr.as_ptr());

        if !module.is_null() {
            debug!("Found potential OpenSSL module: {}", dll_name);

            if let Some((ssl_read, ssl_write)) = find_ssl_functions(module) {
                let version = get_openssl_version(module).unwrap_or_else(|| "Unknown".to_string());

                info!("✓ OpenSSL detected: {} ({})", dll_name, version);

                return Some(OpenSslInfo {
                    module_handle: module,
                    dll_name: dll_name.to_string(),
                    version,
                    ssl_read_addr: ssl_read,
                    ssl_write_addr: ssl_write,
                });
            }
        }
    }

    // Method 2: Enumerate all loaded modules
    info!("Scanning all loaded modules for OpenSSL...");

    let mut modules: Vec<HMODULE> = vec![ptr::null_mut(); 1024];
    let mut bytes_needed = 0;

    if EnumProcessModules(
        GetCurrentProcess(),
        modules.as_mut_ptr(),
        (modules.len() * std::mem::size_of::<HMODULE>()) as DWORD,
        &mut bytes_needed,
    ) != 0
    {
        let module_count = (bytes_needed as usize) / std::mem::size_of::<HMODULE>();

        for i in 0..module_count.min(modules.len()) {
            let module = modules[i];
            if module.is_null() {
                continue;
            }

            if let Some(filename) = get_module_filename(module) {
                let filename_lower = filename.to_lowercase();

                // Check if this looks like an OpenSSL DLL
                if filename_lower.contains("ssl") || filename_lower.contains("crypto") {
                    debug!("Checking module: {}", filename);

                    if let Some((ssl_read, ssl_write)) = find_ssl_functions(module) {
                        let version =
                            get_openssl_version(module).unwrap_or_else(|| "Unknown".to_string());

                        info!("✓ OpenSSL detected in: {} ({})", filename, version);

                        return Some(OpenSslInfo {
                            module_handle: module,
                            dll_name: filename,
                            version,
                            ssl_read_addr: ssl_read,
                            ssl_write_addr: ssl_write,
                        });
                    }
                }
            }
        }
    }

    warn!("No OpenSSL library found in current process");
    None
}

/// Validate that OpenSSL is properly loaded and ready
pub unsafe fn validate_openssl(info: &OpenSslInfo) -> Result<(), String> {
    // Check if module is still loaded
    let current_handle = GetModuleHandleA(
        CString::new(info.dll_name.as_str()).map_err(|_| "Invalid DLL name")?.as_ptr(),
    );

    if current_handle != info.module_handle {
        return Err("OpenSSL module handle changed".to_string());
    }

    // Verify SSL functions are still accessible
    if let Some((ssl_read, ssl_write)) = find_ssl_functions(info.module_handle) {
        if ssl_read != info.ssl_read_addr || ssl_write != info.ssl_write_addr {
            return Err("SSL function addresses changed".to_string());
        }
    } else {
        return Err("SSL functions no longer accessible".to_string());
    }

    trace!("OpenSSL validation passed");
    Ok(())
}
