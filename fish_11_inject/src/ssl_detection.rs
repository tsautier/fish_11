use std::ffi::CString;
use std::ptr;

use log::{debug, error, info, trace, warn};
use winapi::ctypes::c_char;
use winapi::shared::minwindef::{DWORD, HMODULE};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::psapi::{EnumProcessModules, GetModuleFileNameExA};
use crate::pointer_validation::unsafe_transmute_validated;

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
    // Custom builds sometimes
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
                
                // Validate and transmute safely
                if let Ok(version_fn_validated) = unsafe_transmute_validated::<VersionFn>(version_fn, Some(module)) {
                    let version_ptr = version_fn_validated(0); // OPENSSL_VERSION

                    if !version_ptr.is_null() {
                        let version_cstr = std::ffi::CStr::from_ptr(version_ptr);
                        if let Ok(version_str) = version_cstr.to_str() {
                            return Some(version_str.to_string());
                        }
                    }
                } else {
                    error!("Failed to validate OpenSSL version function pointer");
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
pub unsafe fn _detect_openssl() -> Option<OpenSslInfo> {
    #[cfg(debug_assertions)]
    info!("detect_openssl: starting OpenSSL detection...");

    info!("Scanning for OpenSSL libraries...");

    #[cfg(debug_assertions)]
    info!(
        "detect_openssl: method 1 => trying known DLL names ({} names)...",
        OPENSSL_DLL_NAMES.len()
    );

    // Method 1: Try known DLL names
    for (idx, &dll_name) in OPENSSL_DLL_NAMES.iter().enumerate() {
        #[cfg(debug_assertions)]
        info!(
            "detect_openssl: [{}/{}] checking '{}'...",
            idx + 1,
            OPENSSL_DLL_NAMES.len(),
            dll_name
        );

        let dll_name_cstr = CString::new(dll_name).ok()?;
        let module = GetModuleHandleA(dll_name_cstr.as_ptr());

        if !module.is_null() {
            debug!("Found potential OpenSSL module: {}", dll_name);
            #[cfg(debug_assertions)]
            info!("detect_openssl: module '{}' loaded at {:p}", dll_name, module);

            #[cfg(debug_assertions)]
            info!("detect_openssl: looking for SSL functions in '{}'...", dll_name);

            if let Some((ssl_read, ssl_write)) = find_ssl_functions(module) {
                #[cfg(debug_assertions)]
                info!(
                    "detect_openssl: SSL functions found in '{}' - SSL_read={:p}, SSL_write={:p}",
                    dll_name, ssl_read, ssl_write
                );

                #[cfg(debug_assertions)]
                info!("detect_openssl: getting OpenSSL version from '{}'...", dll_name);

                let version = get_openssl_version(module).unwrap_or_else(|| "Unknown".to_string());

                info!("!! OpenSSL detected: {} ({})", dll_name, version);

                #[cfg(debug_assertions)]
                info!("detect_openssl: returning OpenSslInfo for '{}'", dll_name);

                return Some(OpenSslInfo {
                    module_handle: module,
                    dll_name: dll_name.to_string(),
                    version,
                    ssl_read_addr: ssl_read,
                    ssl_write_addr: ssl_write,
                });
            } else {
                #[cfg(debug_assertions)]
                info!("detect_openssl: no SSL functions found in '{}'", dll_name);
            }
        } else {
            #[cfg(debug_assertions)]
            info!(
                "detect_openssl: module '{}' not loaded (GetModuleHandleA returned null)",
                dll_name
            );
        }
    }

    #[cfg(debug_assertions)]
    info!("detect_openssl: method 1 failed => no known DLL found");

    // Method 2: Enumerate all loaded modules
    info!("Scanning all loaded modules for OpenSSL...");
    #[cfg(debug_assertions)]
    info!("detect_openssl: method 2 => enumerating all loaded modules...");

    let mut modules: Vec<HMODULE> = vec![ptr::null_mut(); 1024];
    let mut bytes_needed = 0;

    #[cfg(debug_assertions)]
    info!("detect_openssl: calling EnumProcessModules...");

    if EnumProcessModules(
        GetCurrentProcess(),
        modules.as_mut_ptr(),
        (modules.len() * std::mem::size_of::<HMODULE>()) as DWORD,
        &mut bytes_needed,
    ) != 0
    {
        let module_count = (bytes_needed as usize) / std::mem::size_of::<HMODULE>();

        #[cfg(debug_assertions)]
        info!("detect_openssl: EnumProcessModules returned {} modules", module_count);

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
                    #[cfg(debug_assertions)]
                    info!(
                        "detect_openssl: potential SSL module found: '{}' at {:p}",
                        filename, module
                    );

                    if let Some((ssl_read, ssl_write)) = find_ssl_functions(module) {
                        #[cfg(debug_assertions)]
                        info!(
                            "detect_openssl: SSL functions found in '{}' - SSL_read={:p}, SSL_write={:p}",
                            filename, ssl_read, ssl_write
                        );

                        let version =
                            get_openssl_version(module).unwrap_or_else(|| "Unknown".to_string());

                        info!("!! OpenSSL detected in: {} ({})", filename, version);

                        #[cfg(debug_assertions)]
                        info!("detect_openssl: returning OpenSSLInfo for '{}'", filename);

                        return Some(OpenSslInfo {
                            module_handle: module,
                            dll_name: filename,
                            version,
                            ssl_read_addr: ssl_read,
                            ssl_write_addr: ssl_write,
                        });
                    } else {
                        #[cfg(debug_assertions)]
                        info!("detect_openssl: no SSL functions found in '{}'", filename);
                    }
                }
            }
        }
        #[cfg(debug_assertions)]
        info!("detect_openssl: finished scanning all modules, no OpenSSL found");
    } else {
        #[cfg(debug_assertions)]
        error!("detect_openssl: EnumProcessModules failed!");
    }

    warn!("No OpenSSL library found in current process");
    #[cfg(debug_assertions)]
    info!("detect_openssl: OpenSSL detection failed, returning None");

    None
}

/// Validate that OpenSSL is properly loaded and ready
pub unsafe fn _validate_openssl(info: &OpenSslInfo) -> Result<(), String> {
    #[cfg(debug_assertions)]
    info!("validate_openssl: starting OpenSSL validation for '{}'...", info.dll_name);

    #[cfg(debug_assertions)]
    info!("validate_openssl: creating CString for DLL name '{}'...", info.dll_name);

    // Check if module is still loaded
    let current_handle = GetModuleHandleA(
        CString::new(info.dll_name.as_str())
            .map_err(|e| {
                #[cfg(debug_assertions)]
                error!("validate_openssl: failed to create CString: {:?}", e);
                "Invalid DLL name"
            })?
            .as_ptr(),
    );

    #[cfg(debug_assertions)]
    info!(
        "validate_openssl: GetModuleHandleA returned {:p} (expected {:p})",
        current_handle, info.module_handle
    );

    if current_handle != info.module_handle {
        #[cfg(debug_assertions)]
        error!("validate_openssl: module handle mismatch!");
        return Err("OpenSSL module handle changed".to_string());
    }

    #[cfg(debug_assertions)]
    info!("validate_openssl: module handle verification passed");

    #[cfg(debug_assertions)]
    info!("validate_openssl: verifying SSL functions are still accessible...");

    // Verify SSL functions are still accessible
    if let Some((ssl_read, ssl_write)) = find_ssl_functions(info.module_handle) {
        #[cfg(debug_assertions)]
        info!(
            "validate_openssl: SSL functions found - SSL_read={:p} (expected {:p}), SSL_write={:p} (expected {:p})",
            ssl_read, info.ssl_read_addr, ssl_write, info.ssl_write_addr
        );

        if ssl_read != info.ssl_read_addr || ssl_write != info.ssl_write_addr {
            #[cfg(debug_assertions)]
            error!("validate_openssl: SSL function addresses changed!");
            return Err("SSL function addresses changed".to_string());
        }
    } else {
        #[cfg(debug_assertions)]
        error!("validate_openssl: SSL functions no longer accessible!");
        return Err("SSL functions no longer accessible".to_string());
    }

    trace!("OpenSSL validation passed");
    #[cfg(debug_assertions)]
    info!("validate_openssl: OpenSSL validation completed successfully");

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_openssl_info_struct() {
        // Just verify that our OpenSslInfo struct has the expected fields
        let info = OpenSslInfo {
            module_handle: std::ptr::null_mut(),
            dll_name: "test.dll".to_string(),
            version: "1.0.0".to_string(),
            ssl_read_addr: std::ptr::null(),
            ssl_write_addr: std::ptr::null(),
        };

        assert_eq!(info.dll_name, "test.dll");
        assert_eq!(info.version, "1.0.0");
    }

    #[test]
    fn test_openssl_dll_names_array() {
        // Verify that the OPENSSL_DLL_NAMES constant is not empty
        assert!(!OPENSSL_DLL_NAMES.is_empty());

        // Verify that it contains some expected values
        assert!(OPENSSL_DLL_NAMES.contains(&"libssl-3.dll"));
        assert!(OPENSSL_DLL_NAMES.contains(&"libssl-1_1.dll"));
        assert!(OPENSSL_DLL_NAMES.contains(&"ssleay32.dll"));
    }
}
