use crate::pointer_validation::unsafe_transmute_validated;
use log::{debug, error};
use std::ffi::CString;
use winapi::ctypes::c_char;
use winapi::shared::minwindef::{DWORD, HMODULE};
use winapi::um::libloaderapi::GetProcAddress;
use winapi::um::processthreadsapi::GetCurrentProcess;
use winapi::um::psapi::GetModuleFileNameExA;

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
    "libssl-1_1.dll",
    "libssl-1_1-x64.dll",
    "libeay32.dll",
    "ssleay32.dll",
    "ssl.dll",
    "openssl.dll",
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
                if let Ok(version_fn_validated) =
                    unsafe_transmute_validated::<VersionFn>(version_fn, Some(module))
                {
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
