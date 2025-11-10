#![no_main]

use libfuzzer_sys::fuzz_target;
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

// Import the DLL function to be tested.
use fish_11_dll::dll_interface::fish11_setkey::FiSH11_SetKey;

const BUFFER_SIZE: usize = 4096;

fuzz_target!(|data: &[u8]| {
    // The DLL function expects a mutable, null-terminated C-string.
    // We simulate mIRC's buffer behavior.

    // 1. Create a Rust string from fuzzer data (lossy to handle invalid UTF-8).
    let rust_string = String::from_utf8_lossy(data);

    // 2. Allocate a mutable buffer like mIRC would.
    let buffer = unsafe {
        libc::malloc(BUFFER_SIZE) as *mut c_char
    };
    if buffer.is_null() {
        // Allocation failed, abort.
        return;
    }

    // 3. Convert to a C-string and copy into the buffer.
    if let Ok(c_string) = CString::new(rust_string.as_ref()) {
        let bytes = c_string.as_bytes_with_nul();
        if bytes.len() < BUFFER_SIZE {
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr() as *const c_char, buffer, bytes.len());
            }

            // 4. Call the unsafe DLL function.
            unsafe {
                // We only care about panics/crashes, so ignore the result.
                let _ = FiSH11_SetKey(ptr::null_mut(), buffer, BUFFER_SIZE as i32);
            }
        }
    }

    // 5. Free the allocated buffer to prevent leaks.
    unsafe {
        libc::free(buffer as *mut libc::c_void);
    }
});
