#![no_main]

use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

// Import the DLL function to be tested.
use fish_11::dll_interface::fish11_setmircdir::FiSH11_SetMircDir;
use libfuzzer_sys::fuzz_target;

const BUFFER_SIZE: usize = 4096;

fuzz_target!(|data: &[u8]| {
    // The DLL function expects a mutable, null-terminated C-string.
    // We simulate mIRC's buffer behavior.

    // 1. Create a Rust string from fuzzer data (lossy to handle invalid UTF-8).
    let rust_string = String::from_utf8_lossy(data);

    // 2. Allocate a mutable buffer like mIRC would.
    let buffer = unsafe { libc::malloc(BUFFER_SIZE) as *mut c_char };
    if buffer.is_null() {
        // Allocation failed, abort.
        return;
    }

    // 3. Convert to a C-string and copy into the buffer.
    // NOTE: CString::new will fail if the input contains a NUL byte,
    // which is exactly what we want to test. The fuzzer will generate
    // raw byte slices, so we must handle both cases.
    let bytes_with_nul = if rust_string.contains('\0') {
        // If input has NUL, use it as is, just ensure it's null-terminated.
        let mut bytes = rust_string.as_bytes().to_vec();
        bytes.push(0);
        bytes
    } else {
        // Otherwise, let CString add the terminator.
        if let Ok(c_string) = CString::new(rust_string.as_ref()) {
            c_string.into_bytes_with_nul()
        } else {
            // Should not happen if there's no NUL, but as a fallback.
            unsafe {
                libc::free(buffer as *mut libc::c_void);
            }
            return;
        }
    };

    if bytes_with_nul.len() < BUFFER_SIZE {
        unsafe {
            ptr::copy_nonoverlapping(
                bytes_with_nul.as_ptr() as *const c_char,
                buffer,
                bytes_with_nul.len(),
            );
        }

        // 4. Call the unsafe DLL function.
        unsafe {
            // We only care about panics/crashes, so ignore the result.
            let mut show: i32 = 0;
            let mut nopause: i32 = 0;
            let _ = FiSH11_SetMircDir(
                ptr::null_mut(),
                ptr::null_mut(),
                buffer,
                buffer,
                &mut show as *mut i32,
                &mut nopause as *mut i32,
            );
        }
    }

    // 5. Free the allocated buffer to prevent leaks.
    unsafe {
        libc::free(buffer as *mut libc::c_void);
    }
});
