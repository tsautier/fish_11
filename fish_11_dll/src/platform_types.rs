//! Platform-specific type definitions
//!
//! This module provides type aliases that work across Windows and Unix platforms.
//! On Windows, we use the actual Windows types (HWND, BOOL).
//! On Unix, we define compatible types.

#[cfg(windows)]
pub use winapi::shared::minwindef::BOOL;
#[cfg(windows)]
pub use winapi::shared::windef::HWND;

#[cfg(not(windows))]
pub type HWND = *mut std::ffi::c_void;

#[cfg(not(windows))]
pub type BOOL = std::os::raw::c_int;

// Common C types used across platforms
pub use std::os::raw::{c_char, c_int};

/// Macro for platform-specific ABI
/// On Windows, use "stdcall" (mIRC convention)
/// On Unix, use "C" (standard C calling convention)
#[macro_export]
macro_rules! platform_abi {
    () => {
        #[cfg(windows)]
        {
            "stdcall"
        }
        #[cfg(not(windows))]
        {
            "C"
        }
    };
}

/// Helper macro to export functions with correct ABI
#[macro_export]
macro_rules! export_fn {
    // Windows version
    (
        $vis:vis fn $name:ident($($arg:ident: $ty:ty),*) -> $ret:ty $body:block
    ) => {
        #[cfg(windows)]
        #[no_mangle]
        $vis extern "stdcall" fn $name($($arg: $ty),*) -> $ret $body
        #[cfg(not(windows))]
        #[no_mangle]
        $vis extern "C" fn $name($($arg: $ty),*) -> $ret $body
    };
}
