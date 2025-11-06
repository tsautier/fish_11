//! Platform-specific types for the CLI

#[cfg(windows)]
pub use winapi::shared::minwindef::{BOOL, DWORD};
#[cfg(windows)]
pub use winapi::shared::windef::HWND;

#[cfg(not(windows))]
pub type BOOL = std::os::raw::c_int;
#[cfg(not(windows))]
pub type DWORD = u32;
#[cfg(not(windows))]
pub type HWND = *mut std::ffi::c_void;

// Library name depends on platform
#[cfg(windows)]
pub const LIB_NAME: &str = "fish_11.dll";

#[cfg(not(windows))]
pub const LIB_NAME: &str = "libfish_11.so";
