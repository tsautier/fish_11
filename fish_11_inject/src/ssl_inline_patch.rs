//use std::mem;
use std::ptr::{self};
use std::sync::Mutex;

use log::{error, info, trace, warn};
use winapi::ctypes::c_void;
use winapi::shared::minwindef::DWORD;
use winapi::um::memoryapi::VirtualProtect;
use winapi::um::winnt::{PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE, PAGE_READONLY};

use crate::hook_ssl::{SSL, SslReadFn, SslWriteFn};
use crate::ssl_detection::{OpenSslInfo, detect_openssl, validate_openssl};

// Thread-safe wrapper for OpenSslInfo
#[derive(Clone)]
struct ThreadSafeOpenSslInfo {
    dll_name: String,
    version: String,
    ssl_read_addr: usize,
    ssl_write_addr: usize,
    module_handle: usize,
}

unsafe impl Send for ThreadSafeOpenSslInfo {}
unsafe impl Sync for ThreadSafeOpenSslInfo {}

impl From<OpenSslInfo> for ThreadSafeOpenSslInfo {
    fn from(info: OpenSslInfo) -> Self {
        Self {
            dll_name: info.dll_name,
            version: info.version,
            ssl_read_addr: info.ssl_read_addr as usize,
            ssl_write_addr: info.ssl_write_addr as usize,
            module_handle: info.module_handle as usize,
        }
    }
}

impl From<ThreadSafeOpenSslInfo> for OpenSslInfo {
    fn from(info: ThreadSafeOpenSslInfo) -> Self {
        Self {
            dll_name: info.dll_name,
            version: info.version,
            ssl_read_addr: info.ssl_read_addr as *const u8,
            ssl_write_addr: info.ssl_write_addr as *const u8,
            module_handle: info.module_handle as *mut winapi::shared::minwindef::HINSTANCE__,
        }
    }
}

static PATCHED: Mutex<bool> = Mutex::new(false);
static PATCH_CRITICAL_SECTION: Mutex<()> = Mutex::new(());
static OPENSSL_INFO: Mutex<Option<ThreadSafeOpenSslInfo>> = Mutex::new(None);

// Increased trampoline size for safety
const JMP_SIZE: usize = 12; // 64-bit absolute jump
const TRAMPOLINE_SIZE: usize = 32; // Larger buffer for safety

// Original function bytes storage
static mut SSL_READ_ORIG_BYTES: [u8; JMP_SIZE] = [0; JMP_SIZE];
static mut SSL_WRITE_ORIG_BYTES: [u8; JMP_SIZE] = [0; JMP_SIZE];

// Function pointers for original functions
static mut ORIG_SSL_READ: Option<SslReadFn> = None;
static mut ORIG_SSL_WRITE: Option<SslWriteFn> = None;

#[repr(align(16))]
pub struct AlignedTrampoline {
    buf: [u8; TRAMPOLINE_SIZE],
}

pub static mut SSL_READ_TRAMPOLINE: AlignedTrampoline =
    AlignedTrampoline { buf: [0; TRAMPOLINE_SIZE] };
pub static mut SSL_WRITE_TRAMPOLINE: AlignedTrampoline =
    AlignedTrampoline { buf: [0; TRAMPOLINE_SIZE] };

/// Safe memory protection change with error handling
unsafe fn change_memory_protection(
    addr: *mut c_void,
    size: usize,
    new_protect: DWORD,
) -> Result<DWORD, String> {
    let mut old_protect: DWORD = 0;
    if VirtualProtect(addr, size, new_protect, &mut old_protect) == 0 {
        return Err(format!("VirtualProtect failed at {:p}", addr));
    }
    Ok(old_protect)
}

/// Enhanced patch function with better error handling
unsafe fn patch_function(
    target: *mut u8,
    detour: *const u8,
    original_bytes: &mut [u8],
) -> Result<(), String> {
    // Validate parameters
    if target.is_null() || detour.is_null() {
        return Err("Null pointer passed to patch_function".to_string());
    }

    // Save original bytes
    ptr::copy_nonoverlapping(target, original_bytes.as_mut_ptr(), JMP_SIZE);

    // Change memory protection
    let old_protect =
        change_memory_protection(target as *mut c_void, JMP_SIZE, PAGE_EXECUTE_READWRITE)?;

    // Create absolute jump: mov rax, detour; jmp rax
    let mut patch: [u8; JMP_SIZE] = [0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0];
    let detour_addr = detour as u64;
    patch[2..10].copy_from_slice(&detour_addr.to_le_bytes());

    // Apply patch
    ptr::copy_nonoverlapping(patch.as_ptr(), target, JMP_SIZE);

    // Restore original protection
    let _ = change_memory_protection(target as *mut c_void, JMP_SIZE, old_protect);

    trace!("Function patched successfully at {:p} -> {:p}", target, detour);
    Ok(())
}

/// Enhanced unpatch function
unsafe fn unpatch_function(target: *mut u8, original_bytes: &[u8]) -> Result<(), String> {
    if target.is_null() {
        return Err("Null pointer passed to unpatch_function".to_string());
    }

    let old_protect =
        change_memory_protection(target as *mut c_void, JMP_SIZE, PAGE_EXECUTE_READWRITE)?;
    ptr::copy_nonoverlapping(original_bytes.as_ptr(), target, JMP_SIZE);
    let _ = change_memory_protection(target as *mut c_void, JMP_SIZE, old_protect);

    trace!("Function unpatched successfully at {:p}", target);
    Ok(())
}

/// Build trampoline with enhanced safety
unsafe fn build_trampoline(
    trampoline: &mut AlignedTrampoline,
    original_bytes: &[u8],
    return_addr: u64,
) -> Result<(), String> {
    // Clear trampoline buffer
    trampoline.buf.fill(0);

    // Copy original instructions
    ptr::copy_nonoverlapping(original_bytes.as_ptr(), trampoline.buf.as_mut_ptr(), JMP_SIZE);

    // Create jump back to original function + JMP_SIZE
    let mut jmp_back = [0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xE0]; // mov rax, addr; jmp rax
    jmp_back[2..10].copy_from_slice(&return_addr.to_le_bytes());

    ptr::copy_nonoverlapping(
        jmp_back.as_ptr(),
        trampoline.buf.as_mut_ptr().add(JMP_SIZE),
        JMP_SIZE,
    );

    // Make trampoline executable
    change_memory_protection(
        trampoline.buf.as_mut_ptr() as *mut c_void,
        TRAMPOLINE_SIZE,
        PAGE_EXECUTE_READ,
    )?;

    Ok(())
}

/// Enhanced SSL_read hook with better error handling
unsafe extern "C" fn my_ssl_read(ssl: *mut c_void, buf: *mut u8, num: i32) -> i32 {
    // Validate parameters
    if ssl.is_null() || buf.is_null() || num <= 0 {
        warn!("[PATCH] my_ssl_read: Invalid parameters");
        return -1;
    }

    trace!("[PATCH] my_ssl_read() called: ssl={:p}, buf={:p}, num={}", ssl, buf, num);

    // Call original function using stored function pointer
    if let Some(orig_fn) = ORIG_SSL_READ {
        let ret = orig_fn(ssl as *mut SSL, buf, num);

        if ret > 0 && !buf.is_null() {
            let data_len = std::cmp::min(ret as usize, 32);
            let data = std::slice::from_raw_parts(buf, data_len);
            trace!("[PATCH] my_ssl_read() decrypted data ({} bytes): {:02X?}", ret, data);
        }

        ret
    } else {
        error!("[PATCH] my_ssl_read: Original function pointer is null!");
        -1
    }
}

/// Enhanced SSL_write hook with better error handling
unsafe extern "C" fn my_ssl_write(ssl: *mut c_void, buf: *const u8, num: i32) -> i32 {
    // Validate parameters
    if ssl.is_null() || buf.is_null() || num <= 0 {
        warn!("[PATCH] my_ssl_write: Invalid parameters");
        return -1;
    }

    trace!("[PATCH] my_ssl_write() called: ssl={:p}, buf={:p}, num={}", ssl, buf, num);

    if num > 0 && !buf.is_null() {
        let data_len = std::cmp::min(num as usize, 32);
        let data = std::slice::from_raw_parts(buf, data_len);
        trace!("[PATCH] my_ssl_write() plaintext data ({} bytes): {:02X?}", num, data);
    }

    // Call original function using stored function pointer
    if let Some(orig_fn) = ORIG_SSL_WRITE {
        orig_fn(ssl as *mut SSL, buf, num)
    } else {
        error!("[PATCH] my_ssl_write: Original function pointer is null!");
        -1
    }
}

/// Enhanced SSL patch installation with version detection
pub unsafe fn install_ssl_inline_patches() -> Result<(), String> {
    let _guard = PATCH_CRITICAL_SECTION.lock().map_err(|_| "Failed to acquire patch lock")?;
    let mut patched = PATCHED.lock().map_err(|_| "Failed to acquire patched mutex")?;

    if *patched {
        trace!("SSL patches already installed");
        return Ok(());
    }

    // Detect OpenSSL
    let ssl_info = detect_openssl()
        .ok_or_else(|| "No compatible OpenSSL library found in process".to_string())?;

    info!("Using OpenSSL: {} v{}", ssl_info.dll_name, ssl_info.version);

    // Validate OpenSSL is ready
    validate_openssl(&ssl_info)?;

    let ssl_read = ssl_info.ssl_read_addr as *mut u8;
    let ssl_write = ssl_info.ssl_write_addr as *mut u8;

    trace!("Found SSL functions: SSL_read={:p}, SSL_write={:p}", ssl_read, ssl_write);
    // Store SSL info for later use
    *OPENSSL_INFO.lock().map_err(|_| "Failed to store SSL info")? = Some(ssl_info.clone().into());
    ptr::copy_nonoverlapping(ssl_read as *const u8, ptr::addr_of_mut!(SSL_READ_ORIG_BYTES).cast(), JMP_SIZE);
    ptr::copy_nonoverlapping(ssl_write as *const u8, ptr::addr_of_mut!(SSL_WRITE_ORIG_BYTES).cast(), JMP_SIZE);

    // Build trampolines
    let read_ret_addr = (ssl_read as usize + JMP_SIZE) as u64;
    let write_ret_addr = (ssl_write as usize + JMP_SIZE) as u64;

    build_trampoline(&mut *ptr::addr_of_mut!(SSL_READ_TRAMPOLINE), &SSL_READ_ORIG_BYTES, read_ret_addr)?;
    build_trampoline(&mut *ptr::addr_of_mut!(SSL_WRITE_TRAMPOLINE), &SSL_WRITE_ORIG_BYTES, write_ret_addr)?;

    // Store function pointers to trampolines
    ORIG_SSL_READ = Some(std::mem::transmute(ptr::addr_of!(SSL_READ_TRAMPOLINE) as *const ()));
    ORIG_SSL_WRITE = Some(std::mem::transmute(ptr::addr_of!(SSL_WRITE_TRAMPOLINE) as *const ()));

    // Patch the functions
    patch_function(ssl_read, my_ssl_read as *const u8, &mut *(ptr::addr_of_mut!(SSL_READ_ORIG_BYTES) as *mut [u8; JMP_SIZE]))?;
    patch_function(ssl_write, my_ssl_write as *const u8, &mut *(ptr::addr_of_mut!(SSL_WRITE_ORIG_BYTES) as *mut [u8; JMP_SIZE]))?;

    // Store SSL info for later use - already stored above

    *patched = true;
    info!("SSL hooks installed successfully");
    Ok(())
}

/// Enhanced SSL patch uninstallation with stored info
pub unsafe fn uninstall_ssl_inline_patches() -> Result<(), String> {
    let _guard = PATCH_CRITICAL_SECTION.lock().map_err(|_| "Failed to acquire patch lock")?;
    let mut patched = PATCHED.lock().map_err(|_| "Failed to acquire patched mutex")?;

    if !*patched {
        trace!("SSL patches not installed");
        return Ok(());
    }

    // Get stored SSL info
    let ssl_info_guard = OPENSSL_INFO.lock().map_err(|_| "Failed to access SSL info")?;
    let ssl_info = ssl_info_guard.as_ref().ok_or_else(|| "No SSL info stored".to_string())?;

    // Validate OpenSSL is still available
    let ssl_info_converted: OpenSslInfo = ssl_info.clone().into();
    if let Err(e) = validate_openssl(&ssl_info_converted) {
        warn!("OpenSSL validation failed during uninstall: {}", e);
        // Continue anyway to attempt cleanup
    }

    let ssl_read = ssl_info.ssl_read_addr as *mut u8;
    let ssl_write = ssl_info.ssl_write_addr as *mut u8;

    // Restore original functions
    unpatch_function(ssl_read, &*(ptr::addr_of!(SSL_READ_ORIG_BYTES) as *const [u8; JMP_SIZE]))?;
    unpatch_function(ssl_write, &*(ptr::addr_of!(SSL_WRITE_ORIG_BYTES) as *const [u8; JMP_SIZE]))?;

    // Clear function pointers
    ORIG_SSL_READ = None;
    ORIG_SSL_WRITE = None;

    // Make trampolines read-only
    let _ = change_memory_protection(
        ptr::addr_of_mut!(SSL_READ_TRAMPOLINE).cast::<AlignedTrampoline>().cast::<c_void>(),
        TRAMPOLINE_SIZE,
        PAGE_READONLY,
    );
    let _ = change_memory_protection(
        ptr::addr_of_mut!(SSL_WRITE_TRAMPOLINE).cast::<AlignedTrampoline>().cast::<c_void>(),
        TRAMPOLINE_SIZE,
        PAGE_READONLY,
    );

    drop(ssl_info_guard);
    *OPENSSL_INFO.lock().unwrap() = None;

    *patched = false;
    info!("SSL hooks uninstalled successfully");
    Ok(())
}
