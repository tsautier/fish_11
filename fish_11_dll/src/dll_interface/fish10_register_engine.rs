//! FiSH 10 Engine Registration DLL Interface
//!
//! This module provides DLL functions for registering the FiSH 10 engine
//! with the fish_inject system.

use crate::legacy::get_fish10_engine_ptr;
use fish_11_core::globals::FISH_INJECT_ENGINE_VERSION;
use log::{error, info};

/// Register the FiSH 10 engine with fish_inject
///
/// This function returns a pointer to the FiSH 10 engine that can be
/// registered with the fish_inject system using RegisterEngine().
///
/// # Returns
/// - Pointer to the FiSH 10 engine structure, or NULL on error
///
/// # Safety
/// The returned pointer must be used with the fish_inject RegisterEngine function
/// and should not be freed by the caller.
#[no_mangle]
pub unsafe extern "C" fn FiSH10_RegisterEngine() -> *const crate::legacy::fish10_engine::Fish10Engine
{
    info!("FiSH10_RegisterEngine: Called to get FiSH 10 engine pointer");

    match get_fish10_engine_ptr() {
        Some(ptr) => {
            info!("FiSH10_RegisterEngine: Returning FiSH 10 engine pointer");
            ptr
        }
        None => {
            error!("FiSH10_RegisterEngine: Failed to get FiSH 10 engine pointer");
            std::ptr::null()
        }
    }
}

/// Get the version of the FiSH 10 engine
///
/// # Returns
/// - The engine version as a u32
#[no_mangle]
pub extern "C" fn FiSH10_GetEngineVersion() -> u32 {
    FISH_INJECT_ENGINE_VERSION
}

/// Check if the FiSH 10 engine is available
///
/// # Returns
/// - 1 if the engine is available, 0 otherwise
#[no_mangle]
pub extern "C" fn FiSH10_IsEngineAvailable() -> i32 {
    if get_fish10_engine_ptr().is_some() { 1 } else { 0 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_engine_version() {
        let version = unsafe { FiSH10_GetEngineVersion() };
        assert_eq!(version, FISH_INJECT_ENGINE_VERSION);
    }

    #[test]
    fn test_engine_availability() {
        // Initialize the legacy system first
        crate::legacy::init_legacy_system();

        let available = unsafe { FiSH10_IsEngineAvailable() };
        assert_eq!(available, 1);
    }

    #[test]
    fn test_register_engine() {
        // Initialize the legacy system first
        crate::legacy::init_legacy_system();

        let engine_ptr = unsafe { FiSH10_RegisterEngine() };
        assert!(!engine_ptr.is_null());

        unsafe {
            let engine = &*engine_ptr;
            assert_eq!(engine.version, FISH_INJECT_ENGINE_VERSION);
        }
    }
}
