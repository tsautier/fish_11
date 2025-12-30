use windows::Win32::Foundation::{FARPROC, HMODULE};
use windows::Win32::System::ProcessStatus::{GetModuleInformation, MODULEINFO};
use windows::Win32::System::Threading::GetCurrentProcess;

/// Validate a function pointer
///
/// Checks:
/// 1. Is not NULL
/// 2. Is within the address space of the given module (if module handle provided)
pub unsafe fn validate_function_pointer(ptr: FARPROC, module: Option<HMODULE>) -> Result<(), String> {
    if ptr.is_none() {
        return Err("Function pointer is NULL".to_string());
    }

    if let Some(h_module) = module {
        let mut mod_info = MODULEINFO::default();
        let result = GetModuleInformation(
            GetCurrentProcess(),
            h_module,
            &mut mod_info,
            std::mem::size_of::<MODULEINFO>() as u32,
        );

        if result.is_err() {
            return Err("Failed to retrieve module information for validation".to_string());
        }

        let base_addr = mod_info.lpBaseOfDll as usize;
        let end_addr = base_addr + mod_info.SizeOfImage as usize;
        // Transmute FARPROC (Option<fn>) to address
        let func_addr: usize = std::mem::transmute_copy(&ptr);

        if func_addr < base_addr || func_addr >= end_addr {
            return Err(format!(
                "Function pointer {:p} is outside module address range [{:x} - {:x}]",
                func_addr as *const (), base_addr, end_addr
            ));
        }
    }

    Ok(())
}

/// Safe wrapper for transmuting function pointers after validation
///
/// # Safety
/// Caller must ensure that:
/// - `ptr` is a valid pointer to machine code compatible with the signature `T`
/// - `module` matches the module where the function is expected to reside
pub unsafe fn unsafe_transmute_validated<T: Copy>(
    ptr: FARPROC, 
    module: Option<HMODULE>
) -> Result<T, String> {
    // 1. Validate the pointer
    validate_function_pointer(ptr, module)?;

    // 2. Transmute
    // We use std::mem::transmute_copy to handle the FARPROC (Option<...>) to T conversion
    let func: T = std::mem::transmute_copy(&ptr);
    Ok(func)
}
