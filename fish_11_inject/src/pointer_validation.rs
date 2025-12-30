use winapi::shared::minwindef::{FARPROC, HMODULE};
use winapi::um::psapi::{GetModuleInformation, MODULEINFO};
use winapi::um::processthreadsapi::GetCurrentProcess;

/// Validate a function pointer
///
/// Checks:
/// 1. Is not NULL
/// 2. Is within the address space of the given module (if module handle provided)
pub unsafe fn validate_function_pointer(ptr: FARPROC, module: Option<HMODULE>) -> Result<(), String> {
    if ptr.is_null() {
        return Err("Function pointer is NULL".to_string());
    }

    if let Some(h_module) = module {
        let mut mod_info: MODULEINFO = std::mem::zeroed();
        let result = GetModuleInformation(
            GetCurrentProcess(),
            h_module,
            &mut mod_info,
            std::mem::size_of::<MODULEINFO>() as u32,
        );

        if result == 0 {
            // Failed to get module info, but pointer is not null.
            // Log warning but allow proceeding if we can't verify range?
            // For high security, we should probably fail.
            return Err("Failed to retrieve module information for validation".to_string());
        }

        let base_addr = mod_info.lpBaseOfDll as usize;
        let end_addr = base_addr + mod_info.SizeOfImage as usize;
        let func_addr = ptr as usize;

        if func_addr < base_addr || func_addr >= end_addr {
            return Err(format!(
                "Function pointer {:p} is outside module address range [{:x} - {:x}]",
                ptr, base_addr, end_addr
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

    // 2. Perform the transmute check (basic size check at compile time if possible?)
    // In Rust, we can't easily check function signature compatibility at runtime.
    // relying on the validation above to at least ensure it points to the right module.
    
    // 3. Transmute
    // We use std::mem::transmute_copy to handle the FARPROC (Option<unsafe extern "system" fn()>) to T conversion
    let func: T = std::mem::transmute_copy(&ptr);
    Ok(func)
}
