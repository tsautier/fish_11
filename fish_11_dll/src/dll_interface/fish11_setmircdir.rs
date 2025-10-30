use std::ffi::c_char;
use std::os::raw::c_int;

use winapi::shared::minwindef::BOOL;
use winapi::shared::windef::HWND;

use crate::dll_function_utils::{
    DllFunctionContext, DllResult, dll_function_wrapper, extract_input_string,
};

/// Sets the mIRC directory path for configuration file location
///
/// This function allows the mIRC script to explicitly set the directory where
/// the configuration file should be stored. This avoids reliance on environment
/// variables which may not work correctly in all mIRC configurations.
///
/// # Arguments
/// * `data` - Buffer containing the mIRC directory path
///
/// # Returns
/// * `MIRC_IDENTIFIER` if successful
#[no_mangle]
#[allow(non_snake_case)]
pub extern "stdcall" fn FiSH11_SetMircDir(
    _m_wnd: HWND,
    _a_wnd: HWND,
    data: *mut c_char,
    _parms: *mut c_char,
    _show: BOOL,
    _nopause: BOOL,
) -> c_int {
    dll_function_wrapper(data, "FiSH11_SetMircDir", |data, ctx| fish11_setmircdir_impl(data, ctx))
}

fn fish11_setmircdir_impl(data: *mut c_char, ctx: &DllFunctionContext) -> DllResult<()> {
    let mirc_dir = extract_input_string(data, ctx)?;

    ctx.log_info(&format!("Setting MIRCDIR to: {}", mirc_dir));

    // Set the environment variable for this process
    std::env::set_var("MIRCDIR", &mirc_dir);

    ctx.log_info("MIRCDIR environment variable set successfully");

    // No output needed - this is a silent configuration function
    Ok(())
}
