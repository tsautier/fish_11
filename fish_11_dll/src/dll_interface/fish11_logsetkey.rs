use crate::{
    buffer_utils,
    config::{self, state_management},
    dll_function_identifier,
    unified_error::DllError,
};

dll_function_identifier!(FiSH11_LogSetKey, data, {
    // Input format: <key_in_base64>
    let input = unsafe { buffer_utils::parse_buffer_input(data)? };
    let parts: Vec<&str> = input.splitn(1, ' ').collect();
    let base64_key = parts[0].trim();

    if base64_key.is_empty() {
        return Err(DllError::MissingParameter("base64_key".to_string()));
    }

    // The key is stored in the session state, not written to the INI file for security.
    // This means the log key must be set each time mIRC starts.
    state_management::set_log_key(base64_key)?;

    log::info!("In-memory log encryption key has been set for the current session.");

    Ok("1".to_string())
});