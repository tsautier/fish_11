# Unified Error Handling System

FiSH-11 implements a robust, unified error handling system to provide stability, maintainability, and clear diagnostics. This system replaces inconsistent error handling (panics, silent failures) with a standardized, type-safe approach.

## 1. Core components

### `DllError` Enum

The heart of the system is the `DllError` enum, located in `src/unified_error.rs`. This enum exhaustively defines every possible error that can occur within the DLL's public-facing functions. It is organized into logical categories:

- **input/output errors**: issues with parameters passed to the DLL or the buffer for writing results.
  - `NullPointer`: a required pointer (like the `data` buffer) was null.
  - `InputTooLong`: the input string exceeded the maximum allowed size.
  - `MissingParameter`: a required parameter (e.g., a nickname) was not provided.
- **configuration errors**: problems reading from or writing to `fish_11.ini`.
  - `ConfigNotFound`: the configuration file could not be located.
  - `ConfigSaveFailed`: an error occurred while trying to save the configuration.
  - `KeyNotFound`: a required key for a user or channel was not found in the config.
- **cryptographic errors**: failures during encryption, decryption, or key generation.
  - `EncryptionFailed`: an error occurred during the encryption process.
  - `DecryptionFailed`: decryption failed, likely due to a wrong key or corrupted data.
  - `KeyInvalid`: a provided or generated key is invalid (e.g., weak, wrong size).
  - `ReplayAttackDetected`: a message was received with a nonce that has already been used, indicating a potential replay attack.
- **state errors**: logical errors related to the state of the application.
  - `DuplicateEntry`: an attempt was made to create an entry that already exists (e.g., generating a key for a user who already has one).
- **encoding errors**: failures related to data encoding, such as Base64 or UTF-8.
  - `Base64DecodeFailed`: failed to decode a Base64 string.
  - `InvalidUtf8`: input data was not valid UTF-8.

### `DllResult<T>`

All fallible DLL functions return a `Result<T, DllError>`, which is type-aliased as `DllResult<T>`. This enforces at compile time that every possible error condition is handled by the caller.

```rust
pub type DllResult<T> = Result<T, DllError>;

fn do_something() -> DllResult<String> {
    // logic that can fail
}
```

### Automatic error conversion

The system uses Rust's `From` trait to automatically convert errors from underlying libraries (like I/O errors, Base64 decoding errors, etc.) into the appropriate `DllError` variant. This allows the use of the `?` operator throughout the code, making it clean and readable.

```rust
fn get_key_from_file(user: &str) -> DllResult<Vec<u8>> {
    let config = load_config()?; // Automatically converts a potential FishError to DllError
    let key_b64 = config.get_key(user)?; // Also converts
    let key_bytes = base64::decode(key_b64)?; // Automatically converts a base64::DecodeError
    Ok(key_bytes)
}
```

## 2. Error response to mIRC

A key feature of the system is its ability to translate any `DllError` into a user-friendly response for mIRC.

When a function returns an `Err(DllError)`, a central wrapper:

1. **logs the error**: a detailed, technical version of the error is written to the log file for debugging purposes.
2. **formats a user message**: a clear, concise message is created explaining what went wrong in simple terms.
3. **writes to mIRC**: the message is written back to the mIRC `data` buffer, typically as an `/echo` command.
4. **returns the correct code**: it returns `MIRC_COMMAND` to mIRC so the error message is executed.

### Example error messages

- **`DllError::KeyNotFound`**:
  - **log**: `ERROR: KeyNotFound for user 'bob'`
  - **mirc response**: `/echo -ts [FiSH-11] Error: no encryption key found for 'bob'. please perform a key exchange first.`

- **`DllError::InvalidInput`**:
  - **log**: `ERROR: InvalidInput: expected format: <nickname> <base64_key>`
  - **mirc response**: `/echo -ts [FiSH-11] Error: invalid input. usage: /dll fish_11.dll FiSH11_SetKey <nickname> <base64_key>`

- **`DllError::ReplayAttackDetected`**:
  - **log**: `SECURITY WARNING: ReplayAttackDetected in channel '#secret'`
  - **mirc response**: `/echo -ts [FiSH-11] SECURITY WARNING: a replayed message was detected and rejected in #secret.`

This approach ensures that the user is always informed of issues, and developers have the detailed logs they need to diagnose problems, all while preventing the DLL from ever crashing due to an unhandled error.
