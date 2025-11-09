# Project Structure

FiSH-11 is built on a modular, multi-crate architecture to separate concerns and improve portability. There are four main components in the workspace.

### 1. `fish_11_core`

This is a new, platform-agnostic library containing the portable core logic.

- **purpose**: to hold shared utilities and core functionalities that are not tied to any specific operating system or platform (like Windows DLLs or Linux .so files).
- **contents**: includes common code such as `buffer_utils`.
- **portability**: this crate is key to making FiSH-11 portable. It can be compiled for any target that Rust supports, allowing other projects (like a native Linux client or bot) to build upon a common, stable foundation.

### 2. `fish_11_dll`

The main cryptographic library that exposes a C-compatible Foreign Function Interface (FFI), designed to be loaded by mIRC on Windows.

- **purpose**: to provide all the core cryptographic operations and be the main interface for the mIRC script.
- **contents**: contains the implementation for key exchange, encryption/decryption, the FCEP-1 channel protocol, and the unified error handling system.
- **platform**: it is built upon `fish_11_core` but is specific to Windows, as it's compiled as a `.dll` and uses the `stdcall` calling convention.

### 3. `fish_11_inject`

A Windows-specific DLL that provides transparent, automatic encryption/decryption.

- **purpose**: to hook into the mIRC process and intercept its network calls (`send`/`recv`).
- **contents**: includes the logic for WinSock hooking, detecting encrypted messages in real-time, and calling the `fish_11_dll` to perform the actual crypto operations.
- **platform**: this is the most platform-specific part of the project, relying heavily on the Win32 API. It is an optional component for users who want a seamless, automatic experience.

### 4. `fish_11_cli`

A command-line interface for testing and third-party integration.

- **purpose**: to allow developers and power users to interact with the `fish_11_dll` functions directly from the command line, without needing mIRC.
- **contents**: a simple wrapper that loads the DLL/shared library and calls its functions based on command-line arguments.
- **platform**: cross-platform. It can be compiled for Windows, Linux, etc., and can be used to test either the Windows DLL or a future Linux `.so` version of the library.

## Other important directories

- **`docs/`**: contains all project documentation, including technical specifications (`FCEP-1_DRAFT.txt`), user guides, and detailed explanations of the architecture and API.
- **`experimental/`**: holds unstable or work-in-progress code that is not part of the production build, such as the experimental `ssl_inline_patch.rs`.
- **`scripts/`**: contains helper scripts for building, testing, and interacting with the project, including mIRC scripts (`.mrc`) and PowerShell build scripts.
