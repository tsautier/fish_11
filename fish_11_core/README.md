# Crate: `fish_11_core`

## Overview

`fish_11_core` is the foundational crate for the FiSH-11 project. It serves as the platform-agnostic base, containing all shared logic that is not specific to any operating system or external interface (like a Windows DLL or a Linux shared object).

The primary goal of this crate is to maximize code reuse and ensure that the core business logic of FiSH-11 is portable and can be compiled for any platform supported by Rust.

## Key principles

- **platform-agnostic**: this crate contains pure Rust code and must not include any platform-specific APIs (e.g., Win32 API calls).
- **shared dependency**: it is intended to be used as a dependency by other crates in the FiSH-11 workspace, such as `fish_11_dll` and `fish_11_cli`.
- **stable internal api**: it provides a stable set of utilities that other parts of the project can rely on.

## Modules

Currently, the crate contains the following modules:

### `buffer_utils`

- **purpose**: provides safe and reliable utilities for interacting with C-style data buffers, which is a common requirement for Foreign Function Interface (FFI).
- **implementation**: this module contains functions for safely reading from and writing to raw pointers (`*mut c_char`), handling potential null pointers, managing buffer sizes, and converting between Rust strings and null-terminated C strings. This is critical for preventing buffer overflows and other memory safety bugs when interfacing with C-based applications like mIRC.

## Usage

This crate is not intended for direct use. Instead, it is a dependency for other crates within the workspace.
