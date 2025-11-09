# Development status and roadmap

## Completed features

- [x] Core encryption library (`fish_11_core`, `fish_11_dll`)
- [x] Windows WinSock hooking for transparent operation (`fish_11_inject`)
- [x] X25519 key exchange implementation
- [x] ChaCha20-Poly1305 authenticated encryption
- [x] FCEP-1 channel encryption protocol (multi-user)
- [x] HKDF key derivation for enhanced security
- [x] SHA-256 key fingerprinting for verification
- [x] Comprehensive mIRC script integration (`fish_11.mrc`)
- [x] Command-line interface (`fish_11_cli`) for testing and integration
- [x] Unified error handling system
- [x] Configuration persistence and key management (`fish_11.ini`)
- [x] Memory zeroization and other security hardening features

## Current limitations

- The injection DLL is Windows-only and specific to 32-bit mIRC.
- The `fish_11_core` library is portable, but the `fish_11_dll` wrapper contains Windows-specific FFI code.

## Future roadmap

This is a list of desired features and improvements. Contributions are welcome!

- [ ] **cross-platform library**: mature the `fish_11_core` library and provide stable C-APIs for easy integration on Linux and other systems.
- [ ] **enhanced forward secrecy**: investigate and implement a Double Ratchet algorithm for 1-to-1 conversations to provide stronger forward and post-compromise security.
- [ ] **key rotation**: add functionality for automatic key rotation with configurable intervals.
- [ ] **master password**: implement an option to encrypt the `fish_11.ini` key storage file with a user-provided master password (e.g., using Argon2 for key derivation).
- [ ] **fuzzing integration**: add `cargo-fuzz` (`libfuzzer`) to the project to systematically test for security vulnerabilities in parsing and cryptographic functions.
- [ ] **CI/CD pipeline**: set up a GitHub Actions pipeline for automated testing, building, and releases.
- [ ] **more algorithms/ciphers**: explore the possibility of adding other modern cryptographic algorithms as optional choices.
