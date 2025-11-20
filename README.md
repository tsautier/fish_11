# FiSH_11, a modern IRC encryption (WiP)

FiSH_11 is a modern implementation of an IRC encryption plugin, fully written in Rust. It provides strong, end-to-end encryption for both private messages and multi-user channels, based on [X25519](https://en.wikipedia.org/wiki/Curve25519) and [ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305). With a primary focus on the mIRC client for Windows (with a winsocks dll h00ks for fun & transparent operation) but also libraries and CLI for Linux.

## Development status, bugs and roadmap

### Completed and working features

#### DLL

- [x] DLL loading in mIRC : core encryption library (`fish_11_core`, `fish_11_dll`) fully loaded
- [x] DLL loading in mIRC : Windows WinSock hooking for transparent operation (`fish_11_inject`) : hook all SSL_Read and SSL_Write silently

#### mIRC client

- [x] Right click on a user => key exchange DH X25519 => encrypt/decrypt private messages :)
- [x] Configuration persistence and key management (`fish_11.ini`)
- [x] Read and write the fish_11.ini config file

#### Other OS binary

- [x] Cross compile
- [x] Generate a xxx.so file for Linux

#### Encryption

- [x] X25519 key exchange implementation
- [x] ChaCha20-Poly1305 authenticated encryption
- [x] HKDF key derivation for enhanced security
- [x] SHA-256 key fingerprinting for verification
- [x] Memory zeroization and other security hardening features

### Work in progress features and/or still bugged

- [x] Comprehensive mIRC script integration (`fish_11.mrc`)
- [x] Command-line interface (`fish_11_cli`) for testing and integration
- [x] FCEP-1 channel encryption protocol (multi-user)
- [x] key rotation / TTL management: add functionality for automatic key rotation with configurable intervals.
- [x] fuzzing integration: add `cargo-fuzz` (`libfuzzer`) to the project to systematically test for security vulnerabilities in parsing and cryptographic functions.
- [x] cross-platform library: mature the `fish_11_core` library and provide stable C-APIs for easy integration on Linux and other systems.
- [x] Topic encryption with manual password
- [ ] Refactor the logging engine for fish11_core, fish11_dll and fish11_inject
- [ ] CLI in linux can call the .so library

### Current limitations

- The injection DLL is Windows-only and specific to 32-bit mIRC.
- The `fish_11_core` library is portable, but the `fish_11_dll` wrapper contains Windows-specific FFI code.

### Future roadmap

This is a list of desired features and improvements. Contributions are welcome!

- [ ] ElligatorSwift : improve furtivity over X25519 key exchange with automatic detection (Keypair u32 -> u64 ; curve25519_dalek::ristretto ; curve25519_dalek::scalar ?) with parallel functions.
- [ ] enhanced forward secrecy: investigate and implement a Double Ratchet algorithm for 1-to-1 conversations to provide stronger forward and post-compromise security.
- [ ] master password: implement an option to encrypt the `fish_11.ini` key storage file with a user-provided master password (e.g., using Argon2 for key derivation).
- [ ] CI/CD pipeline: set up a GitHub Actions pipeline for automated testing, building, and releases.
- [ ] more algorithms/ciphers: explore the possibility of adding other modern cryptographic algorithms as optional choices.

## Documentation

- **[Project structure](./docs/PROJECT_STRUCTURE.md)**: an overview of the different crates and their roles.
- **[Installation guide](./docs/INSTALLATION.md)**: how to install pre-built binaries or build from source.
- **[Features](./docs/FEATURES.md)**: a list of core cryptographic, security, and integration features.
- **[How it works](./fish_11_inject/README.md)**: an explanation of the message interception via DLL injection.
- **[Security model](./docs/SECURITY.md)**: details on key storage and security features. (todo)

### Technical references

- **[DLL API reference](./docs/API_REFERENCE.md)**: a detailed reference for all functions exported by the DLL.
- **[CLI reference](./docs/CLI_REFERENCE.md)**: guide for the command-line interface tool.
- **[FCEP-1 protocol](./docs/FCEP-1.md)**: technical details of the channel encryption protocol.
- **[Fuzzing guide](./fuzz/README.md)**: instructions for running security fuzz tests (requires Linux/WSL).
- **[Contributing guide](./CONTRIBUTING.md)**: contributions and help are welcome ! :)

## License

This project is [licensed](./LICENSE) licensed under the GPL-v3.
