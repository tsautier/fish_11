# FiSH_11, a modern IRC encryption (WiP)

FiSH_11 is a modern implementation of an IRC encryption plugin, written in Rust. It provides strong, end-to-end encryption for both private messages and multi-user channels, based on [X25519](https://en.wikipedia.org/wiki/Curve25519) and [ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305). With a primary focus on the mIRC client for Windows but also libraries and CLI for Linux.

## Features

- **Secure encryption**: uses cryptographic standards (X25519, ChaCha20-Poly1305) without dependency to external libraries ;
- **Multi-user channel encryption**: implements and introduce a draft of FCEP-1 (FiSH-11 Channel Encryption Protocol) for secure multi-user channels and key exchange 
- **Forward secrecy**: keys automatically expire after 24 hours to provide forward secrecy
- **Post-compromise security**: compromised keys become useless after the next message exchange, with TTL on exchanged key 
- **Automatic key management**: handles key generation, exchange, and cleanup automatically
- **mIRC integration**: full integration with mIRC through DLL injection
- **Portable**: shared librairies (.so format) for *NIX world.

## Documentation

- **[Project structure](./docs/PROJECT_STRUCTURE.md)**: an overview of the different crates and their roles.
- **[Installation guide](./docs/INSTALLATION.md)**: how to install pre-built binaries or build from source.
- **[Features](./docs/FEATURES.md)**: a list of core cryptographic, security, and integration features.
- **[How it works](./fish_11_inject/README.md)**: an explanation of the message interception via DLL injection.
- **[Security model](./docs/SECURITY.md)**: details on key storage and security features. (todo)
- **[Usage examples](./docs/USAGE_EXAMPLES.md)**: examples of mIRC script commands and direct DLL calls.

### Technical references

- **[DLL API reference](./docs/API_REFERENCE.md)**: a detailed reference for all functions exported by the DLL.
- **[CLI reference](./docs/CLI_REFERENCE.md)**: guide for the command-line interface tool.
- **[FCEP-1 protocol](./docs/FCEP-1.md)**: technical details of the channel encryption protocol.
- **[Error handling](./docs/ERROR_HANDLING.md)**: description of the unified error handling system.
- **[Fuzzing guide](./fuzz/README.md)**: instructions for running security fuzz tests (requires Linux/WSL).

### Project management

- **[Roadmap](./docs/ROADMAP.md)**: the development status and future plans ?
- **[Contributing guide](./CONTRIBUTING.md)**: contribution are welcome ! :)

## License

This project is [licensed](./LICENSE) licensed under the GPL-v3.
