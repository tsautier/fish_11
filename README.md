# FiSH-11, a modern IRC encryption (WiP)

FiSH-11 is a modern implementation of an IRC encryption plugin, written in Rust. It provides strong, end-to-end encryption for both private messages and multi-user channels, based on [X25519](https://en.wikipedia.org/wiki/Curve25519) and [ChaCha20-Poly1305](https://en.wikipedia.org/wiki/ChaCha20-Poly1305). With a primary focus on the mIRC client for Windows but also libraries and CLI for Linux.

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
- **[Fuzzing Guide](./fuzz/README.md)**: instructions for running security fuzz tests (requires Linux/WSL).

### Project management

- **[Roadmap](./docs/ROADMAP.md)**: the development status and future plans.
- **[Contributing guide](./CONTRIBUTING.md)**: how to contribute to the project.

## License

This project is licensed under the GPL v3. See the [LICENSE](./LICENSE) file for details.
