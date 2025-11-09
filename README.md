# FiSH-11: Modern IRC Encryption

[![Build Status](https://github.com/ggielly/fish_11/workflows/Rust/badge.svg)](https://github.com/ggielly/fish_11/actions)

FiSH-11 is a modern, secure, and robust implementation of an IRC encryption plugin, written in Rust. It provides strong, end-to-end encryption for both private messages and multi-user channels, with a primary focus on the mIRC client for Windows but also librairies and CLI for Linux.

This project is a complete rewrite of older FiSH implementations, focusing on modern cryptographic primitives, a secure-by-default design, and a stable, maintainable codebase.

## Documentation

The project's documentation has been split into multiple files for clarity.

- **[Project Structure](./docs/PROJECT_STRUCTURE.md)**: an overview of the different crates and their roles.
- **[Installation Guide](./docs/INSTALLATION.md)**: how to install pre-built binaries or build from source.
- **[Features](./docs/FEATURES.md)**: a list of core cryptographic, security, and integration features.
- **[How It Works](./docs/HOW_IT_WORKS.md)**: an explanation of the message interception and key exchange process.
- **[Security Model](./docs/SECURITY.md)**: details on key storage and security features.
- **[Usage Examples](./docs/USAGE_EXAMPLES.md)**: examples of mIRC script commands and direct DLL calls.

### Technical References

- **[DLL API Reference](./docs/API_REFERENCE.md)**: a detailed reference for all functions exported by the DLL.
- **[CLI Reference](./docs/CLI_REFERENCE.md)**: guide for the command-line interface tool.
- **[FCEP-1 Protocol](./docs/FCEP-1.md)**: technical details of the channel encryption protocol.
- **[Error Handling](./docs/ERROR_HANDLING.md)**: description of the unified error handling system.

### Project Management

- **[Roadmap](./docs/ROADMAP.md)**: the development status and future plans.
- **[Contributing Guide](./CONTRIBUTING.md)**: how to contribute to the project.

## License

This project is licensed under the GPL v3. See the [LICENSE](./LICENSE) file for details.
