# FiSH 11 CLI Reference

The `fish_11_cli` is a command-line interface tool designed to interact with the `fish_11.dll` (on Windows) or `libfish_11.so` (on Linux). It allows users to test cryptographic functions, manage keys, and verify system behavior without needing an IRC client like mIRC.

## Usage

```bash
fish_11_cli [options] <library_path> <command> [parameters...]
```

### Options

*   `-q`, `--quiet`: Minimize output messages (useful for scripting).

### Arguments

*   `<library_path>`: Path to the `fish_11.dll` or `libfish_11.so` file.
*   `<command>`: The specific command to execute.
*   `[parameters...]`: Arguments required by the command.

## Available Commands

| Command | Description | Parameters |
| :--- | :--- | :--- |
| `help` | Show the help message | None |
| `list` | List available functions in the library | None |
| `getversion` | Get the DLL version | None |
| `genkey` | Generate a new encryption key for a target | `<target_name>` |
| `setkey` | Set a specific key for a target | `<target_name> <key>` |
| `getkey` | Get the key for a target | `<target_name>` |
| `delkey` | Delete a key for a target | `<target_name>` |
| `listkeys` | List all stored keys | `[config_path]` |
| `listkeysitem` | List a specific key item | `<index>` |
| `encrypt` | Encrypt a message | `<target_name> <message>` |
| `decrypt` | Decrypt a message | `<target_name> <ciphertext>` |
| `testcrypt` | Test encryption/decryption cycle | `<message>` |
| `getconfigpath` | Get the configuration file path | None |
| `setmircdir` | Set the mIRC directory | `<path>` |
| `ini_getbool` | Get a boolean value from the config | `<section> <key> [default]` |
| `ini_getstring` | Get a string value from the config | `<section> <key> [default]` |
| `ini_getint` | Get an integer value from the config | `<section> <key> [default]` |
| `initchannelkey`| Initialize a channel key | `<channel> <nick1> <nick2>` |
| `getkeyttl` | Get the time-to-live for a key | `<target_name>` |
| `getkeyfingerprint` | Get the SHA-256 fingerprint of a key | `<target_name>` |
| `setnetwork` | Set the current IRC network | `<network_name>` |

## Examples

### General Checks
```bash
# Check version
fish_11_cli fish_11.dll getversion

# List all functions
fish_11_cli fish_11.dll list
```

### Key Management
```bash
# Generate a key for a user or channel
fish_11_cli fish_11.dll genkey #channel

# Set a specific key (manual)
fish_11_cli fish_11.dll setkey alice "+OK 123456..."

# Get a key
fish_11_cli fish_11.dll getkey alice

# List all keys
fish_11_cli fish_11.dll listkeys c:\path\to\fish_11.ini
```

### Encryption & Decryption
```bash
# Encrypt a message
fish_11_cli fish_11.dll encrypt #channel "Hello World"

# Decrypt a message
fish_11_cli fish_11.dll decrypt #channel "+OK ...encrypted..."
```

## Session Management

The CLI supports checking session key status:

```bash
# Check time-to-live for an exchange key
fish_11_cli fish_11.dll getkeyttl alice
```

Exchange keys are valid for 24 hours by default.
