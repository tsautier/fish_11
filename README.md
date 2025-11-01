# FiSH_11 - Secure encryption for IRC & mIRC

FiSH_11 (work in progress) is a modernized implementation of the classic FiSH_10 IRC encryption tool, completely rewritten in Rust with modern cryptographic algorithms and enhanced security features :

- **X25519 (Curve25519-dalek)** for secure key exchange
- **ChaCha20-Poly1305** for authenticated encryption
- **HKDF** for enhanced key derivation
- **Memory zeroization** and constant-time operations for security

## Project structure

FiSH_11 consists of three main components :

### 1. Core encryption library (`fish_11_dll`)

The main cryptographic library providing :

- **Secure key generation and exchange** using X25519 elliptic curve cryptography
- **Message encryption/decryption** with ChaCha20-Poly1305 AEAD
- **Key management** with persistent storage and organization
- **Configuration management** via `fish_11.ini` in user's AppData directory
- **Comprehensive DLL interface** with 17+ exported functions for mIRC integration

### 2. Injection hook library (`fish_11_inject`)

Windows-specific library that :

- **Hooks mIRC's WinSock functions** for transparent message interception
- **Automatically detects and processes** encrypted messages and key exchanges
- **Provides real-time encryption/decryption** without user intervention
- **Supports SSL/TLS detection** for mixed encrypted connections
- **Engine system** for third-party plugin extensions

### 3. Command line interface (`fish_11_cli`)

Standalone testing and integration tool :

- **DLL function testing** and validation outside of mIRC
- **Third-party application integration** (eggdrop bots, scripts)
- **Key management operations** from command line
- **Diagnostic and troubleshooting** capabilities

## Features

### Core cryptographic features

- **Modern key exchange** : X25519 Diffie-Hellman with public key validation
- **Authenticated encryption** : ChaCha20-Poly1305 AEAD preventing tampering
- **Enhanced key derivation** : HKDF-SHA256 for improved shared secret processing  
- **Anti-replay protection** : nonce tracking prevents message replay attacks
- **Key fingerprinting** : SHA-256 fingerprints for manual key verification
- **Secure random generation** : cryptographically secure randomness for all keys and nonces

### Security features

- **Constant-time key operations** : all sensitive comparisons use constant-time algorithms to prevent timing attacks
- **Public key validation** : cryptographic validation of public keys to ensure they're valid Curve25519 points
- **Advanced key derivation** : hKDF for improved shared secret derivation
- **Anti-replay protection** : nonce tracking and validation to prevent message replay attacks
- **Memory zeroization** : secure handling of sensitive data in memory with automatic zeroization
- **Input validation** : strict validation of message sizes and formats
- **Secure buffer handling** : robust buffer validation and safe memory operations
- **Improved error handling** : comprehensive error tracking and safe error recovery
- **Thread-safe operations** : protection against race conditions in concurrent environments

### Integration features

- **Transparent operation** : automatic encryption/decryption via WinSock hooking
- **mIRC script integration** : comprehensive `.mrc` script with GUI menus and commands
- **Key exchange automation** : streamlined DH key exchange with timeout handling
- **Configuration persistence** : settings and keys stored in user profile
- **Cross-platform CLI** : command-line tool for testing and third-party integration
- **Engine plugin system** : extensible architecture for custom functionality

## Available DLL functions

The core library exports the following functions for mIRC integration :

### Key management functions

- `FiSH11_GenKey` - generate a new random encryption key for a nickname
- `FiSH11_SetKey` - manually set an encryption key (base64 encoded)
- `FiSH11_FileGetKey` - retrieve stored key for a nickname. If no key is found, it suggests initiating a key exchange.
- `FiSH11_FileDelKey` - delete a stored key
- `FiSH11_FileListKeys` - returns a formatted string of all stored keys, intended for script parsing. Output may be truncated if it exceeds buffer size.
- `FiSH11_FileListKeysItem` - get specific key information

### Encryption/decryption functions

- `FiSH11_EncryptMsg` - Encrypt a message with ChaCha20-Poly1305
- `FiSH11_DecryptMsg` - Decrypt a received message
- `FiSH11_TestCrypt` - Test encryption/decryption cycle for diagnostics
- `FiSH11_TestCrypt` - Test encryption/decryption cycle for diagnostics

### Key exchange functions

- `FiSH11_ExchangeKey` - Initiate X25519 key exchange (generate and display public key)
- `FiSH11_ProcessPublicKey` - Process received public key and compute shared secret
- `FiSH11_ProcessPublicKey` - Process received public key and compute shared secret

### Utility functions

- `FiSH11_GetVersion` - Display DLL version and build information
- `FiSH11_GetKeyFingerprint` - Generate SHA-256 fingerprint for key verification
- `FiSH11_GetConfigPath` - Get path to configuration file
- `FiSH11_Help` - Display usage help and available commands

### Configuration functions

- `FiSH11_SetMircDir` - Set the mIRC directory path to help locate the configuration file
- `INI_GetBool` - Read a boolean value from the configuration file
- `INI_GetString` - Read a string value from the configuration file
- `INI_GetInt` - Read an integer value from the configuration file

### Injection DLL functions

- `FiSH11_InjectVersion` - Get injection DLL version
- `FiSH11_InjectDebugInfo` - Get debugging information from injection system

## Installation

### Windows binaries installation

1. Download the latest release from the [GitHub Releases](https://github.com/ggielly/fish_11/releases) page
2. Extract the following files to your mIRC directory :
   - `fish_11.dll` (core encryption library)
   - `fish_11_inject.dll` (WinSock hooking library)
   - `fish_11.mrc` (mIRC script interface)
3. In mIRC, load the script : `/load -rs fish_11.mrc`
4. The DLLs will be automatically loaded in the correct order

### Building from sources

#### Prerequisites

- Rust toolchain (install via [rustup](https://rustup.rs/))
- Windows: MSVC Build Tools or Visual Studio. You can build using GCC too.
- For 32-bit mIRC compatibility: i686-pc-windows-msvc

#### Windows build steps

```powershell
# Clone the repository
git clone https://github.com/ggielly/fish_11.git
cd fish_11

# Add 32-bit target for mIRC compatibility
rustup target add i686-pc-windows-msvc

# Build release version (32-bit)
cargo build --release --target i686-pc-windows-msvc --workspace

# Build debug version (with logging)
cargo build --target i686-pc-windows-msvc --workspace
```

Binaries will be located in `target/i686-pc-windows-msvc/release/` or `target/i686-pc-windows-msvc/debug/`

#### Linux cross-compilation

```bash
# Install cross-compilation target
rustup target add i686-pc-windows-gnu

# Install mingw-w64 toolchain
sudo apt-get install gcc-mingw-w64-i686

# Build Windows DLLs from Linux
cargo build --target i686-pc-windows-gnu --release
```

## How FiSH_11 works

FiSH_11 uses a multi-component architecture for transparent IRC encryption :

### 1. DLL loading order (critical parts)

The injection DLL **must** be loaded before the crypto DLL :

1. `fish_11_inject.dll` : installs WinSock hooks first
2. `fish_11.dll` : provides cryptographic functions

### 2. Message interception process

1. **WinSock Hooking** : the injection DLL hooks mIRC's socket functions using the `retour` crate
2. **Message Detection** : intercepts all incoming/outgoing IRC messages in real-time
3. **Pattern Recognition** : detects FiSH encrypted messages (`+FiSH` prefix) and key exchanges (`FiSH11-PubKey:`)
4. **Transparent Processing** :
   - outgoing : encrypts messages automatically before sending
   - incoming : decrypts messages and displays them normally in mIRC
5. **Fallback** : plain text messages pass through unchanged

### 3. Key exchange protocol

1. User initiates with `/fish11_keyx nickname`
2. System generates X25519 keypair and displays public key
3. Public key is manually shared via IRC (PM/channel)
4. Recipient processes key with `/fish11_keyp nickname <received_key>`
5. Both parties compute identical shared secret using Diffie-Hellman
6. Shared secret is processed through HKDF and stored for future encryption

### 4. Technical implementation details

- **Crypto Library** : uses modern Rust crates (`x25519-dalek`, `chacha20poly1305`, `hkdf`)
- **Windows API**: direct Win32 calls for socket hooking and system integration
- **Memory Safety** : automatic zeroization of sensitive data, secure buffer handling
- **Logging** : comprehensive debug logging (debug builds only) to `fish11_inject.log`

## Security and storage

### Key storage

- Keys are stored encrypted in `%APPDATA%\fish_11.ini`
- Configuration includes key metadata (creation time, network associations)
- **CRITICAL: Never share your `fish_11.ini` file - it contains your private keys**

### Security features in practice

- **Forward Secrecy** : aach message uses a unique nonce
- **Authentication** : ChaCha20-Poly1305 prevents message tampering
- **Key Verification** : SHA-256 fingerprints allow manual verification
- **Anti-Replay** : Nonce cache prevents replay attacks
- **Memory Protection** : Sensitive data is zeroized after use

## Usage examples

### Basic mIRC commands

```mirc
; Generate a new key for a user/channel
/dll fish_11.dll FiSH11_GenKey #channel

; Start key exchange with another user
/dll fish_11.dll FiSH11_ExchangeKey bob

; Encrypt a message manually
/dll fish_11.dll FiSH11_EncryptMsg #channel Hello World

; Decrypt a received message
/dll fish_11.dll FiSH11_DecryptMsg #channel +FiSH <encrypted_data>

; Show key fingerprint for verification
/dll fish_11.dll FiSH11_GetKeyFingerprint bob

; List all stored keys
/dll fish_11.dll FiSH11_FileListKeys
```

### mIRC script commands (via fish_11.mrc)

```mirc
; Start automatic key exchange
/fish11_keyx bob

; Show key for verification
/fish11_showkey #channel

; Show fingerprint
/fish11_showfingerprint bob

; Manual key setting
/fish11_setkey #channel myBase64Key==

; Remove a key
/fish11_removekey bob
```

## Command line interface (CLI)

The `fish_11_cli.exe` tool provides standalone access to all DLL functions for testing and integration :

### CLI usage examples

```powershell
# Test DLL loading and get version
fish_11_cli.exe fish_11.dll getversion

# Generate a key for testing
fish_11_cli.exe fish_11.dll genkey testuser

# List all available functions
fish_11_cli.exe fish_11.dll list

# Test encryption/decryption cycle
fish_11_cli.exe fish_11.dll testcrypt "Hello World"

# Get key for specific user
fish_11_cli.exe fish_11.dll getkey testuser

# List all stored keys
fish_11_cli.exe fish_11.dll listkeys

# Quiet mode (minimal output)
fish_11_cli.exe -q fish_11.dll getversion
```

### CLI command mapping

| CLI Command | DLL Function | Description |
|------------|--------------|-------------|
| `getversion` | `FiSH11_GetVersion` | Get DLL version info |
| `genkey` | `FiSH11_GenKey` | Generate random key |
| `setkey` | `FiSH11_SetKey` | Set specific key |
| `getkey` | `FiSH11_FileGetKey` | Retrieve stored key |
| `delkey` | `FiSH11_FileDelKey` | Delete stored key |
| `listkeys` | `FiSH11_FileListKeys` | List all keys |
| `encrypt` | `FiSH11_EncryptMsg` | Encrypt message |
| `decrypt` | `FiSH11_DecryptMsg` | Decrypt message |
| `testcrypt` | `FiSH11_TestCrypt` | Test encrypt/decrypt |
| `exchangekey` | `FiSH11_ExchangeKey` | Start key exchange |
| `processkey` | `FiSH11_ProcessPublicKey` | Process received key |

## Development status and roadmap

### Completed features

- [x] Core encryption library with modern cryptography
- [x] Windows WinSock hooking for transparent operation
- [x] X25519 key exchange implementation
- [x] ChaCha20-Poly1305 authenticated encryption
- [x] HKDF key derivation for enhanced security
- [x] SHA-256 key fingerprinting for verification
- [x] Comprehensive mIRC script integration
- [x] Command-line interface for testing
- [x] Memory zeroization and constant-time operations
- [x] Configuration persistence and key management

### Current limitations

- Windows-only (32-bit mIRC compatibility)
- CLI tool is Windows-only currently
- Manual key exchange process (not automated)

### Future roadmap

- [ ] **Cross-platform CLI** : port to Linux/FreeBSD (eg. for eggdrop integration)
- [ ] **Enhanced forward secrecy** : replace `StaticSecret` with `EphemeralSecret`
- [ ] **Key rotation** : automatic key rotation with configurable intervals
- [ ] **Master password** : encrypt key storage with user-specific master password
- [ ] **Enhanced authentication** : add HMAC signatures to prevent MITM attacks
- [ ] **Unicode support** : improved handling of international characters
- [ ] **Fuzzing integration** : add `libfuzzer` for security testing
- [ ] **CI/CD pipeline** : automated testing and releases
- [ ] **Plugin system** : enhanced engine architecture for extensibility

### Known issues

- Key exchange timeout handling could be improved
- Debug logging is only available in debug builds
- The DLL in key exchange crash mIRC
- Check if we can compile with 64bit with mIRC

## Contributing

We welcome contributions! The project is actively developed and looking for :

- Developpers and helpers : my code is bad !#@%
- **Security review** of cryptographic implementations
- **Cross-platform porting** expertise  
- **mIRC scripting** improvements and features
- **Testing** with various IRC networks and scenarios
- **Documentation** improvements and examples

**Contact** : `guillaume@lavache.com` for questions

### Development setup

1. Install Rust via [rustup](https://rustup.rs/)
2. Add 32-bit Windows target :  `rustup target add i686-pc-windows-msvc`
3. Clone and build : `cargo build --target i686-pc-windows-msvc`
4. Test with CLI : `fish_11_cli.exe target/i686-pc-windows-msvc/debug/fish_11.dll getversion`

## License

GNU GENERAL PUBLIC LICENSE, Version 3, 29 June 2007

## Acknowledgments

This project is inspired by the original FiSH_10 IRC encryption tool, particularly the injection methodology from fish_inject. The modern Rust implementation provides enhanced security while maintaining compatibility with existing IRC infrastructure. Many thanks to the developpers of previous FiSH versions for their hard work.
