# Installation

This guide covers how to install FiSH-11, either from pre-compiled binaries or by building from source.

## Windows Binaries Installation (Recommended)

1. Download the latest release from the [GitHub Releases](https://github.com/ggielly/fish_11/releases) page.
2. Extract the following files to your mIRC directory:
    - `fish_11.dll` (core encryption library)
    - `fish_11_inject.dll` (WinSock hooking library)
    - `fish_11.mrc` (mIRC script interface)
3. In mIRC, load the script: `/load -rs fish_11.mrc`
4. The DLLs will be automatically loaded by the script in the correct order.

## Building from Source

### Prerequisites

- **rust toolchain**: install via [rustup.rs](https://rustup.rs/).
- **windows**: MSVC Build Tools or Visual Studio. For 32-bit mIRC compatibility, you need the `i686-pc-windows-msvc` target.
- **linux**: `gcc-mingw-w64-i686` for cross-compiling to Windows.

### Windows Build Steps

```powershell
# Clone the repository
git clone https://github.com/ggielly/fish_11.git
cd fish_11

# Add 32-bit target for mIRC compatibility
rustup target add i686-pc-windows-msvc

# Build release version (32-bit)
cargo build --release --target i686-pc-windows-msvc --workspace

# Or build debug version (with full logging)
cargo build --target i686-pc-windows-msvc --workspace
```

Binaries will be located in `target/i686-pc-windows-msvc/release/` or `target/i686-pc-windows-msvc/debug/`.

### Linux Cross-compilation (for Windows DLLs)

```bash
# Install cross-compilation target
rustup target add i686-pc-windows-gnu

# Install mingw-w64 toolchain (example for Debian/Ubuntu)
sudo apt-get install gcc-mingw-w64-i686

# Build Windows DLLs from Linux
cargo build --target i686-pc-windows-gnu --release --workspace
```

### Linux Native Compilation

```bash
# Install the standard Linux target if not present
rustup target add x86_64-unknown-linux-gnu

# Build the workspace (e.g., for the CLI and core library)
cargo build --release --workspace --target x86_64-unknown-linux-gnu
```
