# Contributing

We welcome contributions ! This project is actively looking for help in several areas :)

## How to contribute

1  **fork the repository**: create your own fork of the project on GitHub.
2. **create a branch**: make a new branch for your changes.
3. **commit your changes**: write clear and concise commit messages.
4. **push to your fork**: push your changes to your forked repository.
5. **open a pull request**: submit a pull request to the main repository, explaining the changes you have made.

## Areas where help is needed

- **rust development**: the current code can certainly be improved. If you have experience in Rust, especially with cryptography, FFI, or Windows internals, your input would be invaluable.
- **cross-platform porting**: expertise in making the `fish_11_core` library and the `fish_11_cli` tool fully functional and tested on Linux and other *nix systems (FreeBSD is the roadmap).
- **mIRC scripting**: improving the `fish_11.mrc` script with new features, better UI elements, and more robust error handling.
- **testing**: help with testing the plugin on various IRC networks, with different mIRC versions, and under different scenarios to find bugs.
- **documentation**: improving the existing documentation, adding more examples, and clarifying technical details.

## Development setup

1. Install Rust via [rustup.rs](https://rustup.rs/).
2. Add the 32-bit Windows target, which is required for mIRC compatibility:

   ```sh
    rustup target add i686-pc-windows-msvc
   ```

3. Clone the repository and build the project:

   ```sh
    git clone https://github.com/ggielly/fish_11.git
    cd fish_11
    cargo build --workspace --target i686-pc-windows-msvc
   ```

4. You can test your build using the CLI tool:

   ```powershell
    # From the project root in PowerShell
    .\target\i686-pc-windows-msvc\debug\fish_11_cli.exe .\target\i686-pc-windows-msvc\debug\fish_11_dll.dll getversion
    ```

## Contact

For questions or suggestions, you can reach out to `guillaume@lavache.com`.
