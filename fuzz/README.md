# Fuzzing FiSH_11 (WiP)

This directory contains fuzz targets for testing FiSH_11 security-critical functions using `cargo-fuzz`.

## Important requirement: Linux or WSL !#@

**`cargo-fuzz` and its underlying engine, libFuzzer, do not support the Windows MSVC toolchain.**

Therefore, all fuzzing activities must be conducted within a **Linux environment** or on Windows using **Windows Subsystem for Linux (WSL)**. The setup below assumes you are running commands from a Linux/WSL shell.

## Prerequisites

1. **Install `cargo-fuzz`** :

    ```bash
    cargo install cargo-fuzz
    ```

2. **Install a nightly Rust toolchain** :
    The fuzzing crate is configured to use a nightly toolchain via the `rust-toolchain.toml` file. `rustup` will install it automatically when you first run a command in this directory.

## Running fuzz tests

Navigate to the `fuzz/` directory in your Linux/WSL terminal before running these commands.

### Run a single target continuously

This is the standard way to run a fuzz test for an extended period.

```bash
cargo fuzz run fuzz_decrypt_message
```

### Run all targets for a limited time

This is useful for quick checks or for integration into a CI pipeline.

```bash
# Run each target for 60 seconds
cargo fuzz run fuzz_decrypt_message -- -max_total_time=60
cargo fuzz run fuzz_encrypt_message -- -max_total_time=60
cargo fuzz run fuzz_base64_parsing -- -max_total_time=60
cargo fuzz run fuzz_ini_parsing -- -max_total_time=60
cargo fuzz run fuzz_irc_message_parsing -- -max_total_time=60
cargo fuzz run fuzz_wrap_unwrap_key -- -max_total_time=60
cargo fuzz run fuzz_ratchet -- -max_total_time=60
```

## Crash analysis

If `cargo-fuzz` finds a crash, it will save the input that caused it in `fuzz/artifacts/<target_name>/crash-<hash>`.

You can reproduce the crash with :

```bash
cargo fuzz run fuzz_decrypt_message fuzz/artifacts/fuzz_decrypt_message/crash-<hash>
```

To debug it with GDB/LLDB :

```bash
cargo fuzz run --debug-assertions fuzz_decrypt_message fuzz/artifacts/fuzz_decrypt_message/crash-<hash>
```

## Corpus

The `fuzz/corpus/<target_name>/` directory for each target contains a set of "interesting" inputs that the fuzzer has found. You can seed this directory with your own examples to give the fuzzer a head start.

To minimize the corpus (remove redundant examples) :

```bash
cargo fuzz cmin fuzz_decrypt_message
```
