# FiSH 10 Integration with fish_inject

This document describes how to integrate the FiSH 10 legacy compatibility engine with the fish_inject system.

## Overview

The FiSH 10 engine is designed to work seamlessly with the existing fish_inject architecture. It automatically detects and processes FiSH 10 messages (both encrypted messages and DH1080 key exchange) without requiring changes to the core fish_inject code.

## Architecture

The integration follows a modular design:

1. **FiSH 10 Engine**: a standalone engine that implements the fish_inject engine interface
2. **Message Detection**: automatic detection of FiSH 10 messages using the `+OK` prefix and `DH1080_*` patterns
3. **Automatic Routing**: incoming FiSH 10 messages are automatically decrypted, outgoing messages are automatically encrypted
4. **Key Management**: uses the legacy blowfish.ini file format for key storage

## Usage

### Registering the FiSH 10 engine

To use the FiSH 10 engine, you need to register it with the fish_inject system:

```c
// Get the FiSH 10 engine pointer
const FishInjectEngine* fish10_engine = FiSH10_RegisterEngine();

if (fish10_engine != NULL) {
    // Register the engine with fish_inject
    int result = RegisterEngine(fish10_engine);
    
    if (result == 0) {
        printf("FiSH 10 engine registered successfully\n");
    } else {
        printf("Failed to register FiSH 10 engine: %d\n", result);
    }
} else {
    printf("Failed to get FiSH 10 engine pointer\n");
}
```

### Checking Engine Availability

You can check if the FiSH 10 engine is available:

```c
int available = FiSH10_IsEngineAvailable();
if (available) {
    printf("FiSH 10 engine is available\n");
} else {
    printf("FiSH 10 engine is not available\n");
}
```

### Getting engine version

```c
uint32_t version = FiSH10_GetEngineVersion();
printf("FiSH 10 engine version: %u\n", version);
```

## Message processing flow

### Incoming messages

1. **Detection**: The engine checks if the message starts with `+OK` (FiSH 10 encrypted) or `DH1080_` (key exchange)
2. **Decryption**: FiSH 10 encrypted messages are decrypted using the appropriate key
3. **Key Exchange**: DH1080 messages are processed to establish shared secrets
4. **Forwarding**: Decrypted messages are passed to other engines for further processing

### Outgoing messages

1. **Detection**: The engine checks if the target has a legacy key configured
2. **Encryption**: Messages to legacy targets are automatically encrypted with FiSH 10
3. **Key Exchange**: DH1080 key exchange messages are generated when needed
4. **Forwarding**: Encrypted messages are sent to the IRC server

## Configuration

The FiSH 10 engine uses the legacy `blowfish.ini` file format for key storage. Keys can be managed using the existing FiSH 10 DLL functions:

- `FiSH10_SetKey()` - Set a key for a target
- `FiSH10_DH1080_GenerateKeyPair()` - Generate DH1080 key pair
- `FiSH10_DH1080_ComputeSecret()` - Compute shared secret
- `FiSH10_DH1080_SetKey()` - Set DH1080 key


## Troubleshooting

### Engine not available

If `FiSH10_IsEngineAvailable()` returns 0:

1. Check that the legacy system is initialized
2. Verify that the DLL is properly loaded
3. Check the logs for initialization errors

### Messages not being processed

1. Verify that the engine is registered with fish_inject
2. Check that keys are properly configured for the target
3. Ensure that the message format matches FiSH 10 specifications

### Performance issues

1. Check for excessive logging (reduce log level if needed)
2. Verify that key lookups are efficient
3. Ensure that encryption/decryption operations are optimized

## Future enhancements

Potential improvements for future versions:

1. **Network-aware key management**: Associate keys with specific networks
2. **Enhanced DH1080 implementation**: Replace dummy DH operations with real cryptography
3. **Performance optimization**: Optimize Blowfish operations
4. **Extended key exchange**: Support additional key exchange protocols
5. **Better error reporting**: Provide more detailed error information to callers

## API Reference

### Functions

#### `FiSH10_RegisterEngine()`

Returns a pointer to the FiSH 10 engine structure for registration with fish_inject.

**Returns**: `*const FishInjectEngine` - Pointer to the engine, or NULL on error

#### `FiSH10_IsEngineAvailable()`

Checks if the FiSH 10 engine is available and initialized.

**Returns**: `i32` - 1 if available, 0 otherwise

#### `FiSH10_GetEngineVersion()`

Gets the version of the FiSH 10 engine.

**Returns**: `u32` - Engine version

