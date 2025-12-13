# How to Enable Decrypted Content Logging in FiSH-11

## Overview
FiSH-11 includes an optional feature to log the content of encrypted exchanges for debugging purposes. By default this feature is disabled to protect user privacy and security. This document explains how to safely enable it only when needed for troubleshooting.

## Enabling the Feature

### Method 1: Environment Variable (Recommended)
```bash
set LOG_SENSITIVE_CONTENT=1
cargo build --release
```

On Unix systems:
```bash
export LOG_SENSITIVE_CONTENT=1
cargo build --release
```

### Method 2: Compilation Feature
Alternatively, you can add a compilation feature flag to your build configuration, though the environment variable method is preferred for temporary debugging.

## Behavior When Enabled
When the `LOG_SENSITIVE_CONTENT` environment variable is set during compilation:

1. **Incoming Messages**: Decrypted message content will appear in logs with labels like:
   - `Engine: decrypted content from 'nickname': 'actual message text'`
   - `Engine: decrypted topic content for channel '#channel': 'topic text'`

2. **Outgoing Messages**: Messages before encryption and after encryption will be logged:
   - `Engine: topic encryption input for channel '#channel': 'plaintext message'`
   - `Engine: topic encrypted output for channel '#channel': 'base64_encrypted_data'`

3. **Channel Messages**: Similar logging for channel messages
4. **Private Messages**: Logging for private message content

## Security Considerations
⚠️ **WARNING**: This feature logs sensitive encrypted communications in plaintext. Only enable this feature when:
- Troubleshooting specific encryption/decryption issues
- Working in a secure, isolated testing environment
- You fully understand the privacy implications

Never enable this feature in production environments where sensitive data could be exposed.

## Disabling the Feature
To return to normal operation, simply unset the environment variable and rebuild:
```bash
# On Windows
set LOG_SENSITIVE_CONTENT=

# On Unix
unset LOG_SENSITIVE_CONTENT

# Then rebuild
cargo build --release
```

## Checking Current Status
The flag status is determined at compile-time. You can verify the current build by looking for log messages with "decrypted content" or "encryption input/output" labels. If these messages appear in your logs, the feature is currently enabled.