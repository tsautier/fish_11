# FiSH-11 DLL API reference

This document provides a detailed reference for all functions exported by the `fish_11_dll.dll`. These functions are designed to be called from mIRC scripts using the `/dll` command.

**Note**: in all examples, `fish_11.dll` is the filename of the DLL. The actual filename may vary.

---

## Core lifecycle functions

These functions are automatically called by mIRC or the Windows loader and should not be called manually.

- **`DllMain`**: the standard windows dll entry point. handles process attachment and detachment.
- **`LoadDll`**: called by mIRC when the DLL is loaded. it initializes the configuration and logs the mIRC version.
- **`UnloadDll`**: called by mIRC when the DLL is unloaded. it performs necessary cleanup.

---

## General an uility functions

### `FiSH11_GetVersion`

Returns the version of the FiSH-11 DLL.

- **usage**: `/dll fish_11.dll FiSH11_GetVersion`
- **parameters**: none
- **returns**: a string containing the version information, e.g., `FiSH-11 v1.1.0 - Licensed under the GPL v3.`

### `FiSH11_Help`

Displays a comprehensive list of available commands and version information.

- **usage**: `/dll fish_11.dll FiSH11_Help`
- **parameters**: none
- **returns**: a multi-line string (separated by `\r\n`) containing the help text. the mIRC script is responsible for parsing and displaying it.

### `FiSH11_SetMircDir`

Sets the path to the mIRC installation directory. This is used to help the DLL locate the `fish_11.ini` configuration file.

- **usage**: `/dll fish_11.dll FiSH11_SetMircDir C:\mIRC`
- **parameters**:
  - `path`: the absolute path to the mIRC directory.
- **returns**: a string confirming the directory has been set.

### `FiSH11_GetConfigPath`

Returns the full path to the `fish_11.ini` configuration file currently being used.

- **usage**: `/dll fish_11.dll FiSH11_GetConfigPath`
- **parameters**: none
- **returns**: a string containing the absolute path to the configuration file.

---

## Private message key management

### `FiSH11_GenKey`

Generates a new random symmetric key for a user. This command will fail if a key for that nickname already exists.

- **usage**: `/dll fish_11.dll FiSH11_GenKey <nickname>`
- **parameters**:
  - `nickname`: the nickname to associate with the new key.
- **returns**: a string confirming the key generation.

### `FiSH11_SetKey`

Manually sets the symmetric key for a user. The key must be a 32-byte value, encoded in Base64. This will overwrite any existing key for that user.

- **usage**: `/dll fish_11.dll FiSH11_SetKey <nickname> <base64_key>`
- **parameters**:
  - `nickname`: the nickname to associate with the key.
  - `base64_key`: the 32-byte key, encoded in Base64.
- **returns**: `1` on success. on failure, returns an error message.

### `FiSH11_FileGetKey`

Retrieves the stored symmetric key for a given nickname, encoded in Base64.

- **usage**: `/dll fish_11.dll FiSH11_FileGetKey <nickname>`
- **parameters**:
  - `nickname`: the nickname whose key you want to retrieve.
- **returns**: the base64-encoded key as a string. on failure, returns an error message.

### `FiSH11_FileDelKey`

Deletes the key associated with a specific nickname from the configuration.

- **usage**: `/dll fish_11.dll FiSH11_FileDelKey <nickname>`
- **parameters**:
  - `nickname`: the nickname whose key should be deleted.
- **returns**: `1` on success. on failure, returns an error message.

### `FiSH11_FileListKeys`

Returns a formatted list of all stored nicknames and their associated networks.

- **usage**: `/dll fish_11.dll FiSH11_FileListKeys`
- **parameters**: none
- **returns**: a multi-line string (separated by `\r\n`) listing all keys.

### `FiSH11_GetKeyFingerprint`

Calculates and returns a human-readable fingerprint for a user's key. This is useful for verifying keys out-of-band. The fingerprint is derived from the SHA-256 hash of the key.

- **usage**: `/dll fish_11.dll FiSH11_GetKeyFingerprint <nickname>`
- **parameters**:
  - `nickname`: the nickname whose key fingerprint you want.
- **returns**: a string containing the formatted fingerprint, e.g., `Key fingerprint for alice: ABCD EFGH IJKL MNOP`.

### `FiSH11_GetKeyTTL`

Get the time-to-live (TTL) for a key in seconds.

- **usage**: `/dll fish_11.dll FiSH11_GetKeyTTL <nickname> [network]`
- **parameters**:
  - `nickname`: the nickname for which to get the TTL
  - `network` (optional): the network name (default: current network)
- **returns**:
  - `>0` - Time remaining until expiration in seconds
  - `EXPIRED` - Key has expired (for mIRC scripts)
  - `NO_TTL` - Key is not an exchange key (manual key)
  - Error message on failure

### `FiSH11_GetKeyTTLHumanReadable`

Get the time-to-live (TTL) for a key in a human-readable format.

- **usage**: `/dll fish_11.dll FiSH11_GetKeyTTLHumanReadable <nickname> [network]`
- **parameters**:
  - `nickname`: the nickname for which to get the TTL
  - `network` (optional): the network name (default: current network)
- **returns**:
  - Human-readable TTL description (e.g., "12h 30m", "EXPIRED", "NO_TTL")
  - Error message on failure

### `FiSH11_GetKeyStatus`

Get detailed status information for a key.

- **usage**: `/dll fish_11.dll FiSH11_GetKeyStatus <nickname> [network]`
- **parameters**:
  - `nickname`: the nickname for which to get the status
  - `network` (optional): the network name (default: current network)
- **returns**:
  - JSON-like status information including nickname, network, is_exchange, is_valid, and TTL
  - Error message on failure

### `FiSH11_GetKeyStatusHumanReadable`

Get human-readable status information for a key.

- **usage**: `/dll fish_11.dll FiSH11_GetKeyStatusHumanReadable <nickname> [network]`
- **parameters**:
  - `nickname`: the nickname for which to get the status
  - `network` (optional): the network name (default: current network)
- **returns**:
  - Human-readable status description (e.g., "exchange key, expires in 12h 30m", "manual key, expired")
  - Error message on failure

### `FiSH11_GetAllKeysWithTTL`

Get information about all keys with their TTL status.

- **usage**: `/dll fish_11.dll FiSH11_GetAllKeysWithTTL`
- **parameters**: none
- **returns**:
  - List of all keys with their status information
  - Error message on failure

### `FiSH11_GetConfiguredKeyTTL`

Get the configured TTL for exchange keys.

- **usage**: `/dll fish_11.dll FiSH11_GetConfiguredKeyTTL`
- **parameters**: none
- **returns**:
  - TTL in seconds on success
  - Error message on failure

### `FiSH11_SetKeyTTL`

Set the TTL for exchange keys (not yet implemented).

- **usage**: `/dll fish_11.dll FiSH11_SetKeyTTL <ttl_seconds>`
- **parameters**:
  - `ttl_seconds`: the TTL in seconds
- **returns**:
  - Success message on success
  - Error message on failure

---

## Asymmetric key exchange (X25519)

These functions are used to securely establish a shared secret with another user.

### `FiSH11_ExchangeKey`

Initiates a key exchange with a user. It ensures a local keypair exists (generating one if necessary) and returns a public key token to be sent to the other user.

- **usage**: `/dll fish_11.dll FiSH11_ExchangeKey <nickname>`
- **parameters**:
  - `nickname`: the nickname of the user you are initiating the exchange with.
- **returns**: a public key token string, e.g., `FiSH11-PubKey:BASE64...`.

### `FiSH11_ProcessPublicKey`

Processes a public key token received from another user, computes the shared secret, and stores it as the symmetric key for that user.

- **usage**: `/dll fish_11.dll FiSH11_ProcessPublicKey <nickname> <public_key_token>`
- **parameters**:
  - `nickname`: the nickname of the user who sent the key.
  - `public_key_token`: the full public key token string received from the user.
- **returns**: a string confirming the successful key exchange.

---

## Encryption and decryption

### `FiSH11_EncryptMsg`

Encrypts a message for a target user or channel.

- **usage**: `/dll fish_11.dll FiSH11_EncryptMsg <target> <message>`
- **parameters**:
  - `target`: the recipient's nickname or the channel name (e.g., `#channel`).
  - `message`: the plaintext message to encrypt.
- **behavior**:
  - **private message**: if the target is a nickname, it uses the pre-established symmetric key for that user.
  - **channel message**: if the target is a channel (starts with `#` or `&`), it uses the FCEP-1 ratchet-based key for that channel.
- **returns**: the encrypted message, prefixed with `+FiSH `, e.g., `+FiSH BASE64...`.

### `FiSH11_DecryptMsg`

Decrypts a message received from a user or in a channel.

- **usage**: `/dll fish_11.dll FiSH11_DecryptMsg <target> <encrypted_message>`
- **parameters**:
  - `target`: the sender's nickname or the channel name (e.g., `#channel`).
  - `encrypted_message`: the encrypted message string (the `+FiSH ` prefix is optional and will be stripped).
- **behavior**:
  - **private message**: uses the symmetric key associated with the sender's nickname.
  - **channel message**: uses the FCEP-1 ratchet-based key for the channel, handling out-of-order messages and replay protection.
- **returns**: the decrypted plaintext message.

---

## Channel encryption (FCEP-1 : FiSH Channel Encryption Protocol v1)

These functions manage keys for multi-user encrypted channels.

### `FiSH11_InitChannelKey`

Generates a new channel key and distributes it to the specified members. This function is typically called by the channel coordinator.

- **usage**: `/dll fish_11.dll FiSH11_InitChannelKey <#channel> <nick1> <nick2> ...`
- **parameters**:
  - `<#channel>`: the name of the channel.
  - `<nick1> <nick2> ...`: a space-separated list of member nicknames who should receive the key.
- **pre-requisite**: a 1-to-1 symmetric key must already exist for each member (established via `FiSH11_ExchangeKey`).
- **returns**: a series of `/notice` commands (concatenated with `|`) for the mIRC script to execute, which sends the wrapped channel key to each member. Also includes a final confirmation message.

### `FiSH11_ProcessChannelKey`

Processes a received channel key from a coordinator. This function is typically called automatically by the mIRC script when a `+FiSH-CEP-KEY` notice is received.

- **usage**: `/dll fish_11.dll FiSH11_ProcessChannelKey <#channel> <coordinator_nick> <actual_sender> <wrapped_key>`
- **parameters**:
  - `<#channel>`: the channel the key is for.
  - `<coordinator_nick>`: the nickname of the user who claims to have initiated the key distribution.
  - `<actual_sender>`: the real IRC nickname of the sender (provided by the mIRC script, e.g., `$nick`). This is a security measure to prevent impersonation.
  - `<wrapped_key>`: the Base64-encoded wrapped channel key.
- **returns**: a confirmation message that the key was received and stored. Rejects the key if `coordinator_nick` does not match `actual_sender`.
