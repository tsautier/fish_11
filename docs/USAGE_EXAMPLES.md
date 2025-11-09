# Usage examples

## mIRC script commands (via `fish_11.mrc`)

The provided `fish_11.mrc` script offers a user-friendly layer over the raw DLL functions. These are the recommended commands for daily use.

```mirc
; Start an automatic key exchange with user "bob"
/fish11_keyx bob

; Show the Base64-encoded symmetric key for a user or channel
/fish11_showkey #channel

; Show the SHA-256 fingerprint of the key for user "bob" for out-of-band verification
/fish11_showfingerprint bob

; Manually set a symmetric key for a target
/fish11_setkey #channel myBase64Key==

; Remove a key from storage
/fish11_removekey bob

; Initialize a new encrypted channel with bob and carol as members
/fish11_initchannel #secrets bob carol
```

## Direct DLL calls

These examples show how to call the DLL functions directly. This is generally not needed if you are using the `fish_11.mrc` script, but it is useful for debugging or custom scripting.

```mirc
; Generate a new symmetric key for a user/channel
/dll fish_11.dll FiSH11_GenKey #channel

; Start the manual key exchange process with "bob"
/dll fish_11.dll FiSH11_ExchangeKey bob

; Encrypt a message manually for a target with a pre-existing key
/dll fish_11.dll FiSH11_EncryptMsg #channel Hello World

; Decrypt a received message manually
/dll fish_11.dll FiSH11_DecryptMsg #channel +FiSH <encrypted_data>

; Get the fingerprint for a key
/dll fish_11.dll FiSH11_GetKeyFingerprint bob

; List all stored keys
/dll fish_11.dll FiSH11_FileListKeys
```
