;*******************************
;* FiSH_11 Channel Encryption   *
;*******************************
; Channel encryption (FCEP-1) and manual channel key management
; Written by GuY, 2025. Licensed under GPL-v3.

; === CHANNEL JOIN HANDLING ===
on *:JOIN:#:{
  ; Only process our own joins
  if ($nick != $me) return
  
  ; Get channel key if it exists
  var %theKey = $dll(%Fish11DllFile, FiSH11_FileGetKey, $chan)
  if (%theKey != $null) {
    echo $color(Mode text) -at *** FiSH_11: found encryption key for $chan

    ; Check if topic encryption is enabled for this channel
    var %encryptTopic = $fish11_GetChannelIniValue($chan, encrypt_topic)
    if (%encryptTopic == 1) {
      echo $color(Mode text) -at *** FiSH_11: topic encryption enabled for $chan
    }
  }
  unset %theKey
}


; === FCEP-1 CHANNEL ENCRYPTION PROTOCOL HANDLERS ===
; FCEP-1 (FiSH-11 Channel Encryption Protocol) enables secure multi-party
; channel encryption using a hub-and-spoke model where a coordinator distributes
; a shared channel key to all participants via their pre-established pairwise keys.

on ^*:NOTICE:+FiSH-CEP-KEY*:?:{
  ; This event triggers when receiving a channel key distribution message.
  ; Format: +FiSH-CEP-KEY <#channel> <coordinator_nick> <base64_wrapped_key>
  ; $1 = +FiSH-CEP-KEY
  ; $2 = #channel
  ; $3 = coordinator_nick (claimed sender)
  ; $4 = base64_wrapped_key
  
  var %num_tokens = $numtok($1-, 32)
  
  ; Validate message format
  if (%num_tokens < 4) {
    echo -s $chr(9) $+ $chr(160) $+ $chr(9604) FISH_11 : FCEP-1 ERROR : Invalid +FiSH-CEP-KEY format from $nick (expected 4 tokens, got %num_tokens $+ )
    halt
  }
  
  var %channel = $2
  var %coordinator = $3
  var %wrapped_key = $4
  
  ; SECURITY: Verify sender authenticity
  ; The actual IRC sender ($nick) MUST match the claimed coordinator
  ; This prevents impersonation attacks where an attacker sends a +FiSH-CEP-KEY
  ; message claiming to be from a trusted user
  if ($nick != %coordinator) {
    echo -s $chr(9) $+ $chr(160) $+ $chr(9604) FiSH_11 : FCEP-1 SECURITY WARNING : key distribution from $nick claims to be from %coordinator - REJECTED
    echo -s $chr(9) $+ $chr(160) $+ $chr(9604) FiSH_11 : FCEP-1 : this may indicate an impersonation attack attempt!
    halt
  }
  
  ; Validate channel name format
  if (!$regex(%channel, /^[#&]/)) {
    echo -s $chr(9) $+ $chr(160) $+ $chr(9604) FiSH_11 : FCEP-1 ERROR : invalid channel name format: %channel (must start with # or &)
    halt
  }
  
  ; Verify we have a pre-shared key with the coordinator
  var %existing_key = $dll(%Fish11DllFile, FiSH11_FileGetKey, %coordinator)
  
  ; Check for errors or empty/missing key
  if ($left(%existing_key, 6) == Error: || $len(%existing_key) < 4) {
    if ($left(%existing_key, 6) == Error:) {
      echo -s $chr(9) $+ $chr(160) $+ $chr(9604) FiSH_11 : FCEP-1 ERROR: $right(%existing_key, $calc($len(%existing_key) - 6))
    }
    else {
      echo -s $chr(9) $+ $chr(160) $+ $chr(9604) FiSH_11 : FCEP-1 ERROR: no pre-shared key found for coordinator %coordinator
      echo -s $chr(9) $+ $chr(160) $+ $chr(9604) FiSH_11 : FCEP-1 : you must establish a key with %coordinator first using /fish11_X25519_INIT %coordinator
    }
    halt
  }
  
  ; Process the channel key via DLL
  ; DLL will: decode base64, verify sender, unwrap key with pre-shared key, store channel key
  var %result = $dll(%Fish11DllFile, FiSH11_ProcessChannelKey, %channel %coordinator $nick %wrapped_key)
  
  ; Check for success (DLL returns raw message, check if it's an error)
  if (%result && $left(%result, 6) != Error:) {
    ; Success - display confirmation message
    echo -s $chr(9) $+ $chr(160) $+ $chr(9604) FiSH_11 : FCEP-1 : %result
  }
  else {
    ; Error occurred - display error from DLL
    echo -s $chr(9) $+ $chr(160) $+ $chr(9604) FiSH_11 : FCEP-1 ERROR: %result
  }
  
  halt
}


; === FCEP-1 CHANNEL ENCRYPTION COMMANDS ===

; Initialize channel encryption by generating and distributing a channel key
; Usage: /fish11_initchannel <#channel> <nick1> [nick2] [nick3] ...
; Example: /fish11_initchannel #secret alice bob charlie
alias fish11_initchannel {
  if ($1 == $null || $2 == $null) {
    echo $color(Error) -at *** FiSH_11 FCEP-1: Usage: /fish11_initchannel <#channel> <nick1> [nick2] ...
    echo $color(Mode text) -at *** FiSH_11 FCEP-1: Example: /fish11_initchannel #secret alice bob charlie
    echo $color(Mode text) -at *** FiSH_11 FCEP-1: Note: You must have pre-shared keys with all listed members (use /fish11_X25519_INIT first)
    return
  }
  
  var %channel = $1
  var %members = $2-
  
  ; Validate channel name
  if (!$regex(%channel, /^[#&]/)) {
    echo $color(Error) -at *** FiSH_11 FCEP-1 ERROR: Invalid channel name %channel (must start with # or &)
    return
  }
  
  ; Confirm action with user
  echo $color(Mode text) -at *** FiSH_11 FCEP-1: Generating channel key for %channel
  echo $color(Mode text) -at *** FiSH_11 FCEP-1: Members to receive key: %members
  
  ; Call DLL to generate key and create distribution commands
  var %result = $dll(%Fish11DllFile, FiSH11_InitChannelKey, %channel %members)
  
  ; Check for errors (DLL returns "Error: ..." for errors)
  if ($left(%result, 6) == Error:) {
    echo $color(Error) -at *** FiSH_11 FCEP-1 ERROR: %result
    return
  }
  
  ; Parse result: commands are separated by | and last item is confirmation message
  var %num_parts = $numtok(%result, 124)
  var %i = 1
  var %has_commands = $false
  
  ; Execute all commands (parts starting with /)
  while (%i <= %num_parts) {
    var %part = $gettok(%result, %i, 124)
    if ($left(%part, 1) == /) {
      ; Security: Validate that this is an expected command before executing
      if ($left(%part, 8) == /notice ) {
        ; Only allow notice commands which are expected for FCEP-1
        %part
        %has_commands = $true
      }
      else {
        echo $color(Error) -at *** FiSH_11 FCEP-1: SECURITY WARNING - unexpected command from DLL: %part
      }
    }
    else {
      ; This is the confirmation message - display it
      echo $color(Mode text) -at *** FiSH_11 FCEP-1: %part
    }
    inc %i
  }
  
  ; If no commands were found, something went wrong
  if (!%has_commands) {
    echo $color(Error) -at *** FiSH_11 FCEP-1 ERROR: No distribution commands generated
  }
}

; Shorthand aliases for channel encryption
alias fcep { fish11_initchannel $1- }
alias chankey { fish11_initchannel $1- }
alias fcep11 { fish11_initchannel $1- }


; === CHANNEL SETTINGS DIALOG ===
; Direct command for channel encryption settings
alias fish11_channel_settings {
  ; Check if we're in a channel window (more robust check)
  if ($window($active).type != channel) {
    echo $color(Mode text) -at *** FiSH_11: This command can only be used in channel windows
    return
  }
  
  ; Open a dialog to choose encryption method
  var %choice = $input(Add Channel Key Encryption for $active $+ :, pvq, FiSH_11 Add Channel Key)
  if (%choice == $null) return
  
  if (%choice == 1) {
    ; Set Manual Key
    fish11_set_manual_key_dialog $active
  }
  elseif (%choice == 2) {
    ; Set FCEP-1 Key
    fish11_init_fcep_dialog $active
  }
}

; Short alias for channel settings
alias fcs { fish11_channel_settings }

; Dialog for manual key
alias fish11_set_manual_key_dialog {
  ; Check if we're in a channel window (more robust check)
  if ($window($active).type != channel) {
    echo $color(Error) -at *** FiSH_11: Manual key can only be set for channels. Current window: $active (type: $window($active).type)
    return
  }
  
  var %channel = $active
  var %key = $input(Enter 44-character base64 manual key for %channel $+ :, pvq, FiSH_11 Manual Channel Key)

  if (%key != $null) {
    fish11_setkey_manual %channel %key
  }
}

; Dialog for FCEP-1
alias fish11_init_fcep_dialog {
  ; Check if we're in a channel window (more robust check)
  if ($window($active).type != channel) {
    echo $color(Error) -at *** FiSH_11: FCEP-1 key can only be set for channels. Current window: $active (type: $window($active).type)
    return
  }
  
  var %channel = $active
  var %members = $input(Enter members to invite (space-separated) for %channel $+ :, pvq, FiSH_11 FCEP-1 Channel Setup)

  if (%members != $null) {
    fish11_initchannel %channel %members
  }
}

; Display channel key information
alias fish11_show_channel_key_info {
  var %channel = $1

  ; Check if we have a manual key
  var %hasManualKey = $dll(%Fish11DllFile, FiSH11_HasManualChannelKey, %channel)

  ; Check if we have a FCEP/ratchet key
  var %hasRatchetKey = $dll(%Fish11DllFile, FiSH11_HasRatchetChannelKey, %channel)

  ; Check if topic encryption is enabled
  var %encryptTopic = $fish11_GetChannelIniValue(%channel, encrypt_topic)

  window -dCo +l @FiSH-ChannelInfo -1 -1 400 150
  titlebar @FiSH-ChannelInfo Channel Encryption Info for %channel

  aline @FiSH-ChannelInfo Channel: %channel
  aline @FiSH-ChannelInfo $chr(160)
  aline @FiSH-ChannelInfo Manual Key: $iif(%hasManualKey == 1, Set, Not set)
  aline @FiSH-ChannelInfo FCEP/Ratchet Key: $iif(%hasRatchetKey == 1, Set, Not set)
  aline @FiSH-ChannelInfo Topic Encryption: $iif(%encryptTopic == 1, Enabled, Disabled)
  aline @FiSH-ChannelInfo $chr(160)

  if (%hasManualKey == 1 || %hasRatchetKey == 1) {
    aline @FiSH-ChannelInfo Status: Channel encryption is ACTIVE
    aline @FiSH-ChannelInfo All messages and topics will be encrypted
  }
  else {
    aline @FiSH-ChannelInfo Status: Channel encryption is INACTIVE
    aline @FiSH-ChannelInfo Messages and topics will be sent in plain text
  }

  button @FiSH-ChannelInfo "Close", 1, 150 120 100 25
  var %result = $input(,pv,@FiSH-ChannelInfo)
  window -c @FiSH-ChannelInfo
}

; Remove channel key
alias fish11_remove_channel_key {
  var %channel = $1

  ; Remove manual key if it exists
  noop $dll(%Fish11DllFile, FiSH11_RemoveManualChannelKey, %channel)

  ; Remove ratchet key if it exists
  noop $dll(%Fish11DllFile, FiSH11_RemoveRatchetChannelKey, %channel)

  ; Disable topic encryption
  fish11_SetChannelIniValue %channel encrypt_topic 0

  echo $color(Mode text) -at *** FiSH_11: All encryption keys removed for %channel
}
