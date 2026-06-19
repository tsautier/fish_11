;*******************************
;* FiSH_11 Key Management      *
;*******************************
; Key set/get/del/list and fingerprint operations
; Written by GuY, 2025. Licensed under GPL-v3.

; === TRACK NICK CHANGES FOR KEY MANAGEMENT ===
on *:NICK:{
  if (($nick == $me) || ($upper($newnick) == $upper($nick))) { return }
  if (($query($newnick) == $null) || (%NickTrack != [On])) { return }
  
  var %old_nick_key = $dll(%Fish11DllFile, FiSH11_FileGetKey, $nick)
  
  ; If we have a key for the old nick
  if ($len(%old_nick_key) > 4) {
    var %new_nick_key = $dll(%Fish11DllFile, FiSH11_FileGetKey, $newnick)
    
    ; If a key already exists for the new nick, warn user about conflict
    if ($len(%new_nick_key) > 4) {
      echo $color(Error) -at *** FiSH_11: nick change conflict ! You have a key for $nick, who is now $newnick. However, you ALREADY have a different key for $newnick. No keys were changed. Please resolve this manually.
      unset %old_nick_key
      unset %new_nick_key
      return
    }
    
    ; Store the key under the new nickname
    if ($dll(%Fish11DllFile, FiSH11_SetKey, $+($network," ",$newnick," ",%old_nick_key))) {
      echo $color(Mode text) -at *** FiSH_11: key for $nick has been moved to new nick $newnick.
      ; Remove the key from the old nickname to prevent reuse by another user
      noop $dll(%Fish11DllFile, FiSH11_FileDelKey, $+($network," ",$nick))
    }
    unset %new_nick_key
  }
  unset %old_nick_key
}


; === KEY MANAGEMENT FUNCTIONS ===
; Set key with different encoding options
alias fish11_setkey {
  if ($1 == $null || $2 == $null) {
    echo 4 -a Syntax: /fish11_setkey <nickname> <key>
    return
  }
  ; $1 = nickname (data), $2- = key (parms)
  var %msg = $dll(%Fish11DllFile, FiSH11_SetKey, $+($network, $chr(32), $1, $chr(32), $2-))
  if (%msg && $left(%msg, 6) != Error:) {
    echo -a *** FiSH_11: key set for $1 on network $network
  }
  else {
    var %error_msg = $iif(%msg, %msg, "Unknown error - could not set key for $1")
    echo -a *** FiSH_11: error setting key for $1 - %error_msg
  }
  unset %msg
}

alias fish11_setkey_manual {
  if ($1 == $null || $2 == $null) {
    echo 4 -a Syntax: /fish11_setkey_manual <#channel> <base64_encoded_32byte_key>
    echo 4 -a Example: /fish11_setkey_manual #secret AGN2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8s9T0
    return
  }

  ; Validate channel name format
  var %channel = $1
  if (!$regex(%channel, /^[#&]/)) {
    echo 4 -a Error: Channel name must start with # or &
    return
  }

  ; Validate key format (base64, 44 chars)
  var %key = $2-
  
  if ($len(%key) == 44 && $regex(%key, /^[A-Za-z0-9+\/=]+$/)) {
    ; Valid base64 key - use standard function
    var %input = $+(%channel, $chr(32), %key)
    var %msg = $dll(%Fish11DllFile, FiSH11_SetManualChannelKey, %input)
  }
  else {
    ; Non-base64 or different length - use password derivation function
    var %input = $+(%channel, $chr(32), %key)
    var %msg = $dll(%Fish11DllFile, FiSH11_SetManualChannelKeyFromPassword, %input)
  }

  if (%msg && $left(%msg, 6) != Error:) {
    echo -a *** FiSH_11: manual channel key set for %channel
  }
  else {
    var %error_msg = $iif(%msg, %msg, "Unknown error - could not set manual key for %channel")
    echo -a *** FiSH_11: error setting manual key for %channel - %error_msg
  }
}

alias fish11_setkey_utf8 { fish11_writekey raw_bytes $1 $2- }

; Helper for setting keys
alias fish11_writekey {
  if ($2 == /query) var %cur_contact = $active
    else var %cur_contact = $2
  if ($3- == $null) return

  ; Comprehensive network sanitization - remove all special characters
  var %network = $regsubex($network, /[^\w\d]/g, _)

  if ($dll(%Fish11DllFile, FiSH11_SetKey, $+(%network," ",%cur_contact," ",$3-))) {      
    var %info = *** FiSH_11: key for %cur_contact set to *censored*

    if ($window(%cur_contact) == $null) echo $color(Mode text) -at %info
    else echo $color(Mode text) -tm %cur_contact %info
    return $true
  }
  return $false
}


; === KEY EXCHANGE INIT ===
; Initialize key exchange
alias fish11_X25519_INIT {
  if (($1 == /query) || ($1 == $null)) var %cur_contact = $active
  else var %cur_contact = $1

  ; If there's an existing exchange in progress, cancel it first
  if ($hget(fish11.dh, %cur_contact) == 1) {
    echo $color(Mode text) -at *** FiSH_11: restarting key exchange with %cur_contact
  }

  ; Use a hash table to track in-progress exchanges.
  hadd -m fish11.dh %cur_contact 1

  var %pub = $dll(%Fish11DllFile, FiSH11_ExchangeKey, %cur_contact)

  ; Use regex to validate the entire key format.
  if ($regex(%pub, /^X25519_INIT:[A-Za-z0-9+\/=]+$/)) {
    .notice %cur_contact X25519_INIT %pub
    echo $color(Mode text) -tm %cur_contact *** FiSH_11: sent X25519_INIT to %cur_contact $+ , waiting for reply...
  }
  else {
    ; Fallback: show what we got (safely)
    echo $color(Mode text) -at *** FiSH_11: ERROR - key exchange initiation failed. DLL returned: $qt(%pub)
  }

  ; Start a timer to cancel the exchange if no response is received
  .timer.fish11_x25519_ $+ %cur_contact 1 %KEY_EXCHANGE_TIMEOUT_SECONDS fish11_timeout_keyexchange %cur_contact
}

; Process received public key
alias fish11_ProcessPublicKey {
  if ($1 == $null || $2 == $null) {
    echo 4 -a Syntax: /fish11_ProcessPublicKey <nickname> <public_key>
    return
  }
  
  ; Process the public key
  var %result = $dll(%Fish11DllFile, FiSH11_ProcessPublicKey, $1 $2-)
  
  ; Check if processing was successful (no error message)
  if (%result && $left(%result, 6) != Error:) {
    echo $color(Mode text) -at *** FiSH_11: key exchange completed with $1
    echo $color(Error) -at *** FiSH_11 WARNING: key exchange complete, but the identity of $1 is NOT VERIFIED.
    echo $color(Error) -at *** FiSH_11: use /fish_fp11 $1 to see their key fingerprint and verify it with them through a secure channel (e.g., voice call).
  }
  else {
    ; Display error message from DLL
    echo $color(Mode text) -at *** FiSH_11: %result
  }
}

; Shorthand for key exchange
alias keyx { fish11_X25519_INIT $1 }


; === USE KEY FROM ANOTHER CHANNEL/USER ===
alias fish11_usechankey {
  if ($server == $null) {
    echo $color(Mode text) -at *** FiSH_11: ERROR - not connected to a server.
    return
  }
  var %theKey = $dll(%Fish11DllFile, FiSH11_FileGetKey, $2)
  if (%theKey == $null) {
    echo $color(Mode text) -at *** FiSH_11: no valid key for $2 found
  }
  else {
    if ($dll(%Fish11DllFile, FiSH11_SetKey, $+($network," ",$1," ",%theKey))) {
      echo $color(Mode text) -at *** FiSH_11: using same key as $2 for $1
    }
    unset %theKey
  }
}


; === SHOW KEY ===
alias fish11_showkey {
  if ($1 == /query) var %cur_contact = $active
  else var %cur_contact = $1

  var %theKey = $dll(%Fish11DllFile, FiSH11_FileGetKey, %cur_contact)
  if (%theKey != $null) {
    window -dCo +l @FiSH-Key -1 -1 500 80
    aline @FiSH-Key Key for %cur_contact :
    aline -p @FiSH-Key %theKey
    unset %theKey
  }
  else {
    echo $color(Mode text) -at *** FiSH_11: no valid key for %cur_contact found
  }
}


; === REMOVE KEY ===
alias fish11_removekey {
  if ($1 == /query) var %cur_contact = $active
  else var %cur_contact = $1
  
  ; Get result message from DLL
  var %msg = $dll(%Fish11DllFile, FiSH11_FileDelKey, $+($network," ",%cur_contact))
  
  ; Display message from DLL (works for both success and error)
  if (%msg) {
    echo $color(Mode text) -at *** FiSH_11: %msg
  }
  else {
    echo $color(Mode text) -at *** FiSH_11: error - could not remove key for %cur_contact
  }
}


; === SAFETY FUNCTION ===
; Safety function to prevent accidental key overwrites
alias fish11_setkey_safe {
  var %target = $1
  var %existing_key = $dll(%Fish11DllFile, FiSH11_FileGetKey, %target)
  
  if ($len(%existing_key) > 1) {
    if ($?!="Key already exists for %target $+ . Overwrite? (Yes/No)") {
      fish11_setkey %target $2-
    }
  }
  else {
    fish11_setkey %target $2-
  }
}


; === KEY TTL (EXPIRATION) ===
; Show the remaining lifetime of an exchange key
; Exchange keys have a 24-hour TTL from creation time
; Usage: /fish11_keyttl <nickname>
alias fish11_keyttl {
  if ($1 == $null) {
    echo 4 -a Syntax: /fish11_keyttl <nickname>
    return
  }
  
  var %nickname = $1
  var %ttl = $dll(%Fish11DllFile, FiSH11_GetKeyTTL, %nickname)
  
  if (%ttl == EXPIRED) {
    echo $color(Error) -at *** FiSH_11: key for %nickname has EXPIRED
    echo $color(Mode text) -at *** FiSH_11: use /fish11_X25519_INIT %nickname to establish a new key
  }
  else if (%ttl == NO_TTL) {
    echo $color(Mode text) -at *** FiSH_11: key for %nickname has no expiration (manually set key)
  }
  else if (%ttl isnum) {
    var %hours = $int($calc(%ttl / 3600))
    var %mins = $int($calc((%ttl % 3600) / 60))
    echo $color(Mode text) -at *** FiSH_11: key for %nickname expires in %hours hours %mins minutes
  }
  else {
    echo $color(Error) -at *** FiSH_11: could not get key TTL for %nickname
  }
}

; Short alias for key TTL
alias fkeyttl { fish11_keyttl $1 }


; === LIST ALL KEYS ===
alias fish11_file_list_keys {
  var %keys

  ; Check the DLL exists before trying to call it
  if (!$isfile(%Fish11DllFile)) {
    echo $color(Mode text) -at *** FiSH ERROR- DLL not found: %Fish11DllFile
    return
  }
  ; Log that we're about to call the function
  echo $color(Mode text) -at *** FiSH: listing keys...
  ; Ensure MIRCDIR is set (should already be set at startup, but be safe)
  noop $dll(%Fish11DllFile, FiSH11_SetMircDir, $mircdir)
  
  ; Initialize the buffer variable
  var %keys
  
  ; Call DLL function using proper syntax for data return
  echo $color(Mode text) -at *** FiSH: about to call FiSH11_FileListKeys...
  var %keys = $dll(%Fish11DllFile, FiSH11_FileListKeys, $null)
  echo $color(Mode text) -at *** FiSH: DLL call completed, result length: $len(%keys)
  
  ; Check for errors (DLL returns "Error: ..." for errors)
  if ($left(%keys, 6) == Error:) {
    echo $color(Error) -at *** FiSH ERROR: %keys
    return
  }
  
  ; If the function returns data, display it line by line
  if (%keys != $null && $len(%keys) > 0) {
    fish11_display_multiline_result %keys
  }
  else {
    echo $color(Mode text) -at *** FiSH: no keys found
  }
}


; Helper function to safely display multi-line text from DLL
alias fish11_display_multiline_result {
  var %text = $1-
  var %line_count = 0
  var %max_lines = 100

  ; Handle different line ending formats
  %text = $replace(%text, $chr(13) $+ $chr(10), $chr(1))
  %text = $replace(%text, $chr(13), $chr(1))
  %text = $replace(%text, $chr(10), $chr(1))

  ; Display each line
  var %i = 1
  var %num_tokens = $numtok(%text, 1)
  while (%i <= %num_tokens) {
    var %line = $gettok(%text, %i, 1)

    ; Safety check: limit number of lines to prevent crashes
    inc %line_count
    if (%line_count > %max_lines) {
      echo $color(Mode text) -at *** FiSH_11: output truncated (exceeded %max_lines lines)
      break
    }

    ; Display the line with proper formatting
    if ($len(%line) > 0) {
      echo $color(Mode text) -at %line
    }

    inc %i
  }
}


; === FINGERPRINT ===
; Helper function to get and format colored fingerprint for a target
; Returns the colored fingerprint or $null if not available
; Also caches the result in %fish11.lastfingerprint.<target>
alias -l fish11_GetColoredFingerprint {
  var %target = $1
  
  ; Check if there's a cached fingerprint first
  if (%fish11.lastfingerprint. $+ [ %target ] != $null) {
    return $($+(%,fish11.lastfingerprint.,%target),2)
  }
  
  ; Get the fingerprint from DLL
  var %fingerprint = $dll(%Fish11DllFile, FiSH11_GetKeyFingerprint, %target)
  
  ; Check if the response is an error message
  if ($left(%fingerprint, 6) == Error:) {
    return $null
  }
  
  ; Extract just the fingerprint part from the response
  var %fp_only = $gettok(%fingerprint, 2-, 58)
  var %fp_only = $strip(%fp_only)
  
  ; Validate that we have a proper fingerprint
  if (%fp_only == $null || $len(%fp_only) < 10 || $pos(%fp_only, $chr(32)) == 0) {
    return $null
  }
  
  ; Format each group with a different color
  var %group1 = $gettok(%fp_only, 1, 32)
  var %group2 = $gettok(%fp_only, 2, 32) 
  var %group3 = $gettok(%fp_only, 3, 32)
  var %group4 = $gettok(%fp_only, 4, 32)
  
  ; Validate that we have at least 4 groups
  if (%group1 == $null || %group2 == $null || %group3 == $null || %group4 == $null) {
    return $null
  }
  
  ; Create colored version using mIRC color codes
  ; 04=red, 12=blue, 03=green, 07=orange
  var %colored_fp = 04 $+ %group1 $+  12 $+ %group2 $+  03 $+ %group3 $+  07 $+ %group4
  
  ; Cache the result
  set %fish11.lastfingerprint. $+ [ %target ] %colored_fp
  
  return %colored_fp
}

; Display key fingerprint with color for a target
alias fish11_showfingerprint {
  if ($1 == /query) {
    var %target = $active
  }
  else {
    var %target = $1
  }
  
  ; Check if we have a key for this target
  var %key = $dll(%Fish11DllFile, FiSH11_FileGetKey, %target)
  
  if ($len(%key) > 1) {
    var %colored_fp = $fish11_GetColoredFingerprint(%target)
    
    if (%colored_fp != $null) {
      ; Display the colored fingerprint
      echo $color(Mode text) -at *** FiSH_11: key fingerprint for %target is: %colored_fp
    }
    else {
      echo $color(Mode text) -at *** FiSH_11: Error: could not retrieve valid fingerprint for %target
    }
  }
  else {
    echo $color(Mode text) -at *** FiSH_11: no key found for %target
  }
}


; === ALIAS SHORTCUTS FOR USER COMMANDS ===
alias fish_genkey11 { fish11_setkey_safe $1 $2- }
alias fish_setkey11 { fish11_setkey $1 $2- }
alias fish_getkey11 { fish11_showkey $1 }
alias fish_fp11 { fish11_showfingerprint $1- }
alias fish_delkey11 { fish11_removekey $1 }
alias fish_listkeys11 { fish11_file_list_keys }
alias fish_encrypt11 { return $fish11_encrypt($1, $2-) }
alias fish_decrypt11 { return $fish11_decrypt($1, $2-) }
alias fish_keyx11 { fish11_X25519_INIT $1 }
alias fish_keyp11 { fish11_ProcessPublicKey $1 $2- }
alias fish_test11 { fish11_test_crypt $1- }
alias fish_help11 { fish11_help }
alias fish_version11 { fish11_version }
alias fish_initchannel11 { fish11_initchannel $1- }
alias fish_stats11 { fish11_stats }
