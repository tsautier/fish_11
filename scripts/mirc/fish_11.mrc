;***********************
;* FiSH_11 mIRC Script *
;***********************
; "FiSH_11" - Secure IRC encryption script for mIRC
; Written by GuY, 2025. GPL v3.
;
; SECURITY NOTICE: The security of this script depends entirely on the
; binary DLL files (fish_11.dll, fish_11_inject.dll). This mIRC script
; only provides the user interface. Ensure the DLLs are from a trusted
; source, as vulnerabilities in them can compromise your system.

; === INITIALIZATION AND STARTUP ===
on *:START: {
  .fish11_startup
}

alias fish11_startup {
  echo 4 -a *** FiSH_11 SECURITY WARNING: for your safety, ensure your mIRC installation and this script are located in a secure, write-protected directory to prevent malicious DLLs from being loaded.

  var %exe_dir = $nofile($mircexe)

  ; Set paths to DLLs
  %Fish11InjectDllFile = $qt(%exe_dir $+ fish_11_inject.dll)
  %Fish11DllFile = $qt(%exe_dir $+ fish_11.dll)

  echo 4 -a DEBUG : loading DLLs...
  echo 4 -a DEBUG : Fish11InjectDllFile = %Fish11InjectDllFile
  echo 4 -a DEBUG : Fish11DllFile = %Fish11DllFile

  ; Check if DLLs exist
  if (!$exists(%Fish11InjectDllFile)) {
    echo 4 -a *** FiSH_11 ERROR: inject DLL not found: %Fish11InjectDllFile
    
   halt
  }
  
  if (!$exists(%Fish11DllFile)) {
    echo 4 -a *** FiSH_11 ERROR: DLL not found: %Fish11DllFile
    
   halt
  }

  ; Check mIRC's DLL lock
  if ($dllock) {
    echo 4 -a *** FiSH_11 ERROR: mIRC DLLs are locked. Enable DLLs in mIRC settings.
    
    halt
  }

  echo 4 -a DEBUG : Calling fish_11.dll FiSH11_SetMircDir to set configuration path...
  ;noop $dll(%Fish11DllFile, FiSH11_SetMircDir, $mircdir)
  echo 4 -a DEBUG : MIRCDIR set to: $mircdir
  
  ;echo 4 -a DEBUG : Calling fish_11_inject.dll FiSH11_InjectVersion...
  .dll %Fish11InjectDllFile FiSH11_InjectVersion
  
  ;echo 4 -a DEBUG : Calling fish_11.dll FiSH11_GetVersion...  
  .dll %Fish11DllFile FiSH11_GetVersion


  


  ; Initialize default settings if not already set
  if (%autokeyx == $null) { set %autokeyx [Off] }
  if (%mark_outgoing == $null) { set %mark_outgoing [Off] }
  if (%mark_style == $null) { set %mark_style 1 }
  if (%NickTrack == $null) { set %NickTrack [Off] }
  
    ; Register events for incoming messages
  .signal *:TEXT:*:*:fish11_incoming_text
  .signal *:ACTION:*:*:fish11_incoming_action
  .signal *:NOTICE:*:*:fish11_incoming_notice
  
}



; === WINDOW ACTIVATION HANDLER ===
on *:ACTIVE:*: {
  if ($window($active).type isin query channel) {
    fish11_UpdateStatusIndicator
  }
}

; === AUTO KEY EXCHANGE ===
on *:OPEN:?:{
  if (%autokeyx == [On]) {
    var %tmp1 = $dll(%Fish11DllFile, FiSH11_FileGetKey, $nick)
    if ($len(%tmp1) == 0) {
      fish11_X25519_INIT $nick
    }
    unset %tmp1
  }
}

; === OUTGOING MESSAGE HANDLING ===
on *:INPUT:*: {
  ; Check if message should be processed
  var %process_outgoing = $dll(%Fish11DllFile, INI_GetBool, process_outgoing 1)
  if (%process_outgoing == 0) return
  
  ; Get plain prefix
  var %plain_prefix = $dll(%Fish11DllFile, INI_GetString, plain_prefix +p)
  
  ; Don't process if message starts with plain prefix
  if ($left($1-, $len(%plain_prefix)) == %plain_prefix) {
    var %plain_msg = $right($1-, $calc($len($1-) - $len(%plain_prefix)))
    return
  }
  
  ; Don't process commands
  if (($left($1, 1) == /) && ($1 != /me) && ($1 != /msg) && ($1 != /notice)) return
  
  ; Handle message too long
  if ($len($1-) > 850) {
    echo 4 -a Mirc cannot handle lines longer than 850 characters. Text not sent.
    haltdef
    halt
    return
  }
  
  ; Handle message types
  var %target = $active
  var %message = $1-
  var %encrypted = $null
  
  ; Extract target for /msg and /notice
  if ($1 == /msg || $1 == /notice) {
    %target = $2
    %message = $3-
  }
  ; Handle /me actions
  else if ($1 == /me) {
    ; Check if actions should be encrypted
    var %encrypt_action = $dll(%Fish11DllFile, INI_GetBool, encrypt_action 0)
    if (%encrypt_action == 0) return
    
    %message = $2-
  }
  
  ; Try to encrypt
  %encrypted = $dll(%Fish11DllFile, FiSH11_EncryptMsg, %target %message)
  
  ; Only process if encryption was successful
  if (%encrypted != $null && $left(%encrypted, 5) != Error) {
    ; Add encryption mark if configured
    if (%mark_outgoing == [On]) {
      if (%mark_style == 1) {
        ; Suffix style
        .echo $color(own text) $active <$me> %message 12$chr(183)
      }
      else if (%mark_style == 2) {
        ; Prefix style
        .echo $color(own text) $active 12$chr(183) <$me> %message
      }
      else if (%mark_style == 3) {
        ; Colored brackets style
        .echo $color(own text) $active 12[+]3 <$me> %message
      }
    }
    
    ; Send encrypted message based on command type
    if ($1 == /notice) {
      .notice %target %encrypted
      haltdef
    }
    else if ($1 == /msg) {
      .msg %target %encrypted
      haltdef
    }
    else if ($1 == /me) {
      .action %encrypted
      haltdef
    }
    else {
      .msg %target %encrypted
      haltdef
    }
  }
}



; === INCOMING MESSAGE DETECTION AND HANDLING ===
on *:TEXT:*:*:{
  ; Check if we should process incoming messages
  var %process_incoming = $dll(%Fish11DllFile, INI_GetBool, process_incoming 1)
  if (%process_incoming == 0) return
  
  var %chan = $chan
  var %text = $1-
  var %decrypted = $null
  
  ; Check for encrypted message pattern (+FiSH)
  if ($regex(%text, /^\+FiSH /)) {
    ; Try to decrypt the message
    %decrypted = $dll(%Fish11DllFile, FiSH11_DecryptMsg, $iif(%chan, %chan, $nick) %text)
    
    if (%decrypted != $null && $left(%decrypted, 5) != Error) {
      ; Get encryption mark settings
      var %mark_pos = $dll(%Fish11DllFile, INI_GetInt, mark_position 1)
      var %mark_txt = $dll(%Fish11DllFile, INI_GetString, mark_encrypted 12$chr(183))
      
      ; Display decrypted message with appropriate mark
      var %display = $iif(%mark_pos == 1, %decrypted %mark_txt, %mark_txt %decrypted)
      var %safe_display = $strip(%display, b,c,i,k,o,r,u)
      echo $color(text) -t $iif(%chan, %chan, $nick) <$nick> %safe_display
      
      ; Halt to prevent default display
      haltdef
    }
  }
  
  ; Detect DH key exchange message
  else if ($regex(%text, /FiSH11-PubKey:[A-Za-z0-9+\/=]+/)) {
    echo $color(Mode text) -t $iif(%chan, %chan, $nick) *** FiSH_11: Received key exchange request from $nick
    echo $color(Mode text) -t $iif(%chan, %chan, $nick) *** Type /fish_keyp11 $nick %text to complete key exchange
    
    ; Automatic handling if configured
    if (%autokeyx == [On]) {
      fish11_ProcessPublicKey $nick %text
    }
  }
}

; Add handlers for action and notice messages
on *:ACTION:*:*:{
  ; Check if we should process incoming messages
  var %process_incoming = $dll(%Fish11DllFile, INI_GetBool, process_incoming 1)
  if (%process_incoming == 0) return
  
  var %chan = $chan
  var %text = $1-
  var %decrypted = $null
  
  ; Check for encrypted message pattern (+FiSH)
  if ($regex(%text, /^\+FiSH /)) {
    ; Try to decrypt the message
    %decrypted = $dll(%Fish11DllFile, FiSH11_DecryptMsg, $iif(%chan, %chan, $nick) %text)
    
    if (%decrypted != $null && $left(%decrypted, 5) != Error) {
      ; Get encryption mark settings
      var %mark_pos = $dll(%Fish11DllFile, INI_GetInt, mark_position 1)
      var %mark_txt = $dll(%Fish11DllFile, INI_GetString, mark_encrypted 12$chr(183))
      
      ; Display decrypted action with appropriate mark
      var %display = $iif(%mark_pos == 1, %decrypted %mark_txt, %mark_txt %decrypted)
      var %safe_display = $strip(%display, b,c,i,k,o,r,u)
      echo $color(action text) -t $iif(%chan, %chan, $nick) * $nick %safe_display
      
      ; Halt to prevent default display
      haltdef
    }
  }
}




on *:NOTICE:*:*:{
  ; Check if we should process incoming messages
  var %process_incoming = $dll(%Fish11DllFile, INI_GetBool, process_incoming 1)
  if (%process_incoming == 0) return
  
  var %chan = $chan
  var %text = $1-
  var %decrypted = $null
  
  ; Check for encrypted message pattern (+FiSH)
  if ($regex(%text, /^\+FiSH /)) {
    ; Try to decrypt the message
    %decrypted = $dll(%Fish11DllFile, FiSH11_DecryptMsg, $iif(%chan, %chan, $nick) %text)
    
    if (%decrypted != $null && $left(%decrypted, 5) != Error) {
      ; Get encryption mark settings
      var %mark_pos = $dll(%Fish11DllFile, INI_GetInt, mark_position 1)
      var %mark_txt = $dll(%Fish11DllFile, INI_GetString, mark_encrypted 12$chr(183))
      
      ; Display decrypted notice with appropriate mark
      var %display = $iif(%mark_pos == 1, %decrypted %mark_txt, %mark_txt %decrypted)
      var %safe_display = $strip(%display, b,c,i,k,o,r,u)
      echo $color(notice text) -t $iif(%chan, %chan, $nick) -$nick- %safe_display
      
      ; Halt to prevent default display
      haltdef
    }
  }
}



; === KEY EXCHANGE PROTOCOL HANDLERS ===
on ^*:NOTICE:X25519_INIT*:?:{
  ; 25519 base64 encoded public key should be 44 chars
  if ($len($2) == 44) {
    query $nick
    echo $color(Mode text) -tm $nick *** FiSH_11: Received X25519 public key from $nick $+ , sending mine...
    
    ; Generate our key pair
    var %tempkey = $dll(%Fish11DllFile, FiSH_ExchangeKey11, none)
    if (%tempkey) {
      %fish11.prv_key = $gettok(%tempkey, 1, 32)
      %fish11.pub_key = $gettok(%tempkey, 2, 32)
      unset %tempkey
      
      ; Process the received key
      var %secret = $dll(%Fish11DllFile, FiSH11_ProcessPublicKey, $+($nick," ",$2))
      
      ; Send our public key back
      .notice $nick X25519_FINISH %fish11.pub_key
      
      ; Set the computed shared key
      fish11_setkey $nick %secret
      
      unset %fish11.prv_key
      unset %fish11.pub_key
      unset %secret
    }
    else {
      echo $color(Mode text) -tm $nick *** FiSH_11: error generating key pair
    }
  }
  halt
}



on ^*:NOTICE:X25519_FINISH*:?:{
  if (%fish11.dh_ $+ [ $nick ] != 1) {
    echo "*** FiSH_11: no key exchange in progress!"
    halt
  }
  
  if ($len($2) > 178 && $len($2) < 182) {
    if ($len(%fish11.prv_key) == 180 || $len(%fish11.prv_key) == 181) {
      ; Process the received public key with our private key
      var %secret = $dll(%Fish11DllFile, FiSH11_ProcessPublicKey, $+($nick," ",$2))
        if (%secret) {
        ; Set the computed shared key
        fish11_setkey $nick %secret
        
        ; Clean up
        unset %fish11.dh_ $+ [ $nick ]
        unset %fish11.prv_key
        unset %fish11.pub_key
        unset %secret
        
        ; Cancel any pending timeout timer for this nick
        .timer fish_timeout_ $+ $nick off
        
        echo $color(Mode text) -tm $nick *** FiSH_11: key exchange complete with $nick
        echo $color(Error) -tm $nick *** FiSH_11: WARNING: Key exchange complete, but the identity of $nick is NOT VERIFIED.
        echo $color(Error) -tm $nick *** FiSH_11: Use /fish_fp11 $nick to see their key fingerprint and verify it with them through a secure channel (e.g., voice call).
      }
      else {
        echo $color(Mode text) -tm $nick *** FiSH_11: error processing key exchange
      }
    }
  }
  halt
}



; Handle key exchange timeout
alias fish11_timeout_keyexchange {
  if ($1 == $null) {
    echo $color(Mode text) -at *** FiSH_11: timeout handler called with no parameters
    return
  }
  
  var %contact = $1
  
  ; Check if key exchange is still in progress
  if (%fish11.dh_ $+ [ %contact ] == 1) {
    ; Clean up variables
    unset %fish11.dh_ $+ [ %contact ]
    
    ; Notify user of timeout with instructions
    echo $color(Mode text) -at *** FiSH_11: Key exchange with %contact timed out after $KEY_EXCHANGE_TIMEOUT_SECONDS seconds
    echo $color(Mode text) -at *** FiSH_11: To try again, use: /fish11_X25519_INIT %contact
  }
}



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
      echo $color(Error) -at *** FiSH_11: Nick Change Conflict! You have a key for $nick, who is now $newnick. However, you ALREADY have a different key for $newnick. No keys were changed. Please resolve this manually.
      unset %old_nick_key
      unset %new_nick_key
      return
    }
    
    ; Store the key under the new nickname
    if ($dll(%Fish11DllFile, FiSH11_SetKey, $+($network," ",$newnick," ",%old_nick_key))) {
      echo $color(Mode text) -at *** FiSH_11: Key for $nick has been moved to new nick $newnick.
      ; Remove the key from the old nickname to prevent reuse by another user
      noop $dll(%Fish11DllFile, FiSH11_FileDelKey, $+($network," ",$nick))
    }
    unset %new_nick_key
  }
  unset %old_nick_key
}



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
    ; DEBUG : log the key for debugging purposes
    echo $color(Mode text) -at *** FiSH_11: Key for $chan is %theKey
  }
}



; === SIGNAL HANDLERS ===
alias fish11_incoming_text {
  ; $1 = nick, $2 = target, $3- = message
  
  ; Check if we should process this message
  var %process_incoming = $dll(%Fish11DllFile, INI_GetBool, process_incoming 1)
  if (%process_incoming == 0) { return }
  
  ; Check if the message appears to be encrypted
  if ($regex($3-, /^\+FiSH /)) {
    ; Try to decrypt using target for private messages, or nick for channel messages
    var %key_target = $iif($2 ischan, $1, $2)
    var %decrypted = $dll(%Fish11DllFile, FiSH11_DecryptMsg, %key_target $3-)
    
    ; If decryption successful (doesn't start with "Error")
    if ($left(%decrypted, 5) != Error) {
      ; Get encryption mark info if configured
      var %mark_pos = $dll(%Fish11DllFile, INI_GetInt, mark_position 1)
      var %mark_txt = $dll(%Fish11DllFile, INI_GetString, mark_encrypted 12$chr(183))
      
      ; Show decrypted message with optional mark
      var %display = $iif(%mark_pos == 1, %mark_txt $+ %decrypted, %decrypted $+ %mark_txt)
      var %safe_display = $strip(%display, b,c,i,k,o,r,u)
      echo $color(encrypted text) -t $iif($2 ischan, $2, $1) <$1> %safe_display
      halt
    }
  }
  
  ; Check for key exchange message (DH public key)
  if ($regex($3-, /FiSH11-PubKey:[A-Za-z0-9+\/=]+/)) {
    echo -t $iif($2 ischan, $2, $1) *** Received key exchange request from $1
    echo -t $iif($2 ischan, $2, $1) *** Type /fish_keyp11 $1 $3- to complete key exchange
    
    ; Auto-process if configured
    if (%autokeyx == [On]) {
      fish11_ProcessPublicKey $1 $3-
    }
    
    halt
  }
}



alias fish11_incoming_action {
  ; Similar to text processing for actions
  var %process_incoming = $dll(%Fish11DllFile, INI_GetBool, process_incoming 1)
  if (%process_incoming == 0) { return }
  
  if ($regex($3-, /^\+FiSH /)) {
    var %key_target = $iif($2 ischan, $1, $2)
    var %decrypted = $dll(%Fish11DllFile, FiSH11_DecryptMsg, %key_target $3-)
    
    if ($left(%decrypted, 5) != Error) {
      var %mark_pos = $dll(%Fish11DllFile, INI_GetInt, mark_position 1)
      var %mark_txt = $dll(%Fish11DllFile, INI_GetString, mark_encrypted 12$chr(183))
      
      var %display = $iif(%mark_pos == 1, %mark_txt $+ %decrypted, %decrypted $+ %mark_txt)
      var %safe_display = $strip(%display, b,c,i,k,o,r,u)
      echo $color(action text) -t $iif($2 ischan, $2, $1) * $1 %safe_display
      halt
    }
  }
}



alias fish11_incoming_notice {
  ; Similar to text processing for notices
  var %process_incoming = $dll(%Fish11DllFile, INI_GetBool, process_incoming 1)
  if (%process_incoming == 0) { return }
  
  if ($regex($3-, /^\+FiSH /)) {
    var %key_target = $iif($2 ischan, $1, $2)
    var %decrypted = $dll(%Fish11DllFile, FiSH11_DecryptMsg, %key_target $3-)
    
    if ($left(%decrypted, 5) != Error) {
      var %mark_pos = $dll(%Fish11DllFile, INI_GetInt, mark_position 1)
      var %mark_txt = $dll(%Fish11DllFile, INI_GetString, mark_encrypted 12$chr(183))
      
      var %display = $iif(%mark_pos == 1, %mark_txt $+ %decrypted, %decrypted $+ %mark_txt)
      var %safe_display = $strip(%display, b,c,i,k,o,r,u)
      echo $color(notice text) -t $iif($2 ischan, $2, $1) -$1- %safe_display
      halt
    }
  }
}



; === KEY MANAGEMENT FUNCTIONS ===
; Set key with different encoding options
alias fish11_setkey {
  if ($1 == $null || $2 == $null) {
    echo 4 -a Syntax: /fish11_setkey <nickname> <key>
    return
  }
  ; $1 = nickname (data), $2- = key (parms)
  noop $dll(%Fish11DllFile, FiSH11_SetKey, $1, $2-)
  if ($result == 3) echo -a Key set for $1
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



; Initialize key exchange
alias fish11_X25519_INIT {
  if (($1 == /query) || ($1 == $null)) var %cur_contact = $active
  else var %cur_contact = $1
  
  ; If there's an existing exchange in progress, cancel it first
  if (%fish11.dh_ $+ [ %cur_contact ] == 1) {
    .timer fish_timeout_ $+ %cur_contact off
    echo $color(Mode text) -at *** FiSH_11: Restarting key exchange with %cur_contact
  }
  
  set %fish11.dh_ $+ [ %cur_contact ] 1
  
  ; Execute the key exchange function and store result
  .dll %Fish11DllFile FiSH11_ExchangeKey %cur_contact
  
  ; The function sends the public key to the mIRC window directly
  ; Set the timeout timer using the constant KEY_EXCHANGE_TIMEOUT_SECONDS from the DLL (10 seconds)
  .timer fish_timeout_ $+ %cur_contact 1 10 fish11_timeout_keyexchange %cur_contact
}



; Process received public key
alias fish11_ProcessPublicKey {
  if ($1 == $null || $2 == $null) {
    echo 4 -a Syntax: /fish11_ProcessPublicKey <nickname> <public_key>
    return
  }
  
  ; Process the public key
  if ($dll(%Fish11DllFile, FiSH11_ProcessPublicKey, $1 $2-)) {
    echo $color(Mode text) -at *** FiSH_11: key exchange completed with $1
    echo $color(Error) -at *** FiSH_11: WARNING: Key exchange complete, but the identity of $1 is NOT VERIFIED.
    echo $color(Error) -at *** FiSH_11: Use /fish_fp11 $1 to see their key fingerprint and verify it with them through a secure channel (e.g., voice call).
  }
  else {
    echo $color(Mode text) -at *** FiSH_11: key exchange failed with $1
  }
}



; Shorthand for key exchange
alias keyx { fish11_X25519_INIT $1 }



; Use key from another channel/user
alias fish11_usechankey {
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



; Show key in a window
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



; Remove key
alias fish11_removekey {
  if ($1 == /query) var %cur_contact = $active
  else var %cur_contact = $1
  
  if ($dll(%Fish11DllFile, FiSH11_FileDelKey, $+($network," ",%cur_contact))) {
    echo $color(Mode text) -at *** FiSH_11: key for %cur_contact has been removed
  }
  else {
    echo $color(Mode text) -at *** FiSH_11: could not remove key for %cur_contact
  }
}



; Test encryption
alias fish11_test_crypt {
  if ($1 == $null) var %msg = Test message for encryption
  else var %msg = $1-
  
  ; Let the DLL handle the output directly
  .dll %Fish11DllFile FiSH11_TestCrypt %msg
}



; Encrypt message
alias fish11_encrypt {
  if (!$1 || !$2) return
  var %encrypted = $dll(%Fish11DllFile, FiSH11_EncryptMsg, $1, $2-)
  return %encrypted
}



; Decrypt message
alias fish11_decrypt {
  if ($1 == /query) var %cur_contact = $active
  else var %cur_contact = $1
  if ($2- == $null) return
  
  var %decrypted
  if ($dll(%Fish11DllFile, FiSH11_DecryptMsg, %cur_contact, $2-, &%decrypted)) {
    return %decrypted
  }
  else {
    echo $color(Mode text) -at *** FiSH: Decryption failed for %cur_contact
    return $null
  }
}



; List all keys
alias fish11_file_list_keys {
  var %keys

  ; Check the DLL exists before trying to call it
  if (!$isfile(%Fish11DllFile)) {
    echo $color(Mode text) -at *** FiSH: Error - DLL not found: %Fish11DllFile
    return
  }
    ; Log that we're about to call the function
  echo $color(Mode text) -at *** FiSH: Listing keys...
    ; Ensure MIRCDIR is set (should already be set at startup, but be safe)
  noop $dll(%Fish11DllFile, FiSH11_SetMircDir, $mircdir)
  
  ; Initialize the buffer variable
  var %keys
  
  ; Call DLL function using proper syntax for data return
  ; The .dll command executes the function and puts output in the specified buffer
  echo $color(Mode text) -at *** FiSH: about to call FiSH11_FileListKeys...
  .dll %Fish11DllFile FiSH11_FileListKeys %keys
  echo $color(Mode text) -at *** FiSH: DLL call completed, result: %keys
  
  ; If the function returns data, display it line by line
  if (%keys != $null) {
    fish11_display_multiline_result %keys
  }
  else {
    echo $color(Mode text) -at *** FiSH: no keys found or error occurred
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
  while (%i <= $numtok(%text, 1)) {
    var %line = $gettok(%text, %i, 1)
    
    ; Safety check: limit number of lines to prevent crashes
    inc %line_count
    if (%line_count > %max_lines) {
      echo $color(Mode text) -at *** FiSH: output truncated (exceeded %max_lines lines)
      break
    }
    
    ; Display the line with proper formatting
    if ($len(%line) > 0) {
      echo $color(Mode text) -at %line
    }
    
    inc %i
  }
}

; Status indicator update
alias fish11_UpdateStatusIndicator {
  var %active = $active
  
  ; Don't update for non-chat windows
  if (!$window(%active).type) || ($window(%active).type !isin query channel) return
  
  ; Check if we have a key for this target
  var %key = $dll(%Fish11DllFile, FiSH11_FileGetKey, %active)
  
  ; Update status text accordingly
  if ($len(%key) > 1) {
    var %fingerprint = $dll(%Fish11DllFile, FiSH11_GetKeyFingerprint, %active)
    
    ; Extract just the fingerprint part from the response
    ; The response is in format: "Key fingerprint for nickname: XXXX YYYY ZZZZ AAAA"
    var %fp_only = $gettok(%fingerprint, 2-, 58)
    var %fp_only = $strip(%fp_only)
    
    ; Format the fingerprint with alternating colors
    ; Format each group with a different color
    var %group1 = $gettok(%fp_only, 1, 32)
    var %group2 = $gettok(%fp_only, 2, 32) 
    var %group3 = $gettok(%fp_only, 3, 32)
    var %group4 = $gettok(%fp_only, 4, 32)
    
    ; Create colored version using mIRC color codes
    ; 04=red, 12=blue, 03=green, 07=orange
    var %colored_fp = 04 $+ %group1 $+  12 $+ %group2 $+  03 $+ %group3 $+  07 $+ %group4
    
    if (!$window(@FiSH_Status)) { window -hn @FiSH_Status }
    aline -p @FiSH_Status * $timestamp $+ %active is encrypted (Key: %colored_fp $+ )
    
    ; Show encryption in status bar with colored fingerprint
    sbar 4 FiSH: 🔒 %active [Fingerprint: %colored_fp $+ ]
    
    ; Also create a command that lets users copy/display the fingerprint on demand
    set %fish11.lastfingerprint. $+ [ %active ] %colored_fp
  }
  else {
    if (!$window(@FiSH_Status)) { window -hn @FiSH_Status }
    aline -p @FiSH_Status * $timestamp $+ %active is not encrypted
    sbar 4 FiSH: 🔓 %active [No encryption]
    
    ; Clear any stored fingerprint
    unset %fish11.lastfingerprint. $+ [ %active ]
  }
}



; Display key fingerprint with color for a target
alias fish11_showfingerprint {
  if ($1 == /query) {
    var %target = $active
  }
  else {
    var %target = $1
  }

  ; Check if there's a stored colored fingerprint first
  if (%fish11.lastfingerprint. $+ [ %target ] != $null) {
    echo $color(Mode text) -at *** FiSH_11: key fingerprint for %target is: %fish11.lastfingerprint. $+ [ %target ]
    return
  }
  
  ; Otherwise generate one
  var %key = $dll(%Fish11DllFile, FiSH11_FileGetKey, %target)
  if ($len(%key) > 1) {
    var %fingerprint = $dll(%Fish11DllFile, FiSH11_GetKeyFingerprint, %target)
    
    ; Extract just the fingerprint part from the response
    var %fp_only = $gettok(%fingerprint, 2-, 58)
    var %fp_only = $strip(%fp_only)
    
    ; Format the fingerprint with alternating colors
    ; Format each group with a different color
    var %group1 = $gettok(%fp_only, 1, 32)
    var %group2 = $gettok(%fp_only, 2, 32) 
    var %group3 = $gettok(%fp_only, 3, 32)
    var %group4 = $gettok(%fp_only, 4, 32)
    
    ; Create colored version using mIRC color codes
    ; 04=red, 12=blue, 03=green, 07=orange
    var %colored_fp = 04 $+ %group1 $+  12 $+ %group2 $+  03 $+ %group3 $+  07 $+ %group4
    
    ; Display the colored fingerprint
    echo $color(Mode text) -at *** FiSH_11: Key fingerprint for %target is: %colored_fp
    
    ; Store for later
    set %fish11.lastfingerprint. $+ [ %target ] %colored_fp
  }
  else {
    echo $color(Mode text) -at *** FiSH_11: No key found for %target
  }
}



; INI Config Helpers - renamed to reflect INI format
alias fish11_GetIniValue {
  return $dll(%Fish11DllFile, INI_GetString, $1 $2-)
}



alias fish11_SetIniValue {
  noop $dll(%Fish11DllFile, INI_SetString, $1 $2-)
}



alias fish11_GetChannelIniValue {
  return $dll(%Fish11DllFile, INI_GetString, channel_ $+ $1 $+ _ $+ $2 $3-)
}



alias fish11_SetChannelIniValue {
  noop $dll(%Fish11DllFile, INI_SetString, channel_ $+ $1 $+ _ $+ $2 $3-)
}



; Set plain message prefix
alias fish11_prefix {
  if ($1 != $null) {
    ; Add quotes for INI string value
    var %value = " $+ $1- $+ "
    fish11_SetIniValue plain_prefix %value
    echo $color(Mode text) -at *** FiSH: Plain-prefix set to $1-
  }
}



; Backup functionality
alias fish11_ScheduleBackup {
  var %backup_dir = $+(fish_11\backups\)
  
  ; Create directory if it doesn't exist
  if (!$isdir(%backup_dir)) {
    mkdir $+(",$mircdir,%backup_dir,")
  }
  
  ; Create timestamped filename
  var %filename = $+(%backup_dir,fish_keys_,$asctime(yyyy-mm-dd_HH-nn),\.bak)
  
  ; Perform backup
  if ($dll(%Fish11DllFile, FiSH11_BackupKeys, %filename)) {
    echo $color(Mode text) -at *** FiSH: scheduled backup created: %filename
  }
  else {
    echo $color(Error) -at *** FiSH: scheduled backup failed
  }
}

; Show help and version information
alias fish11_help {
  var %helpText
  if ($dll(%Fish11DllFile, FiSH11_Help, &%helpText)) {
    echo $color(Mode text) -at *** FiSH help: %helpText
  }
  else {
    echo $color(Mode text) -at *** FiSH: help information unavailable
  }
}


alias fish11_version {
  var %version
  if ($dll(%Fish11DllFile, FiSH11_GetVersion, &%version)) {
    ;echo -a *** FiSH_11 Version: %version
  }
}



alias fish11_injection_version {
  var %injectionVersion
  if ($dll(%Fish11InjectDllFile, FiSH11_InjectVersion, &%injectionVersion)) {
    ;echo -a *** FiSH_11 Version: %injectionVersion
  }
}



; Debug functionality
alias fish11_debug {
  var %w = @fishdebug
  var %a = aline -ph %w

  var %f1 = fishdebug
  var %f2 = $rand(0,9999)
  ;var %x = $iif($isfile(%Fish11DllFile),$dll(%Fish11DllFile,FiSH11_SetKey,$+($network,%f1,%f2,HelloWorld)),MISSING_DLL)
  var %x = $iif($isfile(%Fish11DllFile),$dll(%Fish11DllFile,FiSH11_SetKey,$+($network,%f1,%f2,HelloWorld)),MISSING_DLL)

  var %f11dll = $+(",$nofile($mircexe),fish_11.dll")
  var %f11config = %fish_config_file

  if (!$window(%w)) {
    window -a %w -1 -1 550 300 Courier New 12
  } 
  else {
    clear %w
    window -a %w
  }

  %a ---------FISH DEBUG---------
  %a $cr
  %a ::VERSION
  %a mIRC version: $version
  %a SSL version: $sslversion
  %a SSL ready: $sslready
  %a SSL mode: $iif($readini($mircini,ssl,load),$v1,default)
  %a $cr
  %a ::mIRC
  %a mIRC dir: $mircdir
  %a mIRC.exe: $mircexe
  %a mIRC.ini: $mircini
  %a Portable: $iif($readini($mircini,about,portable),$v1,NotFound)
  %a $cr
  %a ::Files
  %a fish_11.dll: %Fish11DllFile - $isfile(%Fish11DllFile)
  %a version string: $iif($isfile(%Fish11DllFile),$dll(%Fish11DllFile,FiSH11_GetVersion),NotFound)
  %a fish_11.toml: %fish_config_file - $isfile(%fish_config_file)
  %a $cr
  %a ::INI Configuration
  %a Process incoming: $fish11_GetIniValue(process_incoming)
  %a Process outgoing: $fish11_GetIniValue(process_outgoing)
  %a Plain prefix: $fish11_GetIniValue(plain_prefix)
  %a Mark position: $fish11_GetIniValue(mark_position)
  %a Encrypt notice: $fish11_GetIniValue(encrypt_notice)
  %a Encrypt action: $fish11_GetIniValue(encrypt_action)
  %a No fish10 legacy: $fish11_GetIniValue(no_fish10_legacy)
  %a $cr
  %a ::Variables
  %a fish_config_file: %fish_config_file
  %a FiSH_dll: %Fish11DllFile
  %a $cr
  %a ::Testing
  %a >> Writing key to config
  %a << Reading back key, you should see a 'HelloWorld' on the next line.
  %a !! FileGetKey: $iif($dll(%Fish11DllFile,FiSH11_FileGetKey, $+($network," ",%f1," ",%f2)),$v1,NotFound)
  %a << Deleting key from config

  var %delkey = $dll(%Fish11DllFile,FiSH11_FileDelKey,$+($network," ",%f1," ",%f2))
}



; INI file viewer
alias fish11_ViewIniFile {
  var %w = @iniviewer
  
  if (!$isfile(%fish_config_file)) {
    echo $color(Mode text) -at *** FiSH: Config file not found: %fish_config_file
    return
  }
  
  if (!$window(%w)) {
    window -a %w -1 -1 550 500 Courier New 10
  } 
  else {
    clear %w
    window -a %w
  }
  
  titlebar %w FiSH 11 Configuration - %fish_config_file
  
  var %i = 1
  while (%i <= $lines(%fish_config_file)) {
    aline %w $read(%fish_config_file, %i)
    inc %i
  }
}



; Helper functions
alias -l fishdebug.clip {
  clipboard
  var %i = 1
  while ($line(@fishdebug,%i)) { 
    clipboard -an $v1
    inc %i 
  }
}



alias statusmsg {
  echo 4 -s [FiSH_11] $1-
}



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



; INI Helper Functions (for compatibility with older scripts)
alias INI_GetString {
  ; Arguments: $1 = key, $2 = default value
  var %config_path = $+($scriptdir,fish_11.ini)
  var %value = $readini(%config_path, FiSH11, $1)
  if (%value == $null) { return $2 }
  return %value
}



alias INI_GetInt {
  ; Arguments: $1 = key, $2 = default value
  var %config_path = $+($scriptdir,fish_11.ini)
  var %value = $readini(%config_path, FiSH11, $1)
  if (%value == $null) { return $2 }
  return %value
}



; === MENUS ===

; Menu for channel windows
menu channel {
  -
  FiSH global
  .Show key :fish11_showkey $chan
  .Show fingerprint :fish11_showfingerprint $chan
  .Copy fingerprint to clipboard :{
    fish11_showfingerprint $chan
    var %fp = %fish11.lastfingerprint. $+ [ $chan ]
    if (%fp != $null) {
      clipboard %fp
      echo $color(Mode text) -at *** FiSH_11: fingerprint for $chan copied to clipboard
    }
  }
  .Set new key :{ var %key = $?="Enter new key for " $+ $chan $+ ":" | if (%key != $null) fish11_setkey $chan %key }
  .Set new key (UTF-8) :{ var %key = $?="Enter new key for " $+ $chan $+ " (UTF-8):" | if (%key != $null) fish11_setkey_utf8 $chan %key }
  .Remove key :fish11_removekey $chan
  .Encrypt message :{
    var %msg = $?="Enter message to encrypt:"
    if (%msg) {
      var %encrypted = $fish11_encrypt($chan,%msg)
      echo $color(Mode text) -at *** FiSH: encrypted message: %encrypted
    }
  }
  .Decrypt message :{
    var %msg = $?="Enter message to decrypt:"
    if (%msg) {
      var %decrypted = $fish11_decrypt($chan,%msg)
      echo $color(Mode text) -at *** FiSH: decrypted message: %decrypted
    }
  }
  .Misc config
  ..Encrypt TOPIC $iif($fish11_GetChannelIniValue($chan, encrypt_topic) == 1, [On], [Off])
  ...Enable :{ fish11_SetChannelIniValue $chan encrypt_topic 1 | echo $color(Mode text) -at *** FiSH: topic encryption enabled for $chan }
  ...Disable :{ fish11_SetChannelIniValue $chan encrypt_topic 0 | echo $color(Mode text) -at *** FiSH: topic encryption disabled for $chan }
}

; Menu for query windows
menu query {
  -
  FiSH
  .X25519 keyXchange: fish11_X25519_INIT $1
  .-
  .Show key :fish11_showkey $1
  .Show fingerprint :fish11_showfingerprint $1
  .Copy fingerprint to clipboard :{
    fish11_showfingerprint $1
    var %fp = %fish11.lastfingerprint. $+ [ $1 ]
    if (%fp != $null) {
      clipboard %fp
      echo $color(Mode text) -at *** FiSH_11: fingerprint for $1 copied to clipboard
    }
  }
  .Set new key :{ var %key = $?="Enter new key for " $+ $1 $+ ":" | if (%key != $null) fish11_setkey $1 %key }
  .Set new key (UTF-8) :{ var %key = $?="Enter new key for " $+ $1 $+ " (UTF-8):" | if (%key != $null) fish11_setkey_utf8 $1 %key }
  .Remove key :fish11_removekey $1
  .Encrypt message :{
    var %msg = $?="Enter message to encrypt:"
    if (%msg) {
      var %encrypted = $fish11_encrypt($1,%msg)
      echo $color(Mode text) -at *** FiSH: encrypted message: %encrypted
    }
  }
  .Decrypt message :{
    var %msg = $?="Enter message to decrypt:"
    if (%msg) {
      var %decrypted = $fish11_decrypt($1,%msg)
      echo $color(Mode text) -at *** FiSH: decrypted message: %decrypted
    }
  }
}

; Menu for nicklist
menu nicklist {
  -
  FiSH
  .X25519 keyXchange: fish11_X25519_INIT $1
  .-
  .Show key :fish11_showkey $1
  .Show fingerprint :fish11_showfingerprint $1
  .Set new key :{ var %key = $?="Enter new key for " $+ $1 $+ ":" | if (%key != $null) fish11_setkey $1 %key }
  .Set new key (UTF-8) :{ var %key = $?="Enter new key for " $+ $1 $+ " (UTF-8):" | if (%key != $null) fish11_setkey_utf8 $1 %key }
  .Remove key :fish11_removekey $1
  .Use same key as $chan :fish11_usechankey $1 $chan
  .Encrypt message :{
    var %msg = $?="Enter message to encrypt:"
    if (%msg) {
      var %encrypted = $fish11_encrypt($1,%msg)
      echo $color(Mode text) -at *** FiSH: encrypted message: %encrypted
    }
  }
  .Decrypt message :{
    var %msg = $?="Enter message to decrypt:"
    if (%msg) {
      var %decrypted = $fish11_decrypt($1,%msg)
      echo $color(Mode text) -at *** FiSH: decrypted message: %decrypted
    }
  }
}

; Common menu available in all windows
menu status,channel,nicklist,query {
  FISH_11
  .Core version :fish11_version
  .Injection version : fish11_injection_version
  .Help :fish11_help
  .-
  .List all keys :fish11_file_list_keys
  .Test encryption :fish11_test_crypt
  .-
  .Set plain-prefix :{ var %prefix = $?="Enter new plain-prefix:" | if (%prefix != $null) fish11_prefix %prefix }
  .Auto-KeyXchange $+ $chr(32) $+ %autokeyx
  ..Enable :set %autokeyx [On]
  ..Disable :set %autokeyx [Off]
  .Misc config
  ..Encrypt outgoing $iif($fish11_GetIniValue(process_outgoing) == 1, [On], [Off])
  ...Enable :{ fish11_SetIniValue process_outgoing 1 | echo $color(Mode text) -at *** FiSH: outgoing message encryption enabled }
  ...Disable :{ fish11_SetIniValue process_outgoing 0 | echo $color(Mode text) -at *** FiSH: outgoing message encryption disabled }
  ..Decrypt incoming $iif($fish11_GetIniValue(process_incoming) == 1, [On], [Off])
  ...Enable :{ fish11_SetIniValue process_incoming 1 | echo $color(Mode text) -at *** FiSH: incoming message decryption enabled }
  ...Disable :{ fish11_SetIniValue process_incoming 0 | echo $color(Mode text) -at *** FiSH: incoming message decryption disabled }
  ..-
  ..Crypt-Mark (Incoming)
  ...Prefix :{ fish11_SetIniValue mark_position 2 | echo $color(Mode text) -at *** FiSH: encryption mark set to prefix }
  ...Suffix :{ fish11_SetIniValue mark_position 1 | echo $color(Mode text) -at *** FiSH: encryption mark set to suffix }
  ...Disable :{ fish11_SetIniValue mark_position 0 | echo $color(Mode text) -at *** FiSH: encryption mark disabled }
  ..Crypt-Mark (Outgoing) $+ $chr(32) $+ %mark_outgoing
  ...Enable :set %mark_outgoing [On]
  ...Disable :set %mark_outgoing [Off]
  ...-
  ...Style 1 :{
    set %mark_style 1
    set %mark_outgoing [On]
    echo $color(Mode text) -at *** FiSH: outgoing mark style set to 1 (suffix)
  }
  ...Style 2 :{
    set %mark_style 2
    set %mark_outgoing [On]
    echo $color(Mode text) -at *** FiSH: outgoing mark style set to 2 (prefix)
  }
  ...Style 3 :{
    set %mark_style 3
    set %mark_outgoing [On]
    echo $color(Mode text) -at *** FiSH: outgoing mark style set to 3 (colored brackets)
  }
  ..NickTracker $+ $chr(32) $+ %NickTrack
  ...Enable :{ set %NickTrack [On] | echo $color(Mode text) -at *** FiSH: nick tracking enabled }
  ...Disable :{ set %NickTrack [Off] | echo $color(Mode text) -at *** FiSH: nick tracking disabled }
  ..Encrypt NOTICE $iif($fish11_GetIniValue(encrypt_notice) == 1, [On], [Off])
  ...Enable :{ fish11_SetIniValue encrypt_notice 1 | echo $color(Mode text) -at *** FiSH: NOTICE encryption enabled }
  ...Disable :{ fish11_SetIniValue encrypt_notice 0 | echo $color(Mode text) -at *** FiSH: NOTICE encryption disabled }
  ..Encrypt ACTION $iif($fish11_GetIniValue(encrypt_action) == 1, [On], [Off])
  ...Enable :{ fish11_SetIniValue encrypt_action 1 | echo $color(Mode text) -at *** FiSH: ACTION encryption enabled }
  ...Disable :{ fish11_SetIniValue encrypt_action 0 | echo $color(Mode text) -at *** FiSH: ACTION encryption disabled }
  ..No legacy FiSH 10 $iif($fish11_GetIniValue(no_fish10_legacy) == 1, [On], [Off])
  ...Enable :{ fish11_SetIniValue no_fish10_legacy 1 | echo $color(Mode text) -at *** FiSH: legacy FiSH 10 compatibility disabled }
  ...Disable :{ fish11_SetIniValue no_fish10_legacy 0 | echo $color(Mode text) -at *** FiSH: legacy FiSH 10 compatibility enabled }
  ..-
  ..Open config file :fish11_ViewIniFile
  ..-
  ..FiSH 11 - secure IRC encryption :shell -o https://github.com/ggielly/fish_11
  .Backup and Restore
  ..Create backup now :fish11_ScheduleBackup
  ..Restore from backup :{
    var %file = $sfile($+(",$mircdir,fish_11\backups\"),Restore FiSH keys from:,*.bak)
    if (%file) {
      if ($dll(%Fish11DllFile, FiSH11_RestoreKeys, %file)) {
        echo $color(Mode text) -at *** FiSH: keys successfully restored from %file
      }
      else {
        echo $color(Error) -at *** FiSH: failed to restore keys from %file
      }
    }
  }
  ..Schedule daily backup :{
    .timer.fish11.DailyBackup 0 86400 fish11_ScheduleBackup
    echo $color(Mode text) -at *** FiSH: daily key backup scheduled
  }
  ..Stop scheduled backups :{
    .timers.fish11.DailyBackup off
    echo $color(Mode text) -at *** FiSH: scheduled key backups stopped
  }
  .Debug
  ..Show debug info :fish11_debug
  ..View INI file :fish11_ViewIniFile
}



; Window context menus
menu @fishdebug {
  &Copy to Clipboard: fishdebug.clip
  -
  &Refresh:{ clear @fishdebug | fish11_debug }
  C&lose:{ window -c @fishdebug }
}



menu @iniviewer {
  &Save Changes:{ 
    var %temp_file = $+($mircdir, fish_11.tmp)
    var %backup_file = %fish_config_file $+ .bak
    
    ; Write the content of the window to a temporary file
    .remove %temp_file
    var %i = 1
    while (%i <= $line(@iniviewer, 0)) {
      write %temp_file $line(@iniviewer, %i)
      inc %i
    }

    if (!$isfile(%temp_file)) {
      echo $color(Error) -at *** FiSH: Error writing temporary file. Save aborted.
      return
    }
    
    ; Safely replace the old config file with the new one
    .rename %fish_config_file %backup_file
    .rename %temp_file %fish_config_file
    
    if ($isfile(%fish_config_file)) {
      echo $color(Mode text) -at *** FiSH: configuration saved
      .remove %backup_file
    } else {
      echo $color(Error) -at *** FiSH: Error saving config, restoring from backup.
      .rename %backup_file %fish_config_file
    }
  }
  &Refresh:{ 
    clear @iniviewer
    var %i = 1
    while (%i <= $lines(%fish_config_file)) {
      aline @iniviewer $read(%fish_config_file, %i)
      inc %i
    }
  }
  -
  C&lose:{ window -c @iniviewer }
}



; === ALIAS SHORTCUTS FOR USER COMMANDS ===
; These provide simplified commands for users

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