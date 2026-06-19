;*******************************
;* FiSH_10 Legacy Compatibility *
;*******************************
; DH1080 key exchange and Blowfish encryption for backward compatibility
; Written by GuY, 2025. Licensed under GPL-v3.

; === LEGACY FiSH 10 KEY MANAGEMENT ===

alias fish10_setkey {
  if ($1 == $null || $2 == $null) {
    echo 4 -a Syntax: /fish10_setkey <target> <hex_key>
    return
  }
  var %msg = $dll(%Fish11DllFile, FiSH10_SetKey, $1 $2-)
  if (%msg && $left(%msg, 6) != Error:) {
    echo -a *** FiSH_10: %msg
  }
  else {
    echo -a *** FiSH_10: error setting key - %msg
  }
}

alias fish10_delkey {
  if ($1 == $null) var %target = $active
  else var %target = $1
  var %msg = $dll(%Fish11DllFile, FiSH10_DelKey, %target)
  if (%msg && $left(%msg, 6) != Error:) {
    echo -a *** FiSH_10: %msg
  }
  else {
    echo -a *** FiSH_10: error removing key - %msg
  }
}

alias fish10_showkey {
  if ($1 == $null) var %target = $active
  else var %target = $1
  var %key = $dll(%Fish11DllFile, FiSH10_GetKey, %target)
  if ($left(%key, 6) == Error:) {
    echo -a *** FiSH_10: error retrieving key for %target : %key
  }
  elseif (%key == $null) {
    echo -a *** FiSH_10: no key found for %target
  } else {
    echo -a *** FiSH_10: key for %target : %key
  }
}

alias fish10_usechankey {
  if ($1 == $null || $2 == $null) {
    echo 4 -a Syntax: /fish10_usechankey <target> <source_channel>
    return
  }
  
  var %target = $1
  var %source = $2
  
  ; Get the key from the source
  var %key = $dll(%Fish11DllFile, FiSH11_FileGetKey, %source)
  
  if (%key == $null || $len(%key) < 4) {
    echo $color(Error) -at *** FiSH_10: no valid key found for %source
    return
  }
  
  ; Set the same key for the target
  fish10_setkey %target %key
  echo $color(Mode text) -at *** FiSH_10: using same key as %source for %target
}


; === LEGACY DH1080 KEY EXCHANGE ===

alias fish10_keyx {
  if ($1 == $null) var %target = $active
  else var %target = $1
  
  ; Use hash table to track in-progress exchanges
  hadd -m fish10.dh %target 1
  
  var %pub = $dll(%Fish11DllFile, FiSH10_DH1080_GenerateKeyPair, %target)
  
  ; Check if key generation was successful (should be a base64 string ending with 'A')
  ; DH1080 public keys are ~181 chars long and end with 'A'
  if ($len(%pub) > 100 && $right(%pub, 1) == A) {
    .notice %target DH1080_INIT %pub
    echo $color(Mode text) -tm %target *** FiSH_10: sent DH1080_INIT to %target $+ , waiting for reply...
    
    ; Set timeout timer
    if (%KEY_EXCHANGE_TIMEOUT_SECONDS == $null) { var %timeout = 10 }
    else { var %timeout = %KEY_EXCHANGE_TIMEOUT_SECONDS }
    .timer.fish10_dh1080_ $+ %target 1 %timeout fish10_timeout_keyexchange %target
  }
  else {
    hdel fish10.dh %target
    echo $color(Error) -at *** FiSH_10: DH1080 init failed - %pub
  }
}

; Handle key exchange timeout for FiSH 10/DH1080
alias fish10_timeout_keyexchange {
  if ($1 == $null) return
  var %contact = $1
  
  ; Check if key exchange is still in progress
  if ($hget(fish10.dh, %contact) == 1) {
    hdel fish10.dh %contact
    echo $color(Mode text) -at *** FiSH_10: key exchange with %contact timed out
  }
}


; === LEGACY DH1080 NOTICE HANDLERS ===

on ^*:NOTICE:DH1080_INIT*:?:{
  ; In mIRC NOTICE events:
  ; $1 = "DH1080_INIT"
  ; $2 = public key (base64)
  ; $3 = "CBC" (optional)
  var %their_pub = $2

  ; Validate format: DH1080 public keys should be base64
  if (!$regex(%their_pub, /^[A-Za-z0-9+\/=]+$/)) {
    echo $color(Error) -tm $nick *** FiSH_10: received invalid DH1080_INIT format from $nick
    halt
  }

  echo $color(Mode text) -tm $nick *** FiSH_10: received DH1080_INIT from $nick, responding...

  var %our_pub = $dll(%Fish11DllFile, FiSH10_DH1080_GenerateKeyPair, $nick)
  
  ; Check if key generation failed
  if ($left(%our_pub, 6) == Error:) {
    echo $color(Error) -tm $nick *** FiSH_10: key generation failed - %our_pub
    halt
  }

  var %secret = $dll(%Fish11DllFile, FiSH10_DH1080_ComputeSecret, $nick %their_pub)

  ; Check if secret computation failed
  if ($left(%secret, 6) == Error:) {
    echo $color(Error) -tm $nick *** FiSH_10: key exchange failed - %secret
    halt
  }

  ; The DLL automatically stores the shared secret as a Blowfish key for this nick

  ; Send DH1080_FINISH response with our public key
  .notice $nick DH1080_FINISH %our_pub

  echo $color(Mode text) -tm $nick *** FiSH_10: key exchange complete with $nick
  echo $color(Error) -tm $nick *** FiSH_10 WARNING: key exchange complete, but the identity of $nick is NOT VERIFIED.
  halt
}

on ^*:NOTICE:DH1080_FINISH*:?:{
  ; Verify an exchange is in progress
  if ($hget(fish10.dh, $nick) != 1) {
    echo -at *** FiSH_10: received DH1080_FINISH but no key exchange was in progress with $nick
    halt
  }

  ; In mIRC NOTICE events:
  ; $1 = "DH1080_FINISH"
  ; $2 = public key (base64)
  var %their_pub = $2

  ; Validate format
  if (!$regex(%their_pub, /^[A-Za-z0-9+\/=]+$/)) {
    echo $color(Error) -tm $nick *** FiSH_10: received invalid DH1080_FINISH format from $nick
    hdel fish10.dh $nick
    halt
  }
  
  var %secret = $dll(%Fish11DllFile, FiSH10_DH1080_ComputeSecret, $nick %their_pub)
  
  ; Clean up tracking
  hdel fish10.dh $nick
  
  ; Check if secret computation failed
  if ($left(%secret, 6) == Error:) {
    echo $color(Error) -tm $nick *** FiSH_10: key exchange failed - %secret
    halt
  }

  ; The DLL automatically stores the shared secret as a Blowfish key for this nick

  echo $color(Mode text) -tm $nick *** FiSH_10: key exchange complete with $nick
  echo $color(Error) -tm $nick *** FiSH_10 WARNING: key exchange complete, but the identity of $nick is NOT VERIFIED.
  halt
}


; === LEGACY TOPIC MANAGEMENT ===

; Set a plaintext topic for a channel in the legacy fish10 section
alias fish10_settopic {
  if ($1 == $null || $2- == $null) {
    echo 4 -a Syntax: /fish10_settopic <#channel> <topic>
    return
  }

  var %channel = $1
  var %topic = $2-

  ; Validate channel name
  if (!$regex(%channel, /^[#&]/)) {
    echo $color(Error) -at *** FiSH_10 ERROR: Invalid channel name %channel (must start with # or &)
    return
  }

  var %result = $dll(%Fish11DllFile, FiSH10_SetTopic, $+(%channel, $chr(32), %topic))

  if (%result && $left(%result, 6) != Error:) {
    echo $color(Mode text) -at *** FiSH_10: %result
  }
  else {
    var %error_msg = $iif(%result, %result, "Unknown error - could not set topic for %channel")
    echo $color(Error) -at *** FiSH_10: error setting topic for %channel - %error_msg
  }
}

; Get a plaintext topic for a channel from the legacy fish10 section
alias fish10_gettopic {
  if ($1 == $null) {
    echo 4 -a Syntax: /fish10_gettopic <#channel>
    return
  }

  var %channel = $1

  ; Validate channel name
  if (!$regex(%channel, /^[#&]/)) {
    echo $color(Error) -at *** FiSH_10 ERROR: Invalid channel name %channel (must start with # or &)
    return
  }

  var %result = $dll(%Fish11DllFile, FiSH10_GetTopic, %channel)

  if (%result && $left(%result, 6) != Error:) {
    echo $color(Mode text) -at *** FiSH_10: Topic for %channel is: %result
  }
  else {
    var %error_msg = $iif(%result, %result, "Unknown error - could not get topic for %channel")
    echo $color(Error) -at *** FiSH_10: error getting topic for %channel - %error_msg
  }
}

; Remove a plaintext topic for a channel from the legacy fish10 section
alias fish10_removetopic {
  if ($1 == $null) {
    echo 4 -a Syntax: /fish10_removetopic <#channel>
    return
  }

  var %channel = $1

  ; Validate channel name
  if (!$regex(%channel, /^[#&]/)) {
    echo $color(Error) -at *** FiSH_10 ERROR: Invalid channel name %channel (must start with # or &)
    return
  }

  var %result = $dll(%Fish11DllFile, FiSH10_RemoveTopic, %channel)

  if (%result && $left(%result, 6) != Error:) {
    echo $color(Mode text) -at *** FiSH_10: %result
  }
  else {
    var %error_msg = $iif(%result, %result, "Unknown error - could not remove topic for %channel")
    echo $color(Error) -at *** FiSH_10: error removing topic for %channel - %error_msg
  }
}
