;*******************************
;* FiSH_11 Key Exchange         *
;*******************************
; X25519 key exchange protocol handlers
; Written by GuY, 2025. Licensed under GPL-v3.

; === AUTO KEY EXCHANGE ===
on *:OPEN:?:{
  ; Don't auto-exchange if autokeyx is not enabled
  if (%autokeyx != [On]) return
  
  ; Don't auto-exchange if a legacy DH1080 exchange is in progress
  if ($hget(fish10.dh, $nick)) return
  
  ; Don't auto-exchange if a FiSH 11 exchange is in progress
  if ($hget(fish11.dh, $nick)) return
  
  var %tmp1 = $dll(%Fish11DllFile, FiSH11_FileGetKey, $nick)
  
  ; Check for error messages or empty result
  ; Only initiate exchange if truly no key exists
  if (%tmp1 == $null || $left(%tmp1, 2) == no || $left(%tmp1, 5) == Error) {
    ; No FiSH 11 key found - check for legacy key
    var %has_legacy = $dll(%Fish11DllFile, FiSH10_HasKey, $nick)
    if (%has_legacy != 1) {
      ; No key at all (neither FiSH 11 nor legacy), initiate FiSH 11 exchange
      fish11_X25519_INIT $nick
    }
    unset %has_legacy
  }
  unset %tmp1
}


; === KEY EXCHANGE PROTOCOL HANDLERS ===
on ^*:NOTICE:X25519_INIT*:?:{
  ; This event triggers when someone initiates a key exchange with us.
  ; $1 = X25519_INIT, $2- = public key token from peer
  var %their_pub = $2-

  ; Validate incoming key format using regex for robustness.
  if (!$regex(%their_pub, /^X25519_INIT:[A-Za-z0-9+\/]{43}=$/)) {
    echo $color(Mode text) -tm $nick *** FiSH_11: received invalid INIT key format from $nick
    halt
  }

  query $nick
  echo $color(Mode text) -tm $nick *** FiSH_11: received X25519 public key from $nick, responding...

  ; 1. Generate our own keypair (or get existing one). The DLL returns our public key token.
  var %our_pub = $dll(%Fish11DllFile, FiSH11_ExchangeKey, $nick)

  ; 2. Process their public key. This computes and saves the shared secret.
  var %process_result = $dll(%Fish11DllFile, FiSH11_ProcessPublicKey, $nick %their_pub)

  ; Check if processing was successful (no error message)
  if (%process_result && $left(%process_result, 6) != Error:) {
    ; 3. If successful, send our public key back to them so they can complete the exchange.
    ; Use more flexible regex to validate public key format
    if ($regex(%our_pub, /^X25519_INIT:[A-Za-z0-9+\/=]+$/)) {
      .notice $nick X25519_FINISH %our_pub
      echo $color(Mode text) -tm $nick *** FiSH_11: sent X25519_FINISH to $nick
    }
    else {
      echo $color(Mode text) -tm $nick *** FiSH_11: ERROR - could not generate our own public key to send in reply. DLL returned: $qt(%our_pub)
    }
  }
  else {
    ; Display error message from DLL
    echo $color(Mode text) -tm $nick *** FiSH_11: %process_result
  }

  halt
}

on ^*:NOTICE:X25519_FINISH*:?:{
  ; This event triggers when a peer responds to our key exchange initiation.
  ; $1 = X25519_FINISH, $2- = public key token from peer
  ; Ensure an exchange is in progress with this user by checking the hash table.
  if ($hget(fish11.dh, $nick).item != 1) {
    echo -at *** FiSH_11: received a FINISH notice, but no key exchange was in progress with $nick $+ .
    halt
  }

  var %their_pub = $2-

  ; Use regex to validate the key format from the peer.
  if ($regex(%their_pub, /^X25519_INIT:[A-Za-z0-9+\/]{43}(=|==)?$/)) {
    ; Process the received public key. The DLL computes and stores the shared secret.
    var %process_result = $dll(%Fish11DllFile, FiSH11_ProcessPublicKey, $nick %their_pub)

    ; Check if processing was successful (no error message)
    if (%process_result && $left(%process_result, 6) != Error:) {
      ; Success! Clean up state variables.
      hdel fish11.dh $nick

      echo $color(Mode text) -tm $nick *** FiSH_11: key exchange complete with $nick
      echo $color(Error) -tm $nick *** FiSH_11 WARNING: key exchange complete, but the identity of $nick is NOT VERIFIED.
      echo $color(Error) -tm $nick *** FiSH_11: use /fish_fp11 $nick to see their key fingerprint and verify it with them through a secure channel.
    }
    else {
      ; Display error message from DLL
      echo $color(Mode text) -tm $nick *** FiSH_11: %process_result
    }
  }
  else {
    echo $color(Mode text) -tm $nick *** FiSH_11: received invalid FINISH key format from $nick $+ : $qt(%their_pub)
  }

  halt
}


; === KEY EXCHANGE TIMEOUT ===
; Handle key exchange timeout
alias fish11_timeout_keyexchange {
  if ($1 == $null) {
    echo $color(Mode text) -at *** FiSH_11: timeout handler called with no parameters
    return
  }
  
  var %contact = $1
  
  ; Check if key exchange is still in progress.
  if ($hget(fish11.dh, %contact) == 1) {
    ; Clean up variables.
    hdel fish11.dh %contact
    
    ; Notify user of timeout with instructions.
    echo $color(Mode text) -at *** FiSH_11: key exchange with %contact timed out after $KEY_EXCHANGE_TIMEOUT_SECONDS seconds
    echo $color(Mode text) -at *** FiSH_11: to try again, use: /fish11_X25519_INIT %contact
  }
}
