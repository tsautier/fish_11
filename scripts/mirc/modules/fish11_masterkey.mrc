;*******************************
;* FiSH_11 Master Key           *
;*******************************
; Master key management for encrypting configuration
; Written by GuY, 2025. Licensed under GPL-v3.

; === MASTER KEY MANAGEMENT ===

; Check if master key is unlocked, prompt if not
alias fish11_check_masterkey {
  var %is_unlocked = $dll(%Fish11DllFile, FiSH11_MasterKeyIsUnlocked, $null)
  
  if (%is_unlocked != yes) {
    ; Prompt user for master key password
    echo $color(Mode text) -at *** FiSH_11: master key is locked. Configuration and logs are NOT encrypted.
    echo $color(Mode text) -at *** FiSH_11: use /fish11_unlock to unlock the master key.
  }
  else {
    echo $color(Mode text) -at *** FiSH_11: master key is unlocked. Configuration and logs ARE encrypted.
  }
}

; Unlock master key with password
; Usage: /fish11_unlock [password]
; If no password provided, prompts with $input dialog
alias fish11_unlock {
  var %password = $1-
  
  ; If no password provided, prompt with dialog
  if (%password == $null) {
    %password = $input(Enter master key password:, pvq, FiSH_11 Master Key, )
  }
  
  ; If user cancelled or empty password
  if (%password == $null) {
    echo $color(Error) -at *** FiSH_11: master key unlock cancelled.
    return
  }
  
  ; Call DLL to unlock
  var %result = $dll(%Fish11DllFile, FiSH11_MasterKeyUnlock, %password)
  
  ; Clear password from memory
  unset %password
  
  ; Display result
  if (%result) {
    echo $color(Mode text) -at *** FiSH_11: %result
  }
  else {
    echo $color(Error) -at *** FiSH_11: failed to unlock master key
  }
}

; Lock master key (clear from memory)
; Usage: /fish11_lock
alias fish11_lock {
  var %result = $dll(%Fish11DllFile, FiSH11_MasterKeyLock, $null)
  
  if (%result) {
    echo $color(Mode text) -at *** FiSH_11: %result
  }
  else {
    echo $color(Error) -at *** FiSH_11: Failed to lock master key
  }
}

; Show master key status
; Usage: /fish11_masterkey_status
alias fish11_masterkey_status {
  var %result = $dll(%Fish11DllFile, FiSH11_MasterKeyStatus, $null)
  
  if (%result) {
    echo $color(Mode text) -at *** FiSH_11: %result
  }
  else {
    echo $color(Error) -at *** FiSH_11: Failed to get master key status
  }
}

; Require master key password (loop until unlocked)
; Similar to mircryption's mc_requirepassphrase
alias fish11_require_masterkey {
  var %is_unlocked = $dll(%Fish11DllFile, FiSH11_MasterKeyIsUnlocked, $null)
  
  while (%is_unlocked != yes) {
    var %password = $input(Master key is locked. Enter password to unlock :, pvq, FiSH_11 Master Key Required, )
    
    ; If user cancelled
    if (%password == $null) {
      echo $color(Error) -at *** FiSH_11: master key unlock is required. Cancelling operation.
      return
    }
    
    ; Try to unlock
    var %result = $dll(%Fish11DllFile, FiSH11_MasterKeyUnlock, %password)
    unset %password
    
    ; Check if now unlocked
    %is_unlocked = $dll(%Fish11DllFile, FiSH11_MasterKeyIsUnlocked, $null)
    
    if (%is_unlocked == yes) {
      echo $color(Mode text) -at *** FiSH_11: master key unlocked successfully
    }
    else {
      echo $color(Error) -at *** FiSH_11: incorrect password. Try again.
    }
  }
}

; === END MASTER KEY MANAGEMENT ===
