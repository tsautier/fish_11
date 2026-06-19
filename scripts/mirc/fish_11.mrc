;***********************
;* FiSH_11 mIRC Script *
;***********************
; "FiSH_11" - Secure IRC encryption script for mIRC
; Written by GuY, 2025. Licensed under GPL-v3.
;
; SECURITY NOTICE: The security of this script depends entirely on the
; binary DLL files (fish_11.dll, fish_11_inject.dll). This mIRC script
; only provides the user interface. Ensure the DLLs are from a trusted
; source, as vulnerabilities in them can compromise your system.
;
; This is the main loader script that loads all FiSH_11 modules.
; Modules are located in the 'modules' subdirectory.

; === LOAD ALL MODULES ===
; Load modules in dependency order
load -rs scripts\mirc\modules\fish11_startup.mrc
load -rs scripts\mirc\modules\fish11_key_management.mrc
load -rs scripts\mirc\modules\fish11_key_exchange.mrc
load -rs scripts\mirc\modules\fish11_encrypt_out.mrc
load -rs scripts\mirc\modules\fish11_encrypt_in.mrc
load -rs scripts\mirc\modules\fish11_channel.mrc
load -rs scripts\mirc\modules\fish11_masterkey.mrc
load -rs scripts\mirc\modules\fish11_legacy.mrc
load -rs scripts\mirc\modules\fish11_menus.mrc
load -rs scripts\mirc\modules\fish11_utils.mrc
