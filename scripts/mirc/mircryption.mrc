; ---------------------------------------------------------------------------
; MircryptionSuite - Mircryption v1.20.01 - mirc v5.9x+ script for encryption/decryption
; 2/26/11, http://mircryption.sourceforge.net
; ---------------------------------------------------------------------------
;  some dll skeleton code borrowed from tabo (www.aircscript.com).
;  some c++ coding in xchat port by xro.
;  some mirc code adapted from 'Downloader v1.0' by |nsane (www.mircscripts.org).
;  some mirc code adapted from '(advanced logging) v1.0' by ash (ash@scripters-austnet.org).
;  some mirc code adapted from 'Multi-Kreate Directory' by zack^ (www.mircscripts.org).
;  blowfish encryption algorithms are by bruce schneier (jim conger's implementation).
; ---------------------------------------------------------------------------
; See the mircryption help file for complete installation and usage info,
;  as well as a complete release history.
; ---------------------------------------------------------------------------

; ---------------------------------------------------------------------------
; 11/05/05 - adding ` to server separator list
; 11/05/05 - added switch for disabling stripping of server prefix (makes each)
; 11/11/05 - added option %mc_cleansignal (set to yes to strip colors and change asc(160) to asc(32) before mircryptionsignalall trigger
; 12/15/05 - added %mc_blockctcp_ping as per champi suggestion
; 01/27/06 - fixed potential buffer overflow
;  temp fix witout upgrade, to /set %mc_tracknicks no
; 02/15/06 - added variable to disable space-to-160 conversions
; 05/19/06 - fixed minor bug on line 2654 referencing $ename should have been %ename - thanks Cham
; 11/28/06 - now %mc_uniqueserverkeys = yes will ADD network prefixes to ensure uniqueness between servers when using mirc multiserve
;          - added ability to explicitly alias or dealias channel names, just set %mc_cnamealias_#CHANNAME #CHANNAMEALIAS
;          -  to tell mircryption to use the CHANNAMEALIAS when looking up keys
;          -  you can also use %mc_cnamealias_~NETWORK#CHANNAME %CHANNAMEALIAS to specify unique channel name aliases for only certain channels on certain networks
;          - when track nick changes is enabled but encryption key is disabled, nicks are no longer automigrated
;          - nick tracking is now disabled by default
; 6/4/08   - isvo nick coloring was overriding ishop, fixed [thanks m0viefrea]
; 8/28/08  - minor changes to menus
;          - reports install location in about
; 2/26/11  - added variable to control splitting line lengh (defaulk 250)
; ---------------------------------------------------------------------------


; ---------------------------------------------------------------------------
; installer, called once on first installation.
; just checks for the proper version of mirc
on *:LOAD: {
  if ( $version < 5.9 ) {
    echo 4 -s $nopath($script) cannot be installed - requires mIRC version 5.9 or later!
    echo
    mc_uninstall silent
    halt
  }
  if (%mc_silentupdate == $null) {
    echo 7 -si2 MircryptionSuite - Mircryption script is now installed.  Use right-click pop-ups to access Mircryption menu.
    echo 7 -si2 You can uninstall this script from the main menubar: Commands->Mircryption->Uninstall.
  }
  unset %mc_silentupdate
}

; about function tells version
alias mc_about {
  %mc_scriptversion = 1.19.01
  %mc_dllversion = $dll( %mc_scriptdll , version, dummy )
  if ($dialog(mcupdater_down).hwnd != $null) did -a mcupdater_down 7 Mircryption ver %mc_scriptversion (dll v $+ %mc_dllversion , mirc v $+ $version $+ ) CBC loaded and ready. $+ $crlf
  else echo 7 -s MircryptionSuite - Mircryption ver %mc_scriptversion (dll v $+ %mc_dllversion , mirc v $+ $version  $+ ) CBC loaded and ready.
  echo 7 -s Installed at %mc_scriptdll
  ; force rerunning of theme
  .mcscheme
}
; ---------------------------------------------------------------------------


; ---------------------------------------------------------------------------
; initialization startup each time you launch mirc
on *:START: {
  .mc_startup
}

; initialization startup each time you launch mirc
alias mc_startup {
  %mc_scriptdll = " $+ $scriptdir $+ mircryption.dll $+ "
  var %mcdllfile = " $+ $scriptdir $+ mircryption.dll $+ "
  if (!$exists(%mcdllfile)) {
    var %mcfile = " $+ $scriptdir $+ mircryption $+ .mrc $+ "
    echo 4 -------------------------------
    echo 4 *** MIRCRYPTION ERROR: You have loaded the micryption script %mcfile but the accompanying dll file %mcdllfile was not found.  Please copy the dll file into the proper place, or uninstall the mircryption script from the Command Menu, then restart mirc.
    echo 4 -------------------------------
    .timer 1 3 unload -rs $script
    halt
  }
  if ($lock(dll)) {
    echo 4 -------------------------------
    echo 4 *** MIRCRYPTION ERROR: This script uses a dll (mircryption.dll).  You need to unlock DLLs from Options -> General-> Lock, then restart mirc.
    echo 4 -------------------------------
    .timer 1 3 unload -rs $script
    halt
  }

  ; let user know the script is loaded - do NOT skip this call, as it also stores values for %mc_scriptversion and %mc_dllversion
  .mc_about

  ; set variables to defaults if they are not already set
  /setmcvariables
  ; set current color/identification scheme (defaults to [] around encrypted nicks)
  /mcscheme
  ; set timers to make sure encrypted-state of window captions are shown properly
  /setmctimers

  ; load log rules
  mclog -q reload

  ; init the plaintext hash table
  .mc_bindinit

  ; reset any disable flags
  unset %mc_haltinput
  unset %mc_halttext
}


; simple shortcut function that other scripts can use to check if mircryption is running.
; to check you would use this in your script:  if ($gotmircryption) ...
alias gotmircryption { return $true }
alias gotmircryptioncbc { return $true }

; signal used to tell all mircryption modules to show their version information
on *:SIGNAL:MircryptionInternalSignal_About: {
  .mc_about
}


on 1:UNLOAD: {
  ; unload
  .timermcWindowWatcher off
  .timermcWindowWatcher2 off
  .dll -u %mc_scriptdll
}
; ---------------------------------------------------------------------------

















; ---------------------------------------------------------------------------
; help
alias mircryption {
  ; launch the help file if it is in mirc directory
  if ( $exists(mircryption.chm) ) .run mircryption.chm
  ; now show commandline help in status window
  echo 7 -si4 - 
  echo 7 -si4 . MircryptionSuite - Dark Raichu - http://mircryption.sourceforge.net
  echo 7 -si4 . 
  echo 7 -si4 . NOTE: For detailed info see help file (Help->Help Files->MircryptionSuite).
  echo 7 -si4 . 
  echo 7 -si2 . some c++ coding in xchat port by xro.
  echo 7 -si2 . some dll skeleton code borrowed from tabo (www.aircscript.com).
  echo 7 -si2 . some mirc code adapted from 'Downloader v1.0' by |nsane (www.mircscripts.org).
  echo 7 -si2 . some mirc code adapted from 'advanced logging v1.0' by ash (ash@scripters-austnet.org).
  echo 7 -si2 . some mirc code adapted from 'Multi-Kreate Directory' by zack^ from (www.mircscripts.org).
  echo 7 -si2 . blowfish encryption algorithms are by bruce schneier; jim conger's implementation (www.counterpane.com).
  echo 7 -si2 . pgp dlls are by phil zimmerman and network associates et al. (www.pgp.com).
  echo 7 -si4 . 
  echo 7 -si2 . Use right-click popup menus to access all mircryption commands.
  echo 7 -si4 . 
  echo 7 -si4 . NOTE: For detailed info see help file (Help->Help Files->MircryptionSuite).
  echo 7 -si2 . You can uninstall script from the menu: Commands->Mircryption->Uninstall.
  echo 7 -si2 - 
  ; now show versions
  echo 7 -si2 Versions Running:
  if ($version >= 6.0) .signal MircryptionInternalSignal_About
}

alias mchelp {
  echo 7 -si4 . MircryptionSuite - Dark Raichu - http://mircryption.sourceforge.net
  echo 7 -si4 . 
  echo 7 -si4 . NOTE: For detailed info see help file (Help->Help Files->MircryptionSuite).
  echo 7 -si2 . Use right-click popup menus to access all mircryption commands, or from command line:
  echo 7 -si6 .... /setkey [keyphrase]'             enables encryption/decryption on current channel, using key specified.  can be used to add or modify keys.
  echo 7 -si6 .... /delkey [channel]'               removes encryption key for specified channel (defaults to current channel).
  echo 7 -si6 .... /disablekey'                     temporarily disables encryption for current channel
  echo 7 -si6 .... /enablekey'                      re-enables encryption for current channel
  echo 7 -si6 .... /displaykey'                     shows you (and only you) the key for the current channel
  echo 7 -si6 .... /plain ...'                      send ... text without encryption
  echo 7 -si6 .... /listkeys'                       lists all channel encryption keys currently stored
  echo 7 -si6 .... /keypassphrase [keyword]'        set or change current master keyfile passphrase to keyword
  echo 7 -si6 .... /mcscheme X'                     set color/identification scheme, where X is the scheme number
  echo 7 -si6 .... /etopic [#chan] [text]'          set an encrypted topic for the channel.
  echo 7 -si6 .... /encryptecho channelname text'   echoes encrypted version of text IF channel is set to encrypt, otherwise plaintext
  echo 7 -si6 .... /decryptecho text'               echoes decrypted version of text assuming it is encoded to current channel
  echo 7 -si6 .... /setkeyfile filename'            set the name of the file to be used for storing/retrieving keys
  echo 7 -si6 .... /emsg channelname test...        replacement for /msg - encrypts text if appropriate (good for bots, etc.)
  echo 7 -si6 .... /mcmeow [channelname]            broadcast handshake query to channel
  echo 7 -si6 .... /etext text...                   same as typing text... in encrypted channel, BUT igores disabling, and wont send to channel without encryption
  echo 7 -si6 .... /textpad                         launches the textpad dialog for copy and paste of big text
  echo 7 -si6 .... /mcspeech                        toggle ms agent speech
  echo 7 -si4 . 
  echo 7 -si4 . NOTE: For detailed info see help file (Help->Help Files->MircryptionSuite).
  echo 7 -si2 . You can uninstall script from the menu: Commands->Mircryption->Uninstall.
  echo 7 -si2 - 
  ; now show versions
  echo 7 -si2 Versions Running:
  if ($version >= 6.0) .signal MircryptionInternalSignal_About
}



alias mircryptionurl {
  ; open mircryption web page, triggered from menu->about
  if ( (%mc_nhtmln_dllfilename == $null) || (!$exists(%mc_nhtmln_dllfilename)) ) %mc_nhtmln_dllfilename = nHTMLn_2.92.dll

  var %usenhtml = $false
  if ((%usenhtml == $true) && ($exists(%mc_nhtmln_dllfilename))) {
    ; user has nhtmln addon, so we use that to load the page
    window -p @nthmln
    titlebar @nthmln Web Browser
    var %retv
    %retv = $dll(%mc_nhtmln_dllfilename,attach,$window(@nthmln).hwnd) 
    %retv = $dll(%mc_nhtmln_dllfilename,navigate,mircryption.sourceforge.net)
  }
  else {
    /mc_http http://mircryption.sourceforge.net
  }
}
; ---------------------------------------------------------------------------
























; ---------------------------------------------------------------------------
; callback from dll, used when dll needs to send text to status window
alias statusmsg {
  .echo 4 -si2  $1-
}
; ---------------------------------------------------------------------------



; ---------------------------------------------------------------------------
; we provide a large-capacity edit box in the dll where the user can copy and paste text which gets fed to mirc slowly to avoid flooding
;  avoid line limits and flood killing.  Note this calls \emsg to process lines.
; you would probably want to put this on a function-key shortcut
alias textpad {
  .dll %mc_scriptdll mc_pastepad $active
}
; ---------------------------------------------------------------------------



























; ---------------------------------------------------------------------------
; Custom Right-click Popup Menus


menu menubar,status {
  &Mircryption
  .List all stored channel encryption keys:/listkeys
  .Set/change master keyfile passphrase:/keypassphrase
  .Cleanup all encrypted topics and window background images:/mcfixalltopics
  .-
  .Select display theme..
  ..Display theme &1 - default - "square brackets":/mcscheme 1
  ..Display theme &2 - grey - "subtle grey letters":/mcscheme 2
  ..Display theme &3 - louvs - "magic arrows" :/mcscheme 3
  ..Display theme &4 - whiteblues - "clown's halfop heaven":/mcscheme 4
  ..Display theme &5 - e[MATRiX] - "geek greens for black backgrounds" :/mcscheme 5
  ..Display theme &6 - $chr(64) $+ news - "colored news and $chr(64) $+ op brackets" :/mcscheme 6
  ..Display theme &7 - e[MEKO] - "the best Theme" :/mcscheme 7
  .Window Background Options..
  ..Enable mircryption window background images:/mc_winbackground_enable yes
  ..Disable mircryption window background images:/mc_winbackground_enable no
  ..Configure mircryption window background image files:/mc_winbackground_setimagefiles
  ..Force refresh of mircryption window background images:/mcfixalltopics
  .-
  .Encrypted logging..
  ..Set key for encrypted logging:/setloggingkey
  ..List current logging rules:/mclog list
  ..Show help on logging:/mcloghelp
  ..-
  ..Open (encrypted) logging notes window:/mclognotes
  ..-
  ..Add logging rule:/mclog add
  ..Delete logging rule:/mclog del
  ..Change a logging rule:/mclog change
  ..-
  ..Launch Mircrypted File Viewer:/mclogviewer
  .-
  .Open backlog decryptpad:/mc_bncdecryptpad $chan
  .Perform an md5 jump-join:/mcjumpjoin
  .MS Agent Speech Toggle :.mcspeech
  .&Broadcast meow handshake to all channels:/mcmeowall
  .-
  .Open mIRC debugging window to see raw encrypted text:/mc_debug on
  .Open mIRC debugging window+ to see raw encrypted text and mircryption debugging:/mc_debug onplus
  .Force disable of temporary mircryption halting flags:/mc_nohalts
  .Close mIRC debugging window :/mc_debug off
  .-
  .Change Default Encryption Prefix to +OK (default, blow compatibility):/mcprefixchan "___ALL___" +OK
  .Change Default Encryption Prefix to mcps:/mcprefixchan "___ALL___"
  .Set the Optional Meow Taglines:/setmeowtaglines 
  .-
  .Script Management..
  ..Uninstall the mircryption script now:/mc_uninstall
  ..Move mircryption to top of script order:/reload -rs1 " $+ $script $+ "
  ..-
  ..Help/About:/mircryption
  ..Visit mircryption web page:/mircryptionurl
  ..-
  ..Check web for updates:/mcupdate mircryption.update
}


menu channel {
  &Mircryption
  .Set an encrypted &Topic for current channel:/etopic
  .&Launch the textpad for large text copy and paste:/textpad
  .-
  .&Set encryption key for current channel:/setkey
  .Display &Keyphrase for current channel:/displaykey
  .-
  .&Disable current channel encryption temporarily:/disablekey
  .Re-&enable current channel encryption:/enablekey
  .-
  .Migration of Keys and Backlog Decrypting
  ..Migrate current channel key from another channel..:/migratechankey
  ..Migrate current channel key to query key for ALL nicks in channel:/migratenickkeys all
  ..Migrate current channel key to query key for UNUSED nicks in channel:/migratenickkeys unused
  ..Open backlog decryptpad:/mc_bncdecryptpad $chan
  .-
  .More commands..
  ..List all stored encryption keys:/listkeys
  ..Set/Change master keyfile passphrase:/keypassphrase
  ..-
  ..Remove encryption key from current channel:/delkey
  ..-
  ..Change Encryption Prefix for channel to +OK (default, blow compatibility):/mcprefixchan $chan +OK
  ..Change Encryption Prefix for channel to mcps:/mcprefixchan $chan
  ..Upgrade Key for channel to cbc mode:/mcbcup $chan
  ..Downgrade Key for channel to default (ecb) mode:/mcbcdown $chan
  ..-
  ..Perform an md5 jump-join:/mcjumpjoin
  ..MS Agent Speech Toggle :.mcspeech
  ..&Broadcast meow handshake to channel:/mcmeow
  ..Broadcast meow &advert to current channel (prompts users to upgrade):/mcmeowupgradeadvert 
  ..-
  ..Open mIRC debugging window to see raw encrypted text:/mc_debug on
  ..Open mIRC debugging window+ to see raw encrypted text and mircryption debugging:/mc_debug onplus
  ..Close mIRC debugging window :/mc_debug off
  .-
  .Select display theme..
  ..Display theme &1 - default - "square brackets":/mcscheme 1
  ..Display theme &2 - grey - "subtle grey letters":/mcscheme 2
  ..Display theme &3 - louvs - "magic arrows" :/mcscheme 3
  ..Display theme &4 - whiteblues - "clown's halfop heaven":/mcscheme 4
  ..Display theme &5 - e[MATRiX] - "geek greens for black backgrounds" :/mcscheme 5
  ..Display theme &6 - $chr(64) $+ news - "colored news and $chr(64) $+ op brackets" :/mcscheme 6
  ..Display theme &7 - e[MEKO] - "the best Theme" :/mcscheme 7
  .-
  .Encrypted logging..
  ..Set key for encrypted logging:/setloggingkey
  ..List current logging rules:/mclog list
  ..Show help on logging:/mcloghelp
  ..-
  ..Open (encrypted) logging notes window:/mclognotes
  ..-
  ..Add logging rule:/mclog add
  ..Delete logging rule:/mclog del
  ..Change a logging rule:/mclog change
  ..-
  ..Launch Mircrypted File Viewer:/mclogviewer
  .-
  .Script Management..
  ..Uninstall the mircryption script now:/mc_uninstall
  ..-
  ..Help/About:/mircryption
  ..Visit mircryption web page:/mircryptionurl
  ..-
  ..Check web for updates:/mcupdate mircryption.update
}

; query is ALMOST same as channel, except no topics
menu query {
  &Mircryption
  .&Launch the textpad for large text copy and paste:/textpad
  .-
  .&Set encryption key for current window:/setkey
  .Display &Keyphrase for current window:/displaykey
  .-
  .&Disable current window encryption temporarily:/disablekey
  .Re-&enable current window encryption:/enablekey
  .-
  .Migration of Keys and Backlog Decrypting
  ..Migrate current window key from another nick/window..:/migratechankey
  ..Open backlog decryptpad:/mc_bncdecryptpad $1
  .-
  .More commands..
  ..List all stored encryption keys:/listkeys
  ..Set/Change master keyfile passphrase:/keypassphrase
  ..-
  ..Remove encryption key from current window:/delkey
  ..-
  ..Change Encryption Prefix for channel to +OK (default, blow compatibility):/mcprefixchan $1 +OK
  ..Change Encryption Prefix for channel to mcps:/mcprefixchan $1
  ..Upgrade Key for channel to cbc mode:/mcbcup $chan
  ..Downgrade Key for channel to default (ecb) mode:/mcbcdown $chan
  ..-
  ..Perform an md5 jump-join:/mcjumpjoin
  ..MS Agent Speech Toggle :.mcspeech
  ..&Broadcast meow handshake to window:/mcmeow
  ..-
  ..Open mIRC debugging window to see raw encrypted text:/mc_debug on
  ..Open mIRC debugging window+ to see raw encrypted text and mircryption debugging:/mc_debug onplus
  ..Close mIRC debugging window :/mc_debug off
  .-
  .Select display theme..
  ..Display theme &1 - default - "square brackets":/mcscheme 1
  ..Display theme &2 - grey - "subtle grey letters":/mcscheme 2
  ..Display theme &3 - louvs - "magic arrows" :/mcscheme 3
  ..Display theme &4 - whiteblues - "clown's halfop heaven":/mcscheme 4
  ..Display theme &5 - e[MATRiX] - "geek greens for black backgrounds" :/mcscheme 5
  ..Display theme &6 - $chr(64) $+ news - "colored news and $chr(64) $+ op brackets" :/mcscheme 6
  ..Display theme &7 - e[MEKO] - "the best Theme" :/mcscheme 7
  .-
  .Encrypted logging..
  ..Set key for encrypted logging:/setloggingkey
  ..List current logging rules:/mclog list
  ..Show help on logging:/mcloghelp
  ..-
  ..Open (encrypted) logging notes window:/mclognotes
  ..-
  ..Add logging rule:/mclog add
  ..Delete logging rule:/mclog del
  ..Change a logging rule:/mclog change
  ..-
  ..Launch Mircrypted File Viewer:/mclogviewer
  .-
  .Script Management..
  ..Uninstall the mircryption script now:/mc_uninstall
  ..-
  ..Help/about:/mircryption
  ..Visit mircryption web page:/mircryptionurl
  ..-
  ..Check web for updates:/mcupdate mircryption.update
}

menu @LogNotes {
  .Set key for encrypted logging:/setloggingkey
  .List current logging rules:/mclog list
  .Show help on logging:/mcloghelp
  .-
  .Add logging rule:/mclog add
  .Delete logging rule:/mclog del
  .Change a logging rule:/mclog change
  .-
  .Launch Mircrypted File Viewer:/mclogviewer
  .-
  .Close LogNotes window:/window -c @LogNotes
}

menu @MircDebugWindow,@MircDebugWindowPlus {
  .Close mIRC debugging window :/mc_debug off
}

menu nicklist {
  .Mircryption - Broadcast private meow handshake to [ $$1 ] on [ $chan ] :/mcmeownick $chan $1
}
; ---------------------------------------------------------------------------
























; ---------------------------------------------------------------------------
; Events for incoming text

; incoming - incoming from channel
on ^*:text:*:#: {
  ; process it - and get back a 1 if we handled it, so should haltdef, or 0 if not and should return normally
  ;echo DEBUG in incoming text#, nick is $nick chan is $chan  active is $active and text is $1-
  if ($halted) return
  if (%mc_halttext == yes) return
  if ($mc_oneinput( $nick , $chan , text , $1 , $2-) == 1) haltdef
  .mcfixtopic $chan   
}


; incoming - incoming from notice - seems to be overridden by text
on ^*:notice:*:*: {
  ; process it - and get back a 1 if we handled it, so should haltdef, or 0 if not and should return normally
  if ($halted) return
  if (%mc_halttext == yes) return
  if ($chan != $null) {
    ; interesting, if $chan is set, then this is a notice sent with privmesg and should be treated like incoming text on a chan
    if ($mc_oneinput( $nick , $chan , notice , $1 , $2-) == 1) haltdef
    else if (%mc_fixmircnoticebug == yes) {
      ; we take over in this case to bypass mirc bug(?) which can cause this kind of privmesg notice in $active channel instead of $chan
      echo $colour(notice text) -lbfmt $chan - $+ $nick $+ - $1-
      haltdef
    }
  }
  else {
    if ($mc_oneinput( $nick , $nick , notice , $1 , $2-) == 1) haltdef
    else if (($active == Status Window) && (%mc_fixmircnoticebug == yes)) {
      ; again takeover to prevent mirc bug(?) of displaying notices received while in the status window to ALL windows.
      echo $colour(notice text) -slbfmt - $+ $nick $+ - $1-
      haltdef
    }
  }
  .mcfixtopic $chan
}


; incoming - incoming from query window
on ^*:text:*:?: {
  ; process it - and get back a 1 if we handled it, so should haltdef, or 0 if not and should return normally
  ; echo in incoming text?, nick is $nick chan is $chan  active is $active
  if ($halted) return
  if (%mc_halttext == yes) return
  if ($mc_oneinput( $nick , $nick , query , $1 , $2-) == 1) haltdef
  else if (($nick == -psyBNC)) {
    var %retv
    if ( ($pos($1-,$chr(41) $+ $chr(32) $+ mcps $+ $chr(32),1) > 0) ) {
      %retv = $mc_bncdecryptstring($1-)
      if (%retv == $true) haltdef
    }
    if ( ($pos($1-,$chr(41) $+ $chr(32) $+ +OK $+ $chr(32),1) > 0) ) {
      %retv = $mc_bncdecryptstring($1-)
      if (%retv == $true) haltdef
    }
    if ( ($pos($1-,B $+ $chr(93) $+ mcps $+ $chr(32),1) > 0) ) {
      %retv = $mc_bncdecryptstring($1-)
      if (%retv == $true) haltdef
    }
    if ( ($pos($1-,B $+ $chr(93) $+ +OK $+ $chr(32),1) > 0) ) {
      %retv = $mc_bncdecryptstring($1-)
      if (%retv == $true) haltdef
    }
  }
  .mcfixtopic $active
} 

; incoming - incoming action from channel
on ^*:action:*:#: {
  ; process it - and get back a 1 if we handled it, so should haltdef, or 0 if not and should return normally
  if ($halted) return
  if (%mc_halttext == yes) return
  if ($mc_oneinput($nick, $chan , action , $1 , $2-) == 1) haltdef
  .mcfixtopic $active
}

; incoming - incoming action from query window
on ^*:action:*:?: {
  ; process it - and get back a 1 if we handled it, so should haltdef, or 0 if not and should return normally
  if ($halted) return
  if (%mc_halttext == yes) return
  if ($mc_oneinput( $nick , $nick , queryaction , $1 , $2-) == 1) haltdef
  .mcfixtopic $active
}

; incoming - incoming from dcc chat
on ^*:chat:*: {
  ; process it - and get back a 1 if we handled it, so should haltdef, or 0 if not and should return normally
  ; echo in incoming chat, nick is $nick chan is $chan  active is $active
  if ($halted) return
  if (%mc_halttext == yes) return
  var %cname = $chr(61) $+ $nick
  if ($mc_oneinput( $nick , %cname , query , $1 , $2-) == 1) haltdef
  .mcfixtopic $active
}
; ---------------------------------------------------------------------------






; ---------------------------------------------------------------------------
; here is the new single procedure for handling all incoming text/actions
; $1 is speaker (usually $nick), $2 is output target ($chan or $nick) , $3 is type of echo (text, notice, action), $4 is first word ($mc_isetag() true if encrypted), $5- is the encrypted text (with prefix removed)
alias mc_oneinput {
  var %om 

  var %etagged1 = $false
  var %etagged2 = $false
  var %elen
  var %ename | %ename = $2
  var %cname | %cname = %ename
  var %applytheme = $null
  var %pre
  var %msgtype = $3

  ;echo DEBUGGGGGGING , IN ONEINPUT WITH $1 , $2 , $3

  if ($window(@MircDebugWindowPlus).wid != $null) {
    echo @MircDebugWindowPlus MIRCYRPTION <- :incomingtext: speaker= $1 target= $2 type= %msgtype firstword= $4
  }

  ; clear any previous mc_nick and mc_chan global variables (this is necesary to handle signal chan/nick properly)
  .clearmcnickchan

  ; correct for dcc chat channel names
  %ename = $chatchan(%ename)

  ; incoming messageboard commands are ignored by us
  if ( $4 == !mcb) return 0
  if ( $4 == !mcball) return 0

  ; disable flag?
  if (%mc_halttext == yes) return 0

  if ( $mc_isetag($4)) {
    %etagged1 = $true
    var %firstword | %firstword = $gettok( $5 , 1 , 32)
    if (%firstword == meow) {
      ; special handshake protocol
      .mchandshake $gettok($5 , 2- , 32)
      return 1
    }
    if (%firstword == J1) {
      ; special MPGP job protocol - NEW
      .mpgp_processInputLine $2 $1 $gettok($5 , 1- , 32)
      return 1
    }
    %om = $5-
  }

  if ( $mc_isetag2($4-)) {
    %etagged2 = $true
    %om = $4-
  }

  ; a cute thing we do, allowing notices to be directed at a specific channel, useful for when news replies, to avoid it tracking our active channel
  if (%msgtype == notice) {
    if ($1 == $2) %cname = $active
    if ( $left($4,2) == $chr(150) $+ $chr(150) ) {
      ; strip the special channel name
      %om = $5-
      %elen = $len($4)
      %elen = %elen - 2
      %cname = $right($4 , %elen)
      %ename = $chatchan(%cname)

      ; 5/12/04 experimental - use bot name?
      %ename = [ mcboard_ $+ [ %ename ] $+ _ekey ]

      ; 1/21/05 fix for new ebc/cbc mode (in case user did not modify their news key after upgrading)
      var %keyname = %ename
      var %ecbkeyname = %keyname $+ _ecb

      var %keyvalue = $dll( %mc_scriptdll , mc_displaykey , %ecbkeyname )
      if (%keyvalue == $null) {
        ; hmm, ecb not set because of new upgrade, so now we set it

        var %ecbkey = $dll( %mc_scriptdll , mc_displaykey , %keyname )
        if ( $left(%ecbkey ,4) == cbc; ) {
          %ecbkey = $mid(%ecbkey ,5);
        }
        if ( $left(%ecbkey ,4) == cbc: ) {
          %ecbkey = $mid(%ecbkey ,5);
        }

        %retv = $dll( %mc_scriptdll , mc_setkey , %ecbkeyname %ecbkey )
      }

      ; now we allow special notices to also be redirected to a special window
      if (%mcb_dedicated_notice_window != $null) {
        %cname = @ $+ %mcb_dedicated_notice_window
        /window %cname
      }
      %etagged2 = $true
      %applytheme = news
    }
  }

  if (%etagged1 || %etagged2) {
    var %plen
    var %m | %m = %om
    var %mout
    var %encryptename

    if ( [ $left(%ename,4) ] == chat && $mid(%ename,5,1) == $chr(32)) {
      ; echo in chat
      var %elen = $len(%ename)
      %elen = %elen - 5
      %encryptename = $right(%ename , %elen)
      %ename = $chr(61) $+ %encryptename
    }
    else %encryptename = %ename

    ; decrypt text if appropriate using dll
    if (%etagged1) {

      %m = $dll( %mc_scriptdll  , mc_decrypt , %encryptename %om)
      if ($window(@MircDebugWindowPlus).wid != $null) {
        if (%m != $null) echo @MircDebugWindowPlus MIRCYRPTION <- :decrypted incomingtext etagged1: ename= %encryptename with rest = %m
        else echo 4 @MircDebugWindowPlus MIRCYRPTION <- :failed decrypt incomingtext etagged1: ename= %encryptename
      }
    }
    else if (%etagged2) {
      %m = $dll( %mc_scriptdll  , mc_decrypt2 , %encryptename %om)
      if ($window(@MircDebugWindowPlus).wid != $null) {
        if (%m != $null) echo @MircDebugWindowPlus MIRCYRPTION <- :decrypted incomingtext etagged2: ename= %encryptename
        else echo 4 @MircDebugWindowPlus MIRCYRPTION <- :failed decryptincomingtext etagged2: ename= %encryptename
      }
    }

    ; substitute multispaces with space preserving $160 ?
    %m = $mcmultispacefix(%m)

    ; fish uses special tag for encrypted actions
    if ($mid(%m,2,6) == ACTION) {
      var %eplen = $len(%m)
      var %fistchar = $left(%m,1)
      if ( (%firstchar == $null) || (%firstchar == $chr(1)) ) {
        var %efpos = 9
        %eplen = %eplen - 9
        %msgtype = action
        %m = $mid(%m,%efpos,%eplen)
      }
    }

    ; new strip anything (colors,etc) that user has set to strip in options dialog
    %m = $strip(%m,mo)

    if ( %m != $null ) {
      ; apply any theme (for news for example)
      if (%applytheme != $null) %m = $mc_applytheme(%applytheme,%m)

      ;echo text to proper target channel/querywindow
      if (%msgtype == action) %pre = %mc_preaction_decrypt $1
      else if (%applytheme == news) {
        ; nick prefixing for news
        %pre = %mc_theme_news_prenick $+ $1 $+ %mc_theme_news_postnick
      }
      else if (%msgtype == notice) {
        ; nick prefixing for notice
        %pre = %mc_prenick_decrypt_notice $1 %mc_postnick_decrypt_notice
      }
      else %pre = $prenickify_decrypt(%ename , $1)

      %mout = %pre %m

      if (%applytheme != news) {
        ; we remove colors if this string has a keyword that mirc wants to highlight
        ;        if ($mc_checkhighlight($1,%m) != $false ) %mout = $strip(%mout)
        ; new try to preserve some text colors
        if ($mc_checkhighlight($1,%m) != $false ) %mout = $strip(%pre) %m
      }

      if (%mc_indent == nick) %plen = $len($strip(%pre)) + 1
      else %plen = 0
      if (%mc_indentplus != $null) %plen = %plen + %mc_indentplus

      ;      if (%msgtype == notice) .echo -lbmfti $+ %plen $active  $+ $colour(notice text) $+ %mout
      ;      else .echo -lbmfti $+ %plen %ename %mout

      if (%applytheme == news) {
        $mc_logparse(%msgtype,%cname,$1,%m,$address,$true)
        if ($mchandlehalt() == $true) return 1
        .echo $prespopt_NoHighlight(%pre) %cname %mout
      }
      else if (%msgtype == notice) {
        ; show the notice
        ;if ($mc_checkhighlight($1,%m) != $false) .echo $prespopt4(%pre) %cname %mout
        ; pass it to optional logging function
        ; $1 is speaker (usually $nick), $2 is output target ($chan or $nick) , %msgtype is type of echo (text or action), $4 is first word ($mc_isetag() true if encrypted), $5- is the encrypted text (with prefix removed)
        $mc_logparse(%msgtype,%cname,$1,%m,$address,$true)
        if ($mchandlehalt() == $true) return 1
        ; new try to preserve some text colors
        if ($mc_checkhighlight($1,%m) != $false) .echo $prespopt4(%pre) %cname $strip(%pre) %m
        else {
          ; new fix of timestamp colors
          ;.echo $prespopt4(%pre) %cname  $+ $colour(notice text) $+ %mout
          .echo $colour(notice text) $prespopt4(%pre) %cname %mout
        }
      }
      else if (%msgtype == text) {
        $mc_logparse(%msgtype,%cname,$1,%m,$address,$true)
        if ($mchandlehalt() == $true) return 1
        ; new fix of timestamp colors
        ;.echo $prespopt3(%pre) %cname %mout
        .echo $prespopt3(%pre) %cname %mout
      }
      else if ((%msgtype == action) || (%msgtype == queryaction)) {
        $mc_logparse(%msgtype,%cname,$1,%m,$address,$true)
        if ($mchandlehalt() == $true) return 1
        ; new fix of timestamp colors
        ;.echo $prespopt3(%pre) %cname %mout
        .echo $colour(action text) $prespopt3(%pre) %cname %mout
      }
      else {
        $mc_logparse(%msgtype,%cname,$1,%m,$address,$true)
        if ($mchandlehalt() == $true) return 1
        ; new fix of timestamp colors
        ;.echo $prespopt3(%pre) %cname %mout
        .echo $prespopt3(%pre) %cname %mout
      }

      ; at this point we have: decrypted text (%m), target channel/querywindow ($2), and speaker ($1)
      ; if you had your own stuff you wanted to do to incoming text, you would do it to %m here
      ; built-in mirc msagent (text-to-speech) support does not work with mircryption, as it tries to read encrypted text, so we need to do a work-around
      .mc_msagent $1 %encryptename %msgtype %m

      ; return saying we have handed it
      return 1
    }
  }
  else {
    if ($5 == $null) %om = $4
    else %om = $4-
  }

  ; if we get here, it means we did not "handle" it, and %om is the text
  ; new option to take over from mirc speaking\
  if (%mc_agent_replacemirc == yes) .mc_msagent $1 %cname %msgtype %om

  ; ATTN: pass non-decrypted text to optional logging function
  ; $1 is speaker (usually $nick), $2 is output target ($chan or $nick) , %msgtype is type of echo (text or action), $4 is first word ($mc_isetag() true if encrypted), $5- is the encrypted text (with prefix removed)
  $mc_logparse(%msgtype,%cname,$1,%om,$address,$false)
  if ($mchandlehalt() == $true) return 1
  ; IF we wanted to handle normal incoming text as well, we could do it here and return 1  

  if (%msgtype == notice) {
    ; TEST: take over notices even if not encrypted?
    ;.echo %cname  $+ $colour(notice text) $+ %om
    ;return 1
  }

  if (%mc_takeovernormal == yes) {
    ; user has asked us to takeover normal text too (maybe because they like our indenting
    var %nm = %om
    if (%msgtype == notice) {
      %pre = $1 ->
      %nm = %pre %om
      if ($mc_checkhighlight($1,%om) != $false) .echo $prespopt4(%pre) %cname %nm
      else .echo $colour(notice text) $prespopt4(%pre) %cname %nm
      return 1
    }
    else if (%msgtype == text) {
      if (%mc_nonickbrackets == yes) %pre = $+(,$1,)
      else %pre = < $+ $1 $+ >
      %nm =  %pre %om
      .echo $prespopt3(%pre) %cname %nm
      return 1
    }
    else if ((%msgtype == action) || (%msgtype == queryaction)) {
      %pre = * $1
      %nm = %pre %om
      .echo $colour(action text) $prespopt3(%pre) %cname %nm
      return 1
    }
    else {
      if (%mc_nonickbrackets == yes) %pre = $+(,$1,)
      else %pre = < $+ $1 $+ >
      %nm = %pre %om
      .echo $prespopt3(%pre) %cname %nm
      return 1
    }
  }

  return 0
}


alias mc_checkhighlight {
  ; to be used to customize our highlight if we want to make it also dependent on nick
  ;echo ------
  ;echo nick is = $1
  ;echo plaintext = $2-
  ;echo highlight nicks = $highlight($1).nicks
  ;echo highlight text = $highlight($2-)
  ;echo highlight text.text = $highlight($2-).text
  ;echo highlight color of text = $highlight($2-).color
  ; this gets a highlight if either the text message is to be highlighted OR if the nick+message is to be nick highlighted

  ; if nick is set to highlight then its a true
  if ($highlight($1).nicks == $true) return $true
  if ($highlight($2-).text != $null) return $true
  return $false
}
; ---------------------------------------------------------------------------






















; ---------------------------------------------------------------------------
; Processing functions for outgoing text


on *:input:*: {
  ; outgoing - outgoing to channel

  ; /echo in mircryption :input: with input is '$1-' length is $len($1-)

  ; clear any previous mc_nick and mc_chan global variables (this is necesary to handle signal chan/nick properly)
  .clearmcnickchan

  if ($len($1-) > 850) {
    var %shorten = $len($1-) - 850
    echo 4 Mirc cannot handle safely lines bigger than about 850 characters, and so your text was NOT sent; please shorten it (by about %shorten $+ characters).
    haltdef
    halt
    return
  }

  ; is it already halted (handled by another routine)
  if ($halted) return

  if (%mc_haltinput == yes) return

  ; mircryption messageboard feature handled by separate script
  if ($1 == !mcb) return
  if ($1 == !mcball) return

  var %om | %om = $1-
  var %m | %m = %om
  var %ename
  var %encryptename
  var %elen
  var %cname = $chan

  if (%cname == $null) %cname = $active

  ; correct for dcc chat channel names
  %ename = $chatchan(%cname)

  ;  echo $active channel $chan window outgoing event active is $active

  if ($window(@MircDebugWindowPlus).wid != $null) echo @MircDebugWindowPlus MIRCRYPTION -> :outgoingtext: ename = %ename , chan = $chan , active = $active , 1 = $1

  if ($ctrlenter) {
    ; control enter does not check for commands
  }
  else if ($1 == /me || ($1 == -me)) {
    ; strip off the text after the /me and PRESERVE prefixing spaces
    if ($mcactiondisable(%cname)) return
    %m = $removefirstword(%m)
    %om = %m
  }
  else if (($1 == /msg) || ($1 == /notice)) {
    %cname = $2
    %ename = $chatchan(%cname)
    %m = $2-
    ; strip off the text after the /msg chan and PRESERVE prefixing spaces
    %m = $removefirstword(%m)
    %om = %m
  }
  else if  (($left($1,1) == !) && (%mc_encryptbangs == no)) {
    ; dont ecnrypt bangs?
    if (!$isupper(%om) || !$islower(%om)) {
      ; it's got some letters, so we dont encrypt
      $mc_logparse(input,%cname,$me,%om,$address,$false)
      if ($mchandlehalt() == $true) return
      return
    }
  }
  else if ( $left($1,1) == / ) {
    ; let other commands execute (dont encrypt them as output!)
    $mc_logparse(input,%cname,$me,%om,$address,$false)
    if ($mchandlehalt() == $true) return
    ; there are some commands we take over
    if ( ($mid($1,2,4) == amsg) && ($mid($1-,6,1) == $chr(32)) ) {
      ; we take over amsg with all message which encrypted if appropriate (for some reason $1 == /amsg did not work)
      /mc_amsg $2-
      haltdef
    }
    else if ($1 == /ame) {
      ; we take over ame
      /mc_ame $2-
      haltdef
    }
    return
  }

  if ($mc_ischannelmute($active)) {
    echo 4 Channel set on mute, use /mcmute to toggle.  Text not sent: $1-
    haltdef
    return
  }

  ; new generic mechanism for indicating certain outgoing stuff should not be encrypted (like commands to bots) 8/25/02
  if ($ctrlenter) {
    ; control enter does not check for commands
  }
  else if ( $mc_plainbinding($1-) ) return

  if ($ctrlenter) {
    ; control enter does not check for commands
  }
  else if ( ( $left($1,1) == \ ) && (%mc_correctbackslashes == yes) ) {
    ; user meant to type '/' instead? we guess yes, so we warn user
    ; to be smart about this, we check for some letters in text.  only if we find do we guess this
    echo 4 Correcting '\' to '/'
    var %tlen | %tlen = $len(%om) - 1
    %om = $right($1- , %tlen)
    ; execute it
    / $+ %om
    ; now log it
    %om = / $+ %om
    $mc_logparse(input,%cname,$me,%om,$address,$false)
    $mchandlehalt()
    halt
  }

  if ( [ $left(%ename,4) ] == chat && $mid(%ename,5,1) == $chr(32)) {
    %elen = $len(%ename)
    %elen = %elen - 5
    %encryptename = $right(%ename , %elen)
    %ename = $chr(61) $+ %encryptename
  }
  else %encryptename = %ename

  ; the single character reverser.  if the text starts with %mc_reversechar then we reverse whatever mode we are in, if encrypotion enabled, then we dont, if not, we do
  if (!$ctrlenter && ($left(%om, $len(%mc_reversechar) ) == %mc_reversechar )) {
    var %tlen | %tlen = $len(%om) - $len(%mc_reversechar)
    var %temptext = $right(%om , %tlen)
    if ($dll( %mc_scriptdll ,mc_isencrypting , %encryptename) == yes) {
      ; we could just return here, which would let mirc default routines send the text, BUT that would show the reversechar, so instead we handle it
      if ($1 == /msg ) {
        $mc_logparse(input,%cname,$me, %temptext ,$address,$false)
        if ($mchandlehalt() == $true) { haltdef | return }
        ./msg %cname $right(%om , %tlen)
        var %pre | %pre = -> %cname
        .echo $colour(own text) $prespopt2(%pre) $active %pre $right(%om , %tlen)
        ;echo -> %cname $right(%om , %tlen)
        ;%om = $1 %cname $right(%om , %tlen)
      }
      else if ($1 == /notice) {
        $mc_logparse(input,%cname,$me, %temptext ,$address,$false)
        if ($mchandlehalt() == $true) { haltdef | return }
        ./notice %cname $right(%om , %tlen)
        var %pre | %pre = -> %cname
        .echo $colour(own text) $prespopt2(%pre) $active %pre $right(%om , %tlen)
        ;echo -> %cname $right(%om , %tlen)
        ;%om = $1 %cname $right(%om , %tlen)
      }
      else if ($1 == /me) {
        $mc_logparse(input,%cname,$me, %temptext ,$address,$false)
        if ($mchandlehalt() == $true) { haltdef | return }
        /action $right(%om , %tlen)
        ;var %pre | %pre = *-> %cname
        ;.echo $colour(own action) * $me $right(%om , %tlen)
      }
      else {
        $mc_logparse(input,%cname,$me, %temptext ,$address,$false)
        if ($mchandlehalt() == $true) { haltdef | return }
        var %pre
        if (%mc_nonickbrackets == yes) %pre = $+(,$me,)
        else %pre = < $+ $me $+ >
        var %sendtext = $right(%om , %tlen)
        if (%sendtext == $null) %sendtext = .
        .msg $active %sendtext
        .echo $colour(own text) $prespopt2(%pre) $active %pre %sendtext
      }
      ; logging
      haltdef
      return
    }
    ; strip off the reversechar and continue, forcing encryption
    %om = $right($1- , %tlen)
  }

  if (($dll( %mc_scriptdll ,mc_isencrypting , %encryptename) != yes) && ($ctrlenter || ($left(%m, $len(%mc_reversechar) ) != %mc_reversechar )) ) {
    ; we are not encrypting on this channel, so we will just drop down past encryption
    %m = %om
  }
  else {
    ; ENCRYPT
    ; some servers kill text bigger than about 400 characters.  FURTHERMORE it appears mirc can choke on words>400 characters.
    ; which can happen after we encrypt a line with spaces (spaces can dissapear)
    ; if we detect that the user is trying to send such a big message, we will try to break it up for them
    if ($len(%m) > %mc_splitlinelen) {
      .dll %mc_scriptdll mc_splitsay %encryptename %mc_splitlinelen %m
      haltdef
      return
    }

    ; optional fun scrambler
    if (%speakscrambler == on) {
      %m = $ss_scramblesentence(%om)
      %om = %m
    }

    ; encrypt message if appropriate
    %m = $dll( %mc_scriptdll  , mc_forceencrypt , %encryptename %om)

    if ($window(@MircDebugWindowPlus).wid != $null) {
      if (%m != %om && %m != $null) echo @MircDebugWindowPlus MIRCRYPTION -> :encrypted outgoingtext: encryptename = %encryptename
      else echo 4 @MircDebugWindowPlus MIRCRYPTION -> :didnt encrypt outgoingtext: encryptename = %encryptename
    }
  }

  if ( $left(%m,17) == Mircryption_Error) {
    ; error encrypting output
    .echo 4 -t %m
  }
  else if (%m != %om && %m != $null) {
    ; output encrypted message (note that this does not echo the message to users window)
    ; echo user's original text to the user, with indicator letting user know if it was encrypted
    if ((!$ctrlenter) && ($1 == /me || ($1 == -me))) {
      ; log action
      $mc_logparse(action,%cname,$me,%om,$address,$true)
      if ($mchandlehalt() == $true) return
      .action $mcetagchan($active) %m
      var %pre | %pre = %mc_preaction_encrypt $me 
      ; new fix of timestamp colors
      ;.echo $prespopt2(%pre)  $+ $colour(action text) $+ %pre %om
      .echo $colour(action text) $prespopt2(%pre) %pre %om
      if (%mc_agent_char_mynick != disable) /mc_msagent $me $active action %om
    }
    else if ((!$ctrlenter) && ($1 == /msg)) {
      ; log notice
      $mc_logparse(notice,$2,$me,%om,$address,$true)
      if ($mchandlehalt() == $true) return
      .msg $2 $mcetagchan($2) %m
      var %pre | %pre = %mc_prenick_encrypt $+ -> $+ %mc_postnick_encrypt $2
      ; new fix of timestamp colors
      ;.echo $prespopt2(%pre)  $+ $colour(own text) $+ %pre %om
      .echo $colour(own text) $prespopt2(%pre) %pre %om
      if (%mc_agent_char_mynick != disable) /mc_msagent $me $active text %om
    }
    else if ((!$ctrlenter) && ($1 == /notice)) {
      ; log notice
      $mc_logparse(notice,$2,$me,%om,$address,$true)
      if ($mchandlehalt() == $true) return
      .notice $2 $mcetagchan($2) %m
      var %pre | %pre = %mc_prenick_encrypt_notice $2 %mc_postnick_encrypt_notice
      ; new fix of timestamp colors
      ;.echo $prespopt2(%pre)  $+ $colour(own text) $+ %pre %om
      .echo $colour(own text) $prespopt2(%pre) %pre %om
      if (%mc_agent_char_mynick != disable) /mc_msagent $me $active text %om
    }
    else {
      ; note we use the raw %cname as the target of our send
      ; log text
      $mc_logparse(input,%cname,$me,%om,$address,$true)
      if ($mchandlehalt() == $true) return
      .msg %cname $mcetagchan($active) %m
      var %pre | %pre = $prenickify_encrypt(%cname)
      ; old bad color:
      ;.echo $prespopt2(%pre)  $+ $colour(own text) $+ %pre %om
      ; new timestamp fixed color
      .echo $colour(own text) $prespopt2(%pre) %pre %om

      if (%mc_agent_char_mynick != disable) /mc_msagent $me $active text %om
    }
  }
  else {
    ; normal text not encrypted
    ; log text
    if ((!$ctrlenter) && ($1 == /msg)) $mc_logparse(notice,$2,$me,%om,$address,$false)
    else if ((!$ctrlenter) && ($1 == /me)) $mc_logparse(action,$2,$me,%om,$address,$false)
    else $mc_logparse(input,%cname,$me,%om,$address,$false)
    if ($mchandlehalt() == $true) return
    ;
    if ((!$ctrlenter) && ($1 == /me && %mc_agent_char_mynick != disable && %mc_agent_replacemirc == yes)) /mc_msagent $me $active action %om
    else if ((!$ctrlenter) && ($1 == /msg && %mc_agent_char_mynick != disable && %mc_agent_replacemirc == yes)) /mc_msagent $me $active text %om
    else if ((!$ctrlenter) && (%mc_agent_char_mynick != disable && %mc_agent_replacemirc == yes)) /mc_msagent $me $active text %om

    if (%mc_takeovernormal == yes) {
      ; user has asked us to takeover normal text too (maybe because they like our indenting
      %m = %om

      if ((!$ctrlenter) && ($1 == /me || ($1 == -me))) {
        .action %m
        var %pre | %pre = * $me
        .echo $colour(action text) $prespopt2(%pre) $active %pre %om
        if (%mc_agent_char_mynick != disable) /mc_msagent $me $active action %om
      }
      else if ((!$ctrlenter) && ($1 == /msg)) {
        .msg $2 %m
        var %pre | %pre = -> $2
        .echo $colour(own text) $prespopt2(%pre) $active %pre %om
        if (%mc_agent_char_mynick != disable) /mc_msagent $me $active text %om
      }
      else if ((!$ctrlenter) && ($1 == /notice)) {
        .notice $2 %m
        var %pre | %pre = -> $2
        ; new fix of timestamp colors
        .echo $colour(own text) $prespopt2(%pre) $active %pre %om
        if (%mc_agent_char_mynick != disable) /mc_msagent $me $active text %om
      }
      else {
        .msg %cname %m
        var %pre
        if (%mc_nonickbrackets == yes) %pre = $+(,$me,)
        else %pre = < $+ $me $+ >
        .echo $colour(own text) $prespopt2(%pre) $active %pre %om
        if (%mc_agent_char_mynick != disable) /mc_msagent $me $active text %om
      }

      haltdef
      return
    }

    return
  }
  haltdef
}
; ---------------------------------------------------------------------------




















; ---------------------------------------------------------------------------
; For encrypted topics - we have to be clever and do kludges.  basically what we do is use a dll to
;  change the window titlebar for a channel, even though mirc thinks the topic is something else
;  becasue of this, we must constantly be on watch for things that could make mirc reset the channel
;  window title, and rechange it back (after a tiny delay).

on ^*:TOPIC:*: {
  ; incoming - incoming action from channel
  ; do nothing if the preface is missing - we will encrypt this if channel is set to encrypt
  ; main thing this does is decrypt incoming encrypted topics
  ; but we also now try to fix up topics that should be encrypted but arent like doublte-click topic
  ; changes unfortunately, when you double click mirc always immediately sends out the new topic and
  ; i cant stop it or encrypt it before it sends it out so no way to stop people in channel without
  ; encryption from seeing it for that you have to use /etopic or /etopic menu.  best i can do is
  ; re-encrypt it after it goes out for later people.  HOWEVER, i think its better to give a warning
  ; in this case.

  ; echo IN TOPIC is activated

  if (%mc_halttext == yes) return

  ; otherwise, if user tries to set a plain topic on encrypted (through double click box for example), then we force it to encrypt
  if ( $mc_isetag3($1-) == $false) {
    if ($nick == $me && $dll( %mc_scriptdll ,mc_isencrypting , $chan) == yes) {
      ;  re-encrypt it
      ;      .haltdef
      ;      /etopic $1-
      ; instead of re-encrypting it, which gives false sense of security, we will do the opposie
      if (%mc_warnings == yes) echo 4 -i2 $chan Warning - you have set a plain text topic in an encrypted channel.  Use /etopic or right-click menu to set encrypted topics.
    }
    ; log it if appropriate
    $mc_logparse(topic,$chan,$nick,$1-,$address,$false)
    if ($mchandlehalt() == $true) return
    if ((%mc_agent_replacemirc == yes) && ($nick != $me)) /mc_msagent $nick $chan topic $1-
    return
  }

  if ($len( $1- ) > 901 ) return;
  ;echo $chan channel window incoming text event

  ; decrypt text if appropriate using dll
  ; old method
  ; var %om | %om = $2-
  ; var %m | %m = %om
  ; %m = $dll( %mc_scriptdll  , mc_decrypt , $chan %om)
  var %om | %om = $1-
  var %m | %m = %om
  %m = $dll( %mc_scriptdll  , mc_decrypt2 , $chan %om)

  ; substitute multispaces with space preserving $160 ?
  %m = $mcmultispacefix(%m)

  ;copy decrypted text to channel
  if (%m != %om && %m != $null) {
    %m = %mc_pretopic %m
    %m = $strip(%m)
    .dll %mc_scriptdll mc_forcetopic $window($chan).hwnd $dll( %mc_scriptdll ,mc_isencrypting , $chan) %m
    %mc_lasttopic_author = $nick
    %mc_lasttopic_time = $asctime(ddd mmm d h:nn:ss)
    ; log it if appropriate
    $mc_logparse(topic,$chan,$nick,%m,$address,$true)
    if ($mchandlehalt() == $true) return
    .echo $colour(topic text) -i2 $chan *** %mc_lasttopic_time %mc_lasttopic_author encrypts topic to ' $+ %m $+ '
    if (%mc_lasttopic_author != $me) /mc_msagent %mc_lasttopic_author $chan topic %m
    /mcfixtopic_smart $chan
    .haltdef
  }
  else {
    ; log it if appropriate
    $mc_logparse(topic,$chan,$nick,%om,$address,$false)
    /mcfixtopic_smart $chan
    if ($mchandlehalt() == $true) return
  }
  ; else .dll %mc_scriptdll mc_forcetopic $window($chan).hwnd $dll( %mc_scriptdll ,mc_isencrypting , $chan) %om
}


; manual topic request
raw 332:*: {
  ;echo IN 332TOPIC chan is $chan one is $1 and 2 is $2
  if (%mc_halttext == yes) return
  if ( $mc_isetag3($3-) == $false) {
    ;echo DEBUG FALSE $1-
    return 
  }
  ; decrypt and display topic
  .mcfixtopic $2 speak
}
; ---------------------------------------------------------------------------



; ---------------------------------------------------------------------------
; we neet to capture join to update encrypted topics, and other events which disturb encrypted topics
on *:JOIN:#: {
  ; this triggers when ANYONE joins a channel we are on
  ; we need to use 1 second timers to insure that the window is updated before we fix the topic
  ; name the timer based on channel so many can work simultaneously
  ; note we also pass the nick of the person joining - this is so our fixer reports the new topic if we ourselves join the channel

  if ($nick == $me) mc_updatewinbackground $chan

  if (%mc_halttext == yes) return

  ; log if appropriate
  $mc_logparse(join,$chan,$nick,$address,$false)
  if ($mchandlehalt() == $true) return

  ; dummy encyrpt, to force requesting of master passphrase when joining encrypted channels right away
  var %dummy =  $dll( %mc_scriptdll  , mc_encrypt , $chan dummytext)
  if ($nick == $me) {
    ;.mcfixtopic $chan speak
    ;.timer $+ [ MCFIXTOPIC $+ [ $chan ] ] 1 1 mcfixtopic $chan speak
    .mcfixtopic $chan
    .timer $+ [ MCFIXTOPIC $+ [ $chan ] ] 1 1 mcfixtopic $chan
  }
  else {
    .mcfixtopic $chan $nick
    .timer $+ [ MCFIXTOPIC $+ [ $chan ] ] 1 1 mcfixtopic $chan $nick
  }
  if (%mc_agent_replacemirc == yes && %mc_agent_speakevents == yes && $nick != $me) /mc_msagent $nick $chan join dummytext
}

on *:PART:#: {
  ; log it if appropriate
  $mc_logparse(part,$chan,$nick,$address,$false)
  if ($mchandlehalt() == $true) return
  ; now respond to it
  if ($dll( %mc_scriptdll  , mc_iskeyunlocked , $chan) == yes) /mcfixtopic_smart $chan
  if (%mc_agent_replacemirc == yes && %mc_agent_speakevents == yes && $nick != $me) /mc_msagent $nick $chan part dummytext
}

on *:QUIT: {
  ; log it if appropriate
  var %c = 1
  var %tempvar
  while ($comchan($nick,%c)) {
    %tempvar = $mc_logparse(quit,$ifmatch,$nick,$address,$1-,$false)
    inc %c
  }
  if ($mchandlehalt() == $true) return
  ; now handle it
  if ($dll( %mc_scriptdll  , mc_iskeyunlocked , $chan) == yes) .mcfixtopic_smart $chan
  if (%mc_agent_replacemirc == yes && %mc_agent_speakevents == yes && $nick != $me) /mc_msagent dummy dummy other NOTICE: $nick has quit channel $chan
}

on *:KICK:#: {
  ; log it if appropriate
  $mc_logparse(kick,$chan,$nick,$address,$knick,$1-,$false)
  if ($mchandlehalt() == $true) return
  ; now respond to it
  if ($dll( %mc_scriptdll  , mc_iskeyunlocked , $chan) == yes) /mcfixtopic_smart $chan
  if (%mc_agent_replacemirc == yes && %mc_agent_speakevents == yes) /mc_msagent dummy dummy other $knick was kicked from $chan by $nick
}

on *:CONNECT: {
  if (%mc_agent_replacemirc == yes && %mc_agent_speakevents == yes) /mc_msagent dummy dummy other Connected to server $server with nickname $nick
}

on *:DISCONNECT: {
  if (%mc_agent_replacemirc == yes && %mc_agent_speakevents == yes) /mc_msagent dummy dummy other Disconnected from server $server
  ; LOGfile add SESSION CLOSE tags to all files we modified
  mc_logaddendsessions
}

on *:NOTIFY: {
  if (%mc_agent_replacemirc == yes && %mc_agent_speakevents == yes) /mc_msagent dummy dummy other NOTICE: $nick has connected to irc
}

on *:UNOTIFY: {
  if (%mc_agent_replacemirc == yes && %mc_agent_speakevents == yes) /mc_msagent dummy dummy other NOTICE: $nick has disconnected from irc
}


; private $nick events.
on *:OPEN:?:*: {
  if ($dll( %mc_scriptdll  , mc_iskeyunlocked , $nick) == yes) .mcfixtopic_smart $nick
  else var %dummy = $dll( %mc_scriptdll , mc_encrypt , $nick dummytext )
  mc_updatewinbackground $nick
}

on *:OPEN:=: {
  if ($dll( %mc_scriptdll  , mc_iskeyunlocked , $nick) == yes) .mcfixtopic_smart = $+ $nick
  else var %dummy = $dll( %mc_scriptdll , mc_encrypt , $nick dummytext )
  mc_updatewinbackground $nick
}


; channel $chan events.
on *:MODE:*: if ($dll( %mc_scriptdll  , mc_iskeyunlocked , $chan) == yes) .mcfixtopic_smart $chan
on *:SERVERMODE:*: if ($dll( %mc_scriptdll  , mc_iskeyunlocked , $chan) == yes) .mcfixtopic_smart $chan

; logging rawmode
on *:rawmode:#:{
  var %retv = $mc_logparse(mode,$target,$nick,$address,$1-,$false)
  if ($mchandlehalt() == $true) return %retv
  return %retv
}

; logging server messages
on *:snotice:*: {
  var %retv = $mc_logparse(snotice,$server,$server,$1-,$address,$false)
  if ($mchandlehalt() == $true) return %retv
  return %retv
}

; logging errors
on *:ERROR:*: {
  var %retv = $mc_logparse(snotice,$server,$server,$1-,$address,$false)  
  if ($mchandlehalt() == $true) return %retv
  return %retv
}
; ---------------------------------------------------------------------------



; ---------------------------------------------------------------------------
; topic fixups


alias mcfixtopic_smart {
  ; change topic fix and a delayed one as well to make sure mirc finished with its own update first
  var %cname

  if ($1 == $null) %cname = $chan
  else %cname = $1
  /mcfixtopic %cname
  .timer $+ [ MCFIXTOPIC $+ [ %cname ] ] 1 1 mcfixtopic %cname
}

alias mcfixalltopics {
  ; here we need to go through ALL windows and fix up their titlebars
  ; this can happen if user suddenly enters a valid masterpass after failing to in begining,
  ; or other mirc events that redraw all windows without individually triggering events on individual channels
  ; $1 will be set to periodic if this is a timer triggered fix

  ; /echo -s DEBUGGING REFRESHING TOPICS

  var %querycount | %querycount = $query(0)
  var %chatcount | %chatcount = $chat(0)
  var %ccount = 1
  while ($chan(%ccount) != $null) {
    /mcfixtopic $chan(%ccount)
    if ($1 != periodic) mc_updatewinbackground $chan(%ccount)
    inc %ccount
  }
  %ccount = 1
  while (%ccount <= %chatcount) {
    /mcfixtopic = $+ $chat(%ccount)
    if ($1 != periodic) mc_updatewinbackground $chat(%ccount)
    inc %ccount
  }
  %ccount = 1
  while (%ccount <= %querycount) {
    /mcfixtopic $query(%ccount)
    if ($1 != periodic) mc_updatewinbackground $query(%ccount)
    inc %ccount
  }
}

alias mcfixalltopics2 {
  ; here we need to go through ALL windows and fix up their titlebars
  ; this can happen if user suddenly enters a valid masterpass after failing to in begining,
  ; or other mirc events that redraw all windows without individually triggering events on individual channels
  var %querycount | %querycount = $query(0)
  var %chatcount | %chatcount = $chat(0)
  var %ccount = 1
  while ($chan(%ccount) != $null) {
    /mcfixtopic_smart $chan(%ccount)
    inc %ccount
  }
  %ccount = 1
  while (%ccount <= %chatcount) {
    /mcfixtopic_smart = $+ $chat(%ccount)
    inc %ccount
  }
  %ccount = 1
  while (%ccount <= %querycount) {
    /mcfixtopic_smart $query(%ccount)
    inc %ccount
  }
}


; decrypt an encrypted topic
alias mcfixtopic {
  var %m
  var %cname
  if ($1 == $null) %cname = $chan
  else %cname = $1
  var %ename


  if (%cname == $null) return
  %ename = $chatchan(%cname)
  ; echo DEBUGGING fixing up channel name is %cname ename is %ename

  if (%mc_dontfixtitlebars == yes) {
    ; let users disable this if they have slow machines and dont use/like encrypted topics or titlebar fixing
    .setmctimers2 
    return
  }


  %m = $chan(%cname).topic
  var %om = %m

  ; %mf = $token(1, 32, %m) - cant get this to work for some reason
  ;  var %pos | %pos = $pos(%m , $chr(32))
  ;  var %remlen | %remlen = $len(%m) - %pos
  ;  %mf = $left(%m , %pos)
  ;  var %mn | %mn = $right(%m , %remlen)

  ; /echo -s TEST fixing topic for channel %cname is %m and %mn

  if ($mc_isetag3(%m)) {
    ; old method
    ; %m = $dll( %mc_scriptdll  , mc_decrypt , %ename %mn)
    ; new method
    %m = $dll( %mc_scriptdll  , mc_decrypt2 , %ename %om)
    ; substitute multispaces with space preserving $160 ?
    %m = $mcmultispacefix(%m)
    ;copy decrypted text to channel
    if (%m != %om && %m != $null) {
      %m = %mc_pretopic %m
      %m = $strip(%m)
      .dll %mc_scriptdll mc_forcetopic $window(%cname).hwnd $dll( %mc_scriptdll ,mc_isencrypting , %ename) %m
      if ($2 == speak) .echo $colour(topic text) -i2 %cname *** Topic decrypted as ' $+ %m $+ '
    }
    else {
      %m = $strip(%m)
      ; maybe we shouldnt touch topic if it is not crypted?
      .dll %mc_scriptdll mc_forcetopic $window(%cname).hwnd $dll( %mc_scriptdll ,mc_isencrypting , %ename) %m
    }
  }
  else {
    ;    %m = TST: $+ %m
    ;    echo virgin topic is ' $+ $chan(%cname).topic $+ '
    ;    echo unstripped topic is ' $+ %m $+ '
    %m = $strip(%m)
    ;    echo stripped topic is ' $+ %m $+ '
    ; echo blank for %cname, m is %m encrypting is [ $dll( %mc_scriptdll ,mc_isencrypting , %ename) ]
    .dll %mc_scriptdll mc_forcetopic $window(%cname).hwnd $dll( %mc_scriptdll ,mc_isencrypting , %ename) %m
  }

  ; reset timers - there seems to be a bug in mirc 6.0x where the timers are not being called any longer
  .setmctimers2 
}
; ---------------------------------------------------------------------------



; ---------------------------------------------------------------------------
; a watcher function - for updating window titlebars if a new window is opened
;  this is nescesary because mirc is braindead when it comes to some events
;  and there appears to be no way to trigger an event if you yourself open
;  a query window, for example

alias mc_windowchangewatch {
  var %curwincount | %curwincount = $chan(0)
  var %querycount | %querycount = $query(0)
  var %chatcount | %chatcount = $chat(0)
  var %ccount

  if ( %curwincount > %mc_curwincount) {
    %ccount = 1
    while (%ccount <= %curwincount) {
      /mcfixtopic $chan(%ccount)
      inc %ccount
    }
  }
  %mc_curwincount = %curwincount

  if ( %querycount > %mc_querycount ) {
    %ccount = 1
    while (%ccount <= %querycount) {
      /mcfixtopic $query(%ccount)
      inc %ccount
    }
  }
  %mc_querycount = %querycount

  if ( %chatcount > %mc_chatcount ) {
    %ccount = 1
    while (%ccount <= %chatcount) {
      /mcfixtopic = $+ $chat(%ccount)
      inc %ccount
    }
  }
  %mc_chatcount = %chatcount
}
; ---------------------------------------------------------------------------



; ---------------------------------------------------------------------------
on *:EXIT:{
  ; LOGfile add SESSION CLOSE tags to all files we modified
  mc_logaddendsessions
}

on *:UNLOAD:{
  ; LOGfile add SESSION CLOSE tags to all files we modified
  mc_logaddendsessions
}
; ---------------------------------------------------------------------------



; ---------------------------------------------------------------------------
; save last topic change details - this is nesc. since topic does not pass speaker
raw 333:*: {
  %mc_lasttopic_author = $3
  %mc_lasttopic_time = $asctime($4,ddd mmm d h:nn:ss)
}

; server info we might want to grab
raw 5:*: {
  ; look for the field ' TOPICLEN=# ' and set topiclength with it, if found
  if (%mc_maxtopiclenautograb == yes) {
    var %topiclenstr = $matchtok($1-, TOPICLEN=, 1, 32)
    if (%topiclenstr != $null) {
      ; grab just length after = sign
      %topiclenstr = $gettok(%topiclenstr,2,61)
      if (%topiclenstr != $null) {
        ; set global topiclen setting
        %mc_maxtopiclen = %topiclenstr
      }
    }
  }
}

; ---------------------------------------------------------------------------





; ---------------------------------------------------------------------------
; we have an option to see when users change nicks and migrate keys for them

on *:NICK: {
  ; log it if appropriate
  var %c = 1
  var %tempvar

  while ($comchan($newnick,%c)) {
    %tempvar = $mc_logparse(nick,$ifmatch,$nick,$address,$newnick,$false)
    inc %c
  }
  if ($mchandlehalt() == $true) return

  var %nname = $chatchan($nick)
  var %cname = $chatchan($chan)
  var %newnname = $chatchan($newnick)


  if ($dll( %mc_scriptdll  , mc_iskeyunlocked , %cname) == yes) /mcfixtopic_smart $chan
  if (%mc_agent_replacemirc == yes && %mc_agent_speakevents == yes) /mc_msagent dummy dummy other $nick is now known as $newnick

  ; if option is set and we find a specific key for a private query for a users OLD nick, then if they change nick, we add key to the new nick
  if (%mc_tracknicks == no) return

  ; the private mode of tracknicks will ignore nick changes except in private queries or chats
  if (%mc_tracknicks == private && $mc_chanexists(%newnname) == $false) return


  var %oldnickkey | %oldnickkey = $dll( %mc_scriptdll  , mc_displaykey , %nname )
  ; does there exist a key for the oldnick?  if not, then return since nothing to do
  if ( %oldnickkey == $null ) return


  ; NEW 1/6/06 - do nothing if old key is disabled
  var %isencrypting = $dll( %mc_scriptdll  , mc_isencrypting, %nname )
  if (%isencrypting != yes) return;


  var %newnickkey | %newnickkey = $dll( %mc_scriptdll  , mc_displaykey , %newnname )
  ; does the proper key already exist for new nick? if so just return
  if ( %newnickkey != $null && %newnickkey == %oldnickkey) {
    ; attempt to bleach variable from memory
    %oldnickkey = $str(x , [ $len(%oldnickkey ) ] )
    %newnickkey = $str(x , [ $len(%newnickkey ) ] )
    return
  }

  ; does a dif key already exist for new nick? if so, warn and return
  if ( (%newnickkey != $null && %newnickkey != %oldnickkey) && (%mc_tracknicks_replace != yes) ) {
    echo 4 -s $nick is now known as $newnick but current mircryption key conflicts with old one.
    ; attempt to bleach variable from memory
    %oldnickkey = $str(x , [ $len(%oldnickkey ) ] )
    %newnickkey = $str(x , [ $len(%newnickkey ) ] )
    return
  }

  .dll %mc_scriptdll mc_setkey %newnname %oldnickkey
  echo 4 -s Private mircryption passphrase for $nick has been migrated to $newnick
  %oldnickkey = $str(x , [ $len(%oldnickkey ) ] )
  %newnickkey = $str(x , [ $len(%newnickkey ) ] )
}
; ---------------------------------------------------------------------------








; ---------------------------------------------------------------------------
; Added v1.0b7 - block ctcp time/version requests
; we now STOP replying to ALL ctcp message and dont reply at all to them

ctcp *:ping:*: {
  ; put a ; in front of the /ctcpreply command below to stop your mirc from sending any reply at all to this ctcp
  ;/ctcpreply $nick PING - STOP trying to spy me!
  if (%mc_blockctcp_ping == no) return
  /haltdef
  /halt
}

ctcp *:time:*: {
  ; put a ; in front of the /ctcpreply command below to stop your mirc from sending any reply at all to this ctcp
  ;/ctcpreply $nick TIME - STOP trying to spy me!
  if (%mc_blockctcp == no) return
  /haltdef
  /halt
}

ctcp *:version:*: {
  ; actually version info seems to get sent anyway, contrary to our halt
  ; unless you apply the patch to mirc to block it; see extras directory of mircryption install for a patcher.
  ; .notice $me Received CTCP VERSION from $nick $+ / $+ $site
  ; /ctcpreply $nick VERSION mIRC XP - eXtreme Paranoia Edition w/ mircryption
  if (%mc_blockctcp == no) return
  /haltdef
  /halt
}

ctcp *:userinfo:*: {
  ; does this ctcp even exist?
  ; put a ; in front of the /ctcpreply command below to stop your mirc from sending any reply at all to this ctcp
  ;/ctcpreply $nick USERINFO - Do not even think about it!
  if (%mc_blockctcp == no) return
  /haltdef
  /halt
}

ctcp *:finger:*: {
  ; does this ctcp even exist?
  ; put a ; in front of the /ctcpreply command below to stop your mirc from sending any reply at all to this ctcp
  ;/ctcpreply $nick FINGER - STOP trying to spy me!
  if (%mc_blockctcp == no) return
  /haltdef
  /halt
}
; ---------------------------------------------------------------------------
























; ---------------------------------------------------------------------------
; text formatting stuff

alias mcscheme {
  ; set color/indent scheme presets
  ; allow the user to select from multiple colouring/identification schemes
  if ( $1 != $null ) {
    %mc_scheme = $1
    echo -s mircryption using display theme $1
  }
  if ( %mc_scheme == $null ) %mc_scheme = 1

  ; colors - these are shorthands used in indicator customization below - they default to current irc settings.
  ;          customize to your pleasure, but keep in mind that if you use hardcoded numbers, things may look
  ;          wierd if you change your mirc color scheme.  this command is called on startup or you can call it
  ;          if you change mirc colors while mirc is running.

  ; default colors
  %mc_defaulttext_color = $colour(normal text)
  %mc_dulltext_color = $colour(notice text)
  %mc_action_color = $colour(action text)
  %mc_info_color = $colour(info text)

  ; null out other optional settings so we can detect which have values at end
  %mc_prenick_encrypt_op = $null
  %mc_postnick_encrypt_op = $null
  %mc_prenick_decrypt_op = $null
  %mc_postnick_decrypt_op = $null
  %mc_prenick_encrypt_voice = $null
  %mc_postnick_encrypt_voice = $null
  %mc_prenick_decrypt_voice = $null
  %mc_postnick_decrypt_voice = $null
  %mc_prenick_encrypt_halfop = $null
  %mc_postnick_encrypt_halfop = $null
  %mc_prenick_decrypt_halfop = $null
  %mc_postnick_decrypt_halfop = $null
  %mc_prenick_encrypt_notice = $null
  %mc_postnick_encrypt_notice = $null
  %mc_prenick_decrypt_notice = $null
  %mc_postnick_decrypt_notice = $null

  ; optional news coloring theme
  %mc_theme_news_header = $null
  %mc_theme_news_footer = $null
  %mc_theme_news_presectionheader = $null
  %mc_theme_news_postsectionheader = $null
  %mc_theme_news_presectiontitle = $null
  %mc_theme_news_postsectiontitle = $null
  %mc_theme_news_prenick = $null
  %mc_theme_news_postnick = $null
  %mc_theme_news_preitemnum = $null
  %mc_theme_news_postitemnum = $null
  %mc_theme_news_preauthor = $null
  %mc_theme_news_other = $null

  if ( %mc_scheme == 1 ) {
    ; SCHEME 1 uses brackets around text that is encrypted or decrypted, and + for encrypted/decrypted actions
    ;  very unobtrusive but may be easier to forget if you are encrypted or no
    %mc_prenick_encrypt = [
    %mc_postnick_encrypt = ]
    %mc_prenick_decrypt = [
    %mc_postnick_decrypt = ]
    %mc_preaction_encrypt =   $+ %mc_action_color $+ [*]
    %mc_preaction_decrypt =   $+ %mc_action_color $+ [*]
    %mc_pretopic = (e) 
  }
  else if (%mc_scheme == 2) {
    ; SCHEME 2 prepends a gray e or d to indicate whether text is encrypted or decryted
    %mc_prenick_encrypt =  $+ %mc_dulltext_color $+ e $+  $+ $colour(own text) $+ <
    %mc_postnick_encrypt = >
    %mc_prenick_decrypt =  $+ %mc_dulltext_color $+ d $+  $+ %mc_defaulttext_color $+ <
    %mc_postnick_decrypt = >
    %mc_preaction_encrypt =  $+ %mc_dulltext_color $+ e $+  $+ $colour(own text) $+ *
    %mc_preaction_decrypt =  $+ %mc_dulltext_color $+ d $+  $+ %mc_action_color $+ *
    %mc_pretopic = (e)
  }
  else if (%mc_scheme == 3) {
    ; scheme 3 written by L (3/3/02)
    %mc_prenick_encrypt =  $+ $colour(own text)
    %mc_postnick_encrypt = 12 ->> 
    %mc_prenick_encrypt_op = 5 $+ $chr(64) $+  $+ $colour(own text)
    %mc_prenick_encrypt_voice = 12 $+ $chr(43) $+  $+ $colour(own text)
    %mc_prenick_decrypt =  $+ %mc_defaulttext_color
    %mc_prenick_decrypt_op = 5 $+ $chr(64) $+  $+ %mc_defaulttext_color
    %mc_prenick_decrypt_voice = 12 $+ $chr(43) $+  $+ %mc_defaulttext_color
    %mc_postnick_decrypt = 3 ->> 
    %mc_preaction_encrypt =  $+ %mc_dulltext_color $+ e $+  $+ $colour(own text) $+ *
    %mc_preaction_decrypt =  $+ %mc_dulltext_color $+ d $+  $+ %mc_action_color $+ *
    %mc_pretopic = (e)
  }
  else if (%mc_scheme == 4) {
    ; scheme 4 written by Clown (18/01/03)
    ; color mod by hadez (18/01/03)
    %mc_prenick_encrypt = 2[
    %mc_prenick_encrypt_op = 2[ $+ $chr(64)
    %mc_prenick_encrypt_halfop = 2[ $+ $chr(37)
    %mc_prenick_encrypt_voice = 2[ $+ $chr(43)
    %mc_postnick_encrypt = 2]
    %mc_prenick_decrypt = 12[
    %mc_prenick_decrypt_op = 12[ $+ $chr(64)
    %mc_prenick_decrypt_halfop = 12[ $+ $chr(37)
    %mc_prenick_decrypt_voice = 12[ $+ $chr(43)
    %mc_postnick_decrypt = 12]
    %mc_preaction_encrypt = 12[+] $+ %mc_action_color
    %mc_preaction_decrypt = 2[+] $+ %mc_action_color
    %mc_pretopic = (e) 
  }
  else if (%mc_scheme == 5) {
    ; scheme 5 written by Clown/hadez (18/01/03)
    ; color mod by hadez (18/01/03)
    %mc_hdz_colde = 3
    %mc_hdz_colen = 9
    %mc_prenick_encrypt = [ %mc_hdz_colen ] $+ e[
    %mc_prenick_encrypt_op = [ %mc_hdz_colen ] $+ e[ $+ $chr(64)
    %mc_prenick_encrypt_halfop = [ %mc_hdz_colen ] $+ e[ $+ $chr(37)
    %mc_prenick_encrypt_voice = [ %mc_hdz_colen ] $+ e[ $+ $chr(43)
    %mc_postnick_encrypt = [ %mc_hdz_colen ] $+ ]
    %mc_prenick_decrypt = [ %mc_hdz_colde ] $+ d[
    %mc_prenick_decrypt_op = [ %mc_hdz_colde ] $+ d[ $+ $chr(64)
    %mc_prenick_decrypt_halfop = [ %mc_hdz_colde ] $+ d[ $+ $chr(37)
    %mc_prenick_decrypt_voice = [ %mc_hdz_colde ] $+ d[ $+ $chr(43)
    %mc_postnick_decrypt = [ %mc_hdz_colde ] $+ ]
    %mc_preaction_encrypt = [ %mc_hdz_colen ] $+ e+ $+ %mc_action_color
    %mc_preaction_decrypt = [ %mc_hdz_colde ] $+ d+ $+ %mc_action_color
    %mc_pretopic = (e)
    %mc_theme_news_header = 09(NEWS09) ----------------------------------------
    %mc_theme_news_footer = -----------------------------------------------
    %mc_theme_news_prenick = 09[
    %mc_theme_news_postnick = 09]
    %mc_theme_news_presectionheader = 09[
    %mc_theme_news_postsectionheader = 09]
    %mc_theme_news_presectiontitle = $chr(32) $+ 15
    %mc_theme_news_postsectiontitle = $chr(32) $+ 14
    %mc_theme_news_preitemnum = 15#
    %mc_theme_news_postitemnum = 09 $chr(34)
    %mc_theme_news_preauthor = $chr(34) $+ 15 $+ $chr(160)
    %mc_theme_news_other = 09
  }
  else if ( %mc_scheme == 6 ) {
    ; SCHEME 1 uses brackets around text that is encrypted or decrypted, and + for encrypted/decrypted actions
    ;  very unobtrusive but may be easier to forget if you are encrypted or no
    %mc_prenick_encrypt = [
    %mc_postnick_encrypt = ]
    %mc_prenick_decrypt = [
    %mc_postnick_decrypt = ]
    %mc_prenick_encrypt_op = [ $+ $chr(64)
    %mc_prenick_encrypt_halfop = [ $+ $chr(37)
    %mc_prenick_encrypt_voice = [ $+ $chr(43)
    %mc_prenick_decrypt_op = [ $+ $chr(64)
    %mc_prenick_decrypt_halfop = [ $+ $chr(37)
    %mc_prenick_decrypt_voice = [ $+ $chr(43)
    %mc_preaction_encrypt =   $+ %mc_action_color $+ [*]
    %mc_preaction_decrypt =   $+ %mc_action_color $+ [*]
    %mc_pretopic = (e) 
    ; color news
    %mc_theme_news_header = 2 $+ -=3NEWS2=----------------------------------------
    %mc_theme_news_footer = 2 $+ -----------------------------------------------
    %mc_theme_news_prenick =  $+ %mc_defaulttext_color $+ [
    %mc_theme_news_postnick = ]5
    %mc_theme_news_presectionheader =  $+ %mc_defaulttext_color $+ [ $+ 2
    %mc_theme_news_postsectionheader =  $+ %mc_defaulttext_color $+ ]
    %mc_theme_news_presectiontitle = $chr(32) $+ - 2
    %mc_theme_news_postsectiontitle = $chr(32) $+ -2 $+ $chr(160)
    ;%mc_theme_news_preitemnum = 2[
    ;%mc_theme_news_postitemnum = ]  $+ %mc_defaulttext_color $+ $chr(34)
    %mc_theme_news_preitemnum = $null
    %mc_theme_news_postitemnum = . $chr(34)
    %mc_theme_news_preauthor = $chr(34) $+ 15 $+ $chr(32) - $+ $chr(160)
    %mc_theme_news_other = 5
  }
  else if (%mc_scheme == 7) {
    ; scheme 7 written by Clown/hadez/Meko (02/11/03)
    ; color mod by Meko (02/11/03)
    %mc_hdz_colde = 3
    %mc_hdz_colen = 9
    %mc_prenick_encrypt = [ %mc_hdz_colen ] $+ e[ $+ 
    %mc_prenick_encrypt_op = [ %mc_hdz_colen ] $+ e[ $+ 4 $+ $chr(64)
    %mc_prenick_encrypt_halfop = [ %mc_hdz_colen ] $+ e[ $+ 7 $+ $chr(37)
    %mc_prenick_encrypt_voice = [ %mc_hdz_colen ] $+ e[ $+ 6 $+ $chr(43)
    %mc_postnick_encrypt = [ %mc_hdz_colen ] $+ ]
    %mc_prenick_decrypt = [ %mc_hdz_colde ] $+ d[ $+ 
    %mc_prenick_decrypt_op = [ %mc_hdz_colde ] $+ d[ $+ 4 $+ $chr(64)
    %mc_prenick_decrypt_halfop = [ %mc_hdz_colde ] $+ d[ $+ 7 $+ $chr(37)
    %mc_prenick_decrypt_voice = [ %mc_hdz_colde ] $+ d[ $+ 6 $+ $chr(43)
    %mc_postnick_decrypt = [ %mc_hdz_colde ] $+ ]
    %mc_preaction_encrypt = [ %mc_hdz_colen ] $+ e+ $+ %mc_action_color
    %mc_preaction_decrypt = [ %mc_hdz_colde ] $+ d+ $+ %mc_action_color
    %mc_pretopic = (e)
    %mc_theme_news_header = 09(NEWS09) ----------------------------------------
    %mc_theme_news_footer = -----------------------------------------------
    %mc_theme_news_prenick = 09[
    %mc_theme_news_postnick = 09]
    %mc_theme_news_presectionheader = 09[
    %mc_theme_news_postsectionheader = 09]
    %mc_theme_news_presectiontitle = $chr(32) $+ 15
    %mc_theme_news_postsectiontitle = $chr(32) $+ 14
    %mc_theme_news_preitemnum = 15#
    %mc_theme_news_postitemnum = 09 $chr(34)
    %mc_theme_news_preauthor = $chr(34) $+ 15 $+ $chr(160)
    %mc_theme_news_other = 09
  }

  ; defaults for most cases, where a scheme does not do special stuff if the user is op or voiced
  if (%mc_prenick_encrypt_op == $null) %mc_prenick_encrypt_op = %mc_prenick_encrypt
  if (%mc_postnick_encrypt_op == $null) %mc_postnick_encrypt_op = %mc_postnick_encrypt
  if (%mc_prenick_decrypt_op == $null) %mc_prenick_decrypt_op = %mc_prenick_decrypt
  if (%mc_postnick_decrypt_op == $null) %mc_postnick_decrypt_op = %mc_postnick_decrypt
  if (%mc_prenick_encrypt_voice == $null) %mc_prenick_encrypt_voice = %mc_prenick_encrypt
  if (%mc_postnick_encrypt_voice == $null) %mc_postnick_encrypt_voice = %mc_postnick_encrypt
  if (%mc_prenick_decrypt_voice == $null) %mc_prenick_decrypt_voice = %mc_prenick_decrypt
  if (%mc_postnick_decrypt_voice == $null) %mc_postnick_decrypt_voice = %mc_postnick_decrypt
  if (%mc_prenick_encrypt_halfop == $null) %mc_prenick_encrypt_halfop = %mc_prenick_encrypt
  if (%mc_postnick_encrypt_halfop == $null) %mc_postnick_encrypt_halfop = %mc_postnick_encrypt
  if (%mc_prenick_decrypt_halfop == $null) %mc_prenick_decrypt_halfop = %mc_prenick_decrypt
  if (%mc_postnick_decrypt_halfop == $null) %mc_postnick_decrypt_halfop = %mc_postnick_decrypt
  if (%mc_prenick_encrypt_notice == $null) %mc_prenick_encrypt_notice = [->]
  if (%mc_postnick_encrypt_notice == $null) %mc_postnick_encrypt_notice = $null
  if (%mc_prenick_decrypt_notice == $null) %mc_prenick_decrypt_notice = $null
  if (%mc_postnick_decrypt_notice == $null) %mc_postnick_decrypt_notice = [->]
  if (%mc_theme_news_header == $null) %mc_theme_news_header = -----------------------------------
  if (%mc_theme_news_footer == $null) %mc_theme_news_footer = -----------------------------------
  if (%mc_theme_news_prenick == $null) %mc_theme_news_prenick = %mc_prenick_encrypt
  if (%mc_theme_news_postnick == $null) %mc_theme_news_postnick = %mc_postnick_encrypt $+  $+ $colour(notice text)
  if (%mc_theme_news_presectionheader == $null) %mc_theme_news_presectionheader = [
  if (%mc_theme_news_postsectionheader == $null) %mc_theme_news_postsectionheader = ]
  if (%mc_theme_news_presectiontitle == $null) %mc_theme_news_presectiontitle = $chr(32) $+ - $chr(32)
  if (%mc_theme_news_postsectiontitle == $null) %mc_theme_news_postsectiontitle = $chr(32) $+ - $chr(32)
  if (%mc_theme_news_preitemnum == $null) %mc_theme_news_preitemnum = $null
  if (%mc_theme_news_postitemnum == $null) %mc_theme_news_postitemnum = . $+ $chr(32) $+ $chr(34)
  if (%mc_theme_news_preauthor == $null) %mc_theme_news_preauthor = $chr(34) $+ $chr(32) - $+ $chr(160)
  if (%mc_theme_news_other == $null) %mc_theme_news_other =  $+ $colour(notice text)
}


alias prespopt2 {
  ; helper functions for nice indenting
  var %plen
  if (%mc_indent == nick) %plen = $len($strip($1)) + 1
  else %plen = 0
  if (%mc_indentplus != $null) %plen = %plen + %mc_indentplus

  return -tni $+ %plen
}

alias prespopt3 {
  ; helper functions for nice indenting
  var %plen
  if (%mc_indent == nick) %plen = $len($strip($1)) + 1
  else %plen = 0
  if (%mc_indentplus != $null) %plen = %plen + %mc_indentplus

  return -lbfmti $+ %plen
}

alias prespopt4 {
  ; helper functions for nice indenting
  var %plen
  %plen = $len($strip($1)) + 4
  return -lbfmti $+ %plen
}

alias prespopt_NoHighlight {
  ; helper functions for nice indenting
  var %plen
  if (%mc_indent == nick) %plen = $len($strip($1)) + 1
  else %plen = 0
  if (%mc_indentplus != $null) %plen = %plen + %mc_indentplus

  return -mti $+ %plen
}

alias prenickify_encrypt {
  ; helper function which applies the scheme formatting to your nick when you send outgoing text
  ; called with $1 = channel you are sending to
  var %formattednick

  var %CNICK
  var %CNORMAL
  var %nickcolornum = $mc_nickcolornum($1,$me)
  if (%nickcolornum != $colour(own text) && %nickcolornum != $null && %mc_disablenickcolor != yes && %mc_enablenickcolorown == yes) {
    ; we no longer color our own nick, no matter what
    ;%CNICK = $null
    ;%CNORMAL = $null
    %CNICK =  $+ %nickcolornum
    %CNORMAL =  $+ $colour(own text)
  }
  else {
    %CNICK = $null
    %CNORMAL = $null
  }

  ; now we can format differently depending if user is op/voice on the outgoing channel
  if ($me isop $1) %formattednick = %mc_prenick_encrypt_op $+ %CNICK $+ $me $+ %CNORMAL $+ %mc_postnick_encrypt_op
  else if ($me ishop $1) %formattednick = %mc_prenick_encrypt_halfop $+ %CNICK $+ $me $+ %CNORMAL $+ %mc_postnick_encrypt_halfop
  else if ($me isvo $1) %formattednick = %mc_prenick_encrypt_voice $+ %CNICK $+ $me $+ %CNORMAL $+ %mc_postnick_encrypt_voice
  else %formattednick = %mc_prenick_encrypt $+ %CNICK $+ $me $+ %CNORMAL $+ %mc_postnick_encrypt
  return %formattednick
}

alias prenickify_decrypt {
  ; helper function which applies the scheme formatting to an incoming nick when you receive encrypted text
  ; called with $1 = channel text was received on and $2 = nick of person
  var %formattednick
  ; now we can format differently depending if nick is op/voice on the incoming channel

  var %CNICK
  var %CNORMAL
  var %nickcolornum = $mc_nickcolornum($1,$2)
  if (%nickcolornum != $colour(normal text) && %nickcolornum != $null && %mc_disablenickcolor != yes) {
    %CNICK =  $+ %nickcolornum
    %CNORMAL =  $+ $colour(normal text)
  }
  else {
    %CNICK = $null
    %CNORMAL = $null
  }

  if ($2 isop $1) %formattednick = %mc_prenick_decrypt_op $+ %CNICK $+ $2 $+ %CNORMAL $+ %mc_postnick_decrypt_op
  else if ($2 isvo $1) %formattednick = %mc_prenick_decrypt_voice $+ %CNICK $+ $2 $+ %CNORMAL $+ %mc_postnick_decrypt_voice
  else if ($2 ishop $1) %formattednick = %mc_prenick_decrypt_halfop $+ %CNICK $+ $2 $+ %CNORMAL $+ %mc_postnick_decrypt_halfop
  else %formattednick = %mc_prenick_decrypt $+ %CNICK $+ $2 $+ %CNORMAL $+ %mc_postnick_decrypt

  return %formattednick
}


alias mc_nickcolornum {
  ; return color nick should be shown as
  ; $1 is chan/win  $2 is nick
  var %colornum

  ; simplest way (supports per-nick coloring from addressbook but not permode/peridle)
  ; %colornum = $cnick($2).color

  ; smarter way
  %colornum = $nick($1,$2).color

  ; do we have to do something different for own nick ($me)
  ; echo -s COLORNUM1 = %colornum ( $1 , $2 ) = $colour(normal text) = $colour(own text)

  ; default to nick color not based on channel? this may be unnescesary and inappropriate for own nick?
  ;  if (%colornum == $null) %colornum = $cnick($2).color

  ; return it
  return %colornum
}


alias mc_applytheme {
  ; helper function which is currently only used to color the news replies
  var %applytheme = $1
  var %mtext = $2-
  var %p1
  var %p1b
  var %p2
  var %p3
  var %firstchar = $left(%mtext,1)
  if (%applytheme == news) {
    ; echo DEBUG processing news line $1-
    if ($left(%mtext,4) == ----) {
      ; just the -----... top and bottom header
      if ($right(%mtext,1) == $chr(160)) %mtext = %mc_theme_news_footer
      else %mtext = %mc_theme_news_header
    }
    else if ($left(%mtext,1) == [) {
      ; section start (sectionname, sectiontitle, totalnum, newnum)
      var %sectionname
      var %sectiontitle
      var %postcount
      ; grab section name
      %p1 = $pos(%mtext,],1)
      %p1 = %p1 - 2
      %sectionname = $mid(%mtext,2, %p1 )
      ; grab title
      %p1 = %p1 + 6
      %p2 = $pos(%mtext,-,0)
      %p2 = $pos(%mtext,-,%p2)
      %p3 = %p2 - %p1
      %p3 = %p3 - 1
      %sectiontitle = $mid(%mtext, %p1 , %p3)
      ; grab postcount
      %p2 = %p2 + 2
      %p3 = $len(%mtext) - %p2
      %p3 = %p3 + 1
      %postcount = $mid(%mtext,%p2,%p3)
      ; now form text
      ;echo sectionname = ' $+ %sectionname $+ ' and sectiontitle = ' $+ %sectiontitle $+ ' and postcount = ' $+ %postcount $+ '
      %mtext = %mc_theme_news_presectionheader $+ %sectionname $+ %mc_theme_news_postsectionheader $+ %mc_theme_news_presectiontitle $+ %sectiontitle $+ %mc_theme_news_postsectiontitle $+ %postcount
    }
    else if ( %firstchar isnum ) {
      ; item number followed by item text (number, newflag, text, author, date)
      var %itemnum
      var %newflag
      var %itemtext
      var %itemauthordate
      ; grab item num
      %p1 = $pos(%mtext,.,1)
      %p1b = $pos(%mtext,*,1)
      if ( (%p1 == $null) || ( (%p1b != $null) && (%p1b > 0) && ((%p1b < %p1) || (%p1 == $null)) )) {
        ; sometimes a * is used instead of . for new news
        %p1 = %p1b
      }

      if ((%p1 == $null) || (%p1 < 1) || (%p1 > 6)) {
        ; bug - this isnt really an item
        %mtext = %mc_theme_news_other $+ %mtext
        return
      }
      %p1 = %p1 - 1
      %itemnum = $mid(%mtext,1, %p1 )
      ; grab item text
      %p1 = %p1 + 4
      %p2 = $pos(%mtext, - , 0)
      %p2 = $pos(%mtext, - , %p2)
      %p2 = %p2 - 2
      %p3 = %p2 - %p1
      %itemtext = $mid(%mtext, %p1, %p3)
      ; grab authour and date
      %p2 = %p2 + 4
      %p3 = $len(%mtext) - %p2
      %p3 = %p3 + 1
      %itemauthordate = $mid(%mtext,%p2,%p3)
      ; now form text
      ; echo DEBUG itemnum = ' $+ %itemnum $+ ' and newflag = ' $+ %newflag $+ ' and itemtext = ' $+ %itemtext $+ ' and itemauthordate = ' $+ %itemauthordate $+ ' .
      %mtext = %mc_theme_news_preitemnum $+ %itemnum $+ %mc_theme_news_postitemnum $+ %itemtext $+ %mc_theme_news_preauthor $+ %itemauthordate 
    }
    else {
      ; other reply from news bot
      %mtext = %mc_theme_news_other $+ %mtext
    }
  }
  return %mtext
}


alias mc_debug {
  ; helper function for opening and closing debug windows
  if ($1 == on) {
    /debug -pt @MircDebugWindow
  }
  else if ($1 == onplus) {
    /debug -pt @MircDebugWindowPlus
  }
  else if ($2 == off) {
    /debug off
    /window -c @MircDebugWindow
    /window -c @MircDebugWindowPlus
  }
  else {
    if (($window(@MircDebugWindow).wid == $null) && ($window(@MircDebugWindowPlus).wid == $null) )  {
      /debug -pt @MircDebugWindow
    }
    else {
      /debug off
      /window -c @MircDebugWindow
      /window -c @MircDebugWindowPlus
    }
  }
}


alias mcetagchan {
  ; return the etag to use for channel (or pm target) $1
  ; usually we just return %mc_etag, but you could modify it if you wanted.
  var %rettag = %mc_etag
  var %chanetagvar = mc_etag_ $+ $1
  var %chanetag = [ % $+ [ %chanetagvar ] ]

  ; check for a variable with the name like this:  %mc_etag_CHAN (ie %mc_etag_#cppcoderzone)
  ; if one is found, use the value of that variable as the etag.\
  ; so for example to use a special etag of +OK for channel #blowcrypt you would put the following in your alt-R variables list:  %mc_etag_#blowcrypt +OK
  if (%chanetag != $null) %rettag = %chanetag

  ;echo DEBUG-> inside mcetagchan from chan $1 (chanetagvar = %chanetagvar , chanetag = %chanetag) returning etag = %rettag
  return %rettag
}


alias mcmultispacefix {
  ; mirc compresses multiple spaces, so after decrypting we replace them with $char(160) which looks like a space
  ;  or you can set a custom character in alt+r variables by setting %mc_multispacechar

  ; disabled
  if (%mc_multispacefix == "no") return $1-

  var %spacefind = $chr(32) $+ $chr(32)
  if ( ( $pos($1-,%spacefind,1 ) == $null ) && ( $mid($1,1,1) != $chr(32) ) ) return $1-
  var %m

  if (%mc_multispacechar == $null) {
    %m = $replace($1-,$chr(32),$chr(160))
  }
  else {
    %m = $replace($1-,$chr(32),%mc_multispacechar)

  }
  return %m
}
; ---------------------------------------------------------------------------






















; ---------------------------------------------------------------------------
; Accessory channel functions

; set (add or modify) keys.
;  "/setkey [channelname] passkeyphrase"  (if channelname not specified, current channel is used)
alias setkey {
  var %cname
  var %kname
  if ($1 == $null) {
    %cname = $active
  }
  else if ($2 == $null) {
    %cname = $1
  }
  else {
    %cname = $1
    %kname = $2-
  }
  var %wname = %cname
  %cname = $chatchan(%cname)

  if (%cname == Status Window) {
    echo 4 -s You cannot encrypt the status window. Em.. Why would you want to do that anyway?
    return
  }

  if (%kname == $null) {
    var %prevkey = $dll( %mc_scriptdll  , mc_displaykey , %cname)
    if (%prevkey != $null) %kname = $input(Use words and symbols (20-50 characters) and prefix with 'cbc:' to use new CBC mode:,1,Set new keyphrase for channel %cname,%prevkey)
    else %kname = $input(Use words and symbols (20-50 characters) and prefix with 'cbc:' to use new CBC mode:,1,Set new keyphrase for channel %cname)
    %prevkey = $str(x , [ $len(%prevkey ) ] )
    if (%kname == $null) return
  }

  var %retv | %retv = $dll( %mc_scriptdll  , mc_setkey , %cname %kname)
  if ((%retv != $null) && (%retv != %cname)) echo 4 -s %retv
  mcfixtopic_smart %wname
  %kname = $str(x , [ $len(%kname) ] )
  mc_updatewinbackground %wname
}


; addkey is same as setkey
alias addkey /setkey $1-


; delete key(s)
;  "/delkey [channelname]"  (if channelname not specified, current channel is used)
alias delkey {
  var %cname | %cname = $active
  if ($1 != $null) %cname = $1
  var %wname = %cname
  %cname = $chatchan(%cname)

  echo 4 -s $dll( %mc_scriptdll , mc_delkey, %cname)
  mcfixtopic_smart %wname
  mc_updatewinbackground %wname
}


; temporarily disable a key
alias disablekey {
  var %cname | %cname = $active
  if ($1 != $null) %cname = $1
  var %wname = %cname
  %cname = $chatchan(%cname)
  echo 4 -s $dll( %mc_scriptdll  , mc_disablekey , %cname)
  mcfixtopic_smart %wname
  mc_updatewinbackground %wname
}


; re-enable a temporarily disabled key
alias enablekey {
  var %cname | %cname = $active
  if ($1 != $null) %cname = $1
  var %wname = %cname
  %cname = $chatchan(%cname)
  echo 4 -s $dll( %mc_scriptdll  , mc_enablekey , %cname)
  mcfixtopic_smart %wname
  mc_updatewinbackground %wname
}


; toggle disabling/enabling of key, for fast shortcut
alias mctogglekey {
  var %cname | %cname = $active
  if ($1 != $null) %cname = $1
  var %wname = %cname
  %cname = $chatchan(%cname)
  if ($dll( %mc_scriptdll , mc_isencrypting , %cname) == yes) {
    echo 4 -s $dll( %mc_scriptdll  , mc_disablekey , %cname)
  }
  else {
    echo 4 -s $dll( %mc_scriptdll  , mc_enablekey , %cname)
  }
  mcfixtopic_smart %wname
  mc_updatewinbackground %wname
}


; display current key to the user
alias displaykey {
  var %cname | %cname = $active
  if ($1 != $null) %cname = $1
  %cname = $chatchan(%cname)
  var %keyval | %keyval = $dll( %mc_scriptdll  , mc_displaykey , %cname)
  if (%keyval == $null) echo mircryption key for %cname has not been set.
  else echo 4 -s mircryption key for %cname is ' $+ %keyval $+ '
  %keyval = $str(x , [ $len(%keyval ) ] )
}
; ---------------------------------------------------------------------------




; ---------------------------------------------------------------------------
; some commands to make it easier to migrate keys
alias migratenickkeys {
  var %ekey
  var %sourcechan = $chan
  var %nickname

  if (%sourcechan == $null) %sourcechan = $active
  %sourcechan = $chatchan(%sourcechan)

  ; get encryption key for source channel
  %ekey = $dll( %mc_scriptdll  , mc_displaykey , %sourcechan)
  if (%ekey == $null) {
    %sourcechan = $chr(35) $+ %sourcechan
    %ekey = $dll( %mc_scriptdll  , mc_displaykey , %sourcechan)
  }

  %ekey = $input(Set the mircryption passphrase for $1 nicks on channel %sourcechan to:,1,Set query-window passphrases for $1 nicks,%ekey)
  if (%ekey == $null) return

  ; now we loop through all nicks on channel %sourcechan and set the query passphrases
  var %ncount = $nick(%sourcechan,0)
  var %count = 1
  var %oldekey
  var %botnick = $null
  if ($gotmcboard) %botnick = $mcboard_getbotnick(%sourcechan)
  while (%count <= %ncount) {
    %nickname = $nick(%sourcechan,%count)
    if ((%nickname != $me) && (%nickname != $null) && (%nickname != %botnick)) {
      %nickname = $chatchan(%nickname)
      if ($1 == all) {
        %oldekey = $dll( %mc_scriptdll  , mc_displaykey , %nickname)
        if (%oldekey == %ekey) echo 4 Not setting keyphrase for %nickname since it's already set to that key.
        else /setkey %nickname %ekey 
      }
      else {
        %oldekey = $dll( %mc_scriptdll  , mc_displaykey , %nickname)
        if (%oldekey == $null) /setkey %nickname %ekey 
        else echo 4 Not setting keyphrase for %nickname since it has an existing value.
      }
    }
    else if (%nickname == %botnick) {
      echo 4 Not setting keyphrase for %nickname since it's the news board bot.
    }
    %count = %count + 1
  }
}

alias migratechankey {
  var %ekey
  var %sourcechan = $1
  var %targetchan = $chan

  if (%targetchan == $null) %targetchan = $active

  %targetchan = $chatchan(%targetchan)
  %sourcechan = $chatchan(%sourcechan)

  if (%sourcechan == $null) %sourcechan = $input(Set the mircryption passphrase for current channel to same passphrase as what channel (include the #):,1,Migrate passphrase from existing channel)
  if (%sourcechan == $null) return

  ; get encryption key for source channel
  %ekey = $dll( %mc_scriptdll  , mc_displaykey , %sourcechan)
  if (%ekey == $null) {
    %sourcechan = $chr(35) $+ %sourcechan
    %ekey = $dll( %mc_scriptdll  , mc_displaykey , %sourcechan)
  }
  if (%ekey == $null) {
    .echo 4 -t no mircryption keyphrase found for channel %sourcechan
    return
  }

  /setkey %targetchan %ekey 
}
; ---------------------------------------------------------------------------





; ---------------------------------------------------------------------------
; etopic activated through menu
alias etopic {
  var %m
  var %om

  var %ename
  var %ttext
  var %explicitchan

  ; get channel name if its specified and rest of text
  if ($left($1,1) == $chr(35)) {
    ; first word is channel name
    %ename = $1
    %ttext = $2-
    %explicitchan = $true
  }
  else {
    ; first word begins new text
    %ename = $chan
    %ttext = $1-
    %explicitchan = $false
  }

  if (%ttext == $null && %ename != $null && %explicitchan == $true) {
    ; user just specified an explicit channel but no text, so we just call to display the topic
    /topic %ename
    return
  }
  else if (%ename == $null) {
    ; if they specified just text and no channel name then set channel name to current channel
    %ename = $chan
  }

  var %test1 | %test1 = test text

  var %test2 | %test2 = $dll( %mc_scriptdll  , mc_encrypt2 , %ename %test1)
  if (%test2 == %test1 || %test2 == $null ) {
    ; we used to give an error if no key was set on etopic, but for script compatiblility and keeping with emsg and esay we now set normal topic
    if ( (%ttext == $null) || (%explicitchan == $false) ) {
      .echo 4 -t Encrypted topic cannot be set - you are not set to encrypt on this channel.
      return
    }
    /topic %ename %ttext
    return
  }


  if (%ttext == $null) {
    ; they havent specified anything so we ask them
    var %prevtopic | %prevtopic = $chan(%ename).topic
    if ( $mc_isetag3(%prevtopic) ) {
      %prevtopic = $dll( %mc_scriptdll  , mc_decrypt2 , %ename %prevtopic)
      ; substitute multispaces with space preserving $160 ?
      %prevtopic = $mcmultispacefix(%prevtopic)
    }
    if (%prevtopic == $null) %prevtopic = $chan(%ename).topic
    if (%prevtopic == $null) %om = $input($chan $+ :,1,Mircryption Encrypted Topic)
    else %om = $input($chan $+ :,1,Mircryption Encrypted Topic,%prevtopic)
    if (%om == $null) return
  }
  else %om = %ttext

  while ( $true ) {
    %m = %om

    ; new 7/22/05 - we try to use +OK prefix if appropriate
    var %etag = $mcetagchan(%ename)

    if (%etag == +OK) {
      ; encrypt message with old style
      %m = $dll( %mc_scriptdll  , mc_encrypt , %ename %om)
    }
    if (%etag != +OK) {
      ; encrypt message with new style
      %m = $dll( %mc_scriptdll  , mc_encrypt2 , %ename %om)
    }


    if ( $left(%m,17) == Mircryption_Error) {
      ; error encrypting output
      .echo 4 -t %m
      return
    }
    if ((%m == %om) || (%m == $null)) {
      .echo 4 -t Encrypted topic could not be set.
      return
    }

    ; new check for topic being too long
    if ( $len(%m) > %mc_maxtopiclen) {
      %om = $input(The encrypted topic you have set for $chan is probably too long and will likely be truncated by the irc server.  Please shorten it:,1,Warning - Mircryption Encrypted Topic is Too Long,%om)
      if (%om == $null) return
    }
    else .break
  }

  ; add prefix if old style encryption
  if (%etag == +OK) %m = +OK %m

  ; set topic
  .topic %ename %m

  ; we need to manually remember that we are the author of the last topic change, since raw 333 is not triggered on self topic change
  %mc_lasttopic_author = $me
  %mc_lasttopic_time = $asctime(ddd mmm d h:nn:ss)
}
; ---------------------------------------------------------------------------
























; ---------------------------------------------------------------------------
; Accesory keyfile functions

; set master passowrd for key file
;  "/keypassphrase passphrase"
alias keypassphrase {
  var %kname | %kname = $1-

  if (%kname == $null) %kname = ?
  echo 4 -s $dll( %mc_scriptdll , mc_setunlockpassphrase, %kname)
  /mcfixalltopics
}


;; dont let user pass unless they enter the correct passphrase
alias mc_requirepassphrase {
  var %reqk = ?
  while ( $dll( %mc_scriptdll  , mc_iskeyunlocked, dummy) != yes) {
    echo 4 -s $dll( %mc_scriptdll , mc_setunlockpassphrase, %reqk)
  }
  /mcfixalltopics
}


; display a list of keys
;  "/listkeys" (lists all stored keys)
alias listkeys {
  .dll %mc_scriptdll mc_listkeys , $active
}


; set the name of the file to be used for storing/retrieving keys
alias setkeyfile {
  .dll %mc_scriptdll mc_setkeyfile $1
  echo -s Mircryption using keyfile $1 $+ .
}
; ---------------------------------------------------------------------------


























; ---------------------------------------------------------------------------
; manual decryption/encrypting commands

; for bots&other scripts, aux. func to return encrypted or decrypted txt, as appropriate
; /mc_encrypt $channelname text...
alias mc_encrypt {
  if ($2- == $null) return $null
  if ($1 == $null) return $null
  var %m | %m = $dll( %mc_scriptdll  , mc_encrypt , $1 $2-)
  if (%m == $null) return $2-
  return %m
}


; for bots&other scripts, aux. func to return encrypted or decrypted txt, as appropriate
; /mc_decrypt $channelname text...
alias mc_decrypt {
  if ($1 == $null) return $null
  var %etext | %etext = $2-

  ;  if ( $mc_isetag(%etext) ) {
  ;    var %llen = $len(%etext) - 5
  ;    %etext = $right(%etext , %llen)
  ;  }

  if (%etext == $null) return $null
  var %m | %m = $dll( %mc_scriptdll  , mc_decrypt2 , $1 %etext)

  ; substitute multispaces with space preserving $160 ?
  %m = $mcmultispacefix(%m)

  if (%m == $null) return %etext
  return %m
}


alias decryptecho {
  ; when we move to the use of the new (crcable) tags in all messages it wont be necesary to be in the source channel, but for now it is
  if ( $1 == $null ) return
  var %resultstr
  var %cname = $active

  ; crypt it to current $active channel
  %resultstr = $dll( %mc_scriptdll  , mc_decrypt2 , %cname $1-)

  ; substitute multispaces with space preserving $160 ?
  %resultstr = $mcmultispacefix(%resultstr)

  if ((%resultstr == $null) || (%resultstr == $1-)) {
    ; initial decrypt failed, maybe they forgot the mcps?
    var %temptxt = mcps $1-
    %resultstr = $dll( %mc_scriptdll  , mc_decrypt2 , %cname %temptxt)
    ; substitute multispaces with space preserving $160 ?
    %resultstr = $mcmultispacefix(%resultstr)
  }
  if ((%resultstr == $null) || (%resultstr == $1-)) {
    .echo Text could not be decyrpted!
    return
  }

  else .echo Decrypted to: %resultstr
}



alias decryptechoc {
  ; when we move to the use of the new (crcable) tags in all messages it wont be necesary to be in the source channel, but for now it is
  ; $1 is channel nam
  if ( $2 == $null ) return
  var %resultstr
  var %cname = $1

  ; crypt it to current $active channel
  %resultstr = $dll( %mc_scriptdll  , mc_decrypt2 , %cname $2-)

  ; substitute multispaces with space preserving $160 ?
  %resultstr = $mcmultispacefix(%resultstr)

  if ((%resultstr == $null) || (%resultstr == $2-)) {
    ; initial decrypt failed, maybe they forgot the mcps?
    var %temptxt = mcps $2-
    %resultstr = $dll( %mc_scriptdll  , mc_decrypt2 , %cname %temptxt)
    ; substitute multispaces with space preserving $160 ?
    %resultstr = $mcmultispacefix(%resultstr)
  }
  if ((%resultstr == $null) || (%resultstr == $2-)) {
    .echo Text could not be decyrpted!
    return
  }

  else .echo Decrypted to: %resultstr
}




alias encryptecho {
  var %cname = $1
  if ((%cname == $null) || ($2 == $null)) return
  if ($dll( %mc_scriptdll  , mc_displaykey , %cname ) == $null) %cname = $chr(35) $+ $1
  if ($dll( %mc_scriptdll  , mc_displaykey , %cname ) == $null) {
    .echo No key could be found for %cname (remember to use # in front of channel names)
    return
  }
  var %result
  %result = $dll( %mc_scriptdll  , mc_encrypt2 , %cname $2- )
  .echo Encrypted ' $+ $2- $+ ' ( %cname ) To: %result
  %result = $dll( %mc_scriptdll  , mc_forceencrypt, %cname $2- )
  .echo Encrypted ' $+ $2- $+ ' ( %cname ) To: %result
}
; ---------------------------------------------------------------------------







; ---------------------------------------------------------------------------
; for bots&other scripts, aux. func to display encrypted or decrypted txt, as appropriate
alias emsg {
  if ($mc_ischannelmute($1)) {
    echo 4 Channel $1 set on MUTE, use /mcmute to toggle. Text not sent: $2-
    return
  }
  var %m | %m = $dll( %mc_scriptdll , mc_encrypt , $1 $2-)
  if ($2- == $null) return $null
  if ($1 == $null) return $null

  ; log
  $mc_logparse(input,$1,$me,$2-,$address,$true)
  if ($mchandlehalt() == $true) return
  if ((%m == $null) || (%m == $2-)) msg $1 $2-
  else {
    .msg $1 $mcetagchan($1) %m
    var %pre | %pre = $prenickify_encrypt($1)
    ;.echo $prespopt2(%pre) $1  $+ $colour(own text) $+ %pre $2-
    ; old bad color:
    ;.echo $prespopt2(%pre)  $+ $colour(own text) $+ %pre %om
    ; new timestamp fixed color
    .echo $colour(own text) $prespopt2(%pre) $1 %pre $2-
  }
}


; for bots&other scripts, aux. func to display encrypted or decrypted txt, as appropriate
alias forceemsg {
  var %m | %m = $dll( %mc_scriptdll , mc_forceencrypt , $1 $2-)
  if ($2- == $null) return $null
  if ($1 == $null) return $null

  ; log
  $mc_logparse(input,$1,$me,$2-,$address,$true)
  if ($mchandlehalt() == $true) return

  if ((%m == $null) || (%m == $2-)) msg $1 $2-
  else {
    .msg $1 $mcetagchan($1) %m
    var %pre | %pre = $prenickify_encrypt($1)
    ;.echo $prespopt2(%pre) $1  $+ $colour(own text) $+ %pre $2-
    ; old bad color:
    ;.echo $prespopt2(%pre)  $+ $colour(own text) $+ %pre %om
    ; new timestamp fixed color
    .echo $colour(own text) $prespopt2(%pre) $1 %pre $2-
  }
}


; for bots&other scripts, aux. func to display encrypted or decrypted txt, as appropriate
; wont send unless key found
alias smsg {
  var %m | %m = $dll( %mc_scriptdll , mc_forceencrypt , $1 $2-)
  if ($2- == $null) return $null
  if ($1 == $null) return $null
  ; log
  $mc_logparse(input,$1,$me,$2-,$address,$true)
  if ($mchandlehalt() == $true) return
  if ((%m == $null) || (%m == $2-)) .echo 4 Encrypted text could not be sent, since no key is defined for this user/channel.
  else {
    .msg $1 $mcetagchan($1) %m
    var %pre | %pre = $prenickify_encrypt($1)
    ;.echo $prespopt2(%pre) $1  $+ $colour(own text) $+ %pre $2-
    ; old bad color:
    ;.echo $prespopt2(%pre)  $+ $colour(own text) $+ %pre %om
    ; new timestamp fixed color
    .echo $colour(own text) $prespopt2(%pre) $1 %pre $2-
  }
}


; for bots&other scripts, aux. func to display encrypted or decrypted txt, as appropriate
; wont send unless key found, silent if query window not open
alias esmsg {
  var %m | %m = $dll( %mc_scriptdll , mc_forceencrypt , $1 $2-)
  if ($2- == $null) return $null
  if ($1 == $null) return $null
  ; log
  $mc_logparse(input,$1,$me,$2-,$address,$true)
  if ($mchandlehalt() == $true) return
  if ((%m == $null) || (%m == $2-)) .echo 4 Encrypted text could not be sent, since no key is defined for this user/channel.
  else {
    .msg $1 $mcetagchan($1) %m
    var %pre | %pre = $prenickify_encrypt($1)
    if ($window($1).wid != $null) {
      ;.echo $prespopt2(%pre) $1  $+ $colour(own text) $+ %pre $2-
      ; old bad color:
      ;.echo $prespopt2(%pre)  $+ $colour(own text) $+ %pre %om
      ; new timestamp fixed color
      .echo $colour(own text) $prespopt2(%pre) $1 %pre $2-
    }
  }
}


; for bots&other scripts, aux. func to display encrypted or decrypted txt, as appropriate, to *default chan*
alias esay {
  if ($1- == $null) return $null
  var %cname | %cname = $chan
  if (%cname == $null) %cname = $active
  %cname = $chatchan(%cname)

  ; log
  $mc_logparse(input,%cname,$me,$1-,$address,$true)
  if ($mchandlehalt() == $true) return

  var %m | %m = $dll( %mc_scriptdll  , mc_encrypt , %cname $1-)
  ; if active channel not encrypted, then just send the command normally
  if ((%m == $null) || (%m == $1-)) /say $1-
  else {
    .msg %cname $mcetagchan(%cname) %m
    var %pre | %pre = $prenickify_encrypt(%cname)
    ;.echo $prespopt2(%pre)  $+ $colour(own text) $+ %pre $1-
    ; old bad color:
    ;.echo $prespopt2(%pre)  $+ $colour(own text) $+ %pre %om
    ; new timestamp fixed color
    .echo $colour(own text) $prespopt2(%pre) %pre $1-
  }
}


; for bots&other scripts, aux. func to encrypt /me messages, as appropriate
alias eaction {
  if ($1- == $null) return $null
  var %cname | %cname = $chan
  if (%cname == $null) %cname = $active
  %cname = $chatchan(%cname)

  ; log
  $mc_logparse(action,%cname,$me,$1-,$address,$true)
  if ($mchandlehalt() == $true) return

  var %m | %m = $dll( %mc_scriptdll  , mc_encrypt , %cname $1-)
  ; if active channel not encrypted, then just send the command normally
  if ((%m == $null) || (%m == $1-)) {
    /action $1-
  }
  else {
    .action $mcetagchan($active) %m
    var %pre | %pre = %mc_preaction_encrypt $me 
    .echo $prespopt2(%pre)  $+ $colour(action text) $+ %pre $1-
  }
}

; eme is same as eaction
alias eme /eaction $1-

; edescribe is same as mc_describe (encrypted version of describe)
alias edescribe /mc_describe $1 $2-


; for bots&other scripts, aux. func to encrypt /me messages, as appropriate
alias mc_describe {
  if ($2- == $null) return $null
  var %cname | %cname = $1
  %cname = $chatchan(%cname)

  ; log
  $mc_logparse(action,%cname,$me,$2-,$address,$true)
  if ($mchandlehalt() == $true) return

  var %m | %m = $dll( %mc_scriptdll  , mc_encrypt , %cname $2-)
  ; if active channel not encrypted, then just send the command normally
  if ((%m == $null) || (%m == $2-)) {
    /describe %cname $2-
  }
  else {
    .describe $1 $mcetagchan($active) %m
    var %pre | %pre = %mc_preaction_encrypt $me 
    .echo $prespopt2(%pre) $1  $+ $colour(action text) $+ %pre $2-
  }
}

; forced encryption, even if channel disabled, and warning if no key exists for channel
alias etext {
  if ($1- == $null) return $null
  var %cname | %cname = $chan
  if (%cname == $null) %cname = $active
  %cname = $chatchan(%cname)
  var %m | %m = $dll( %mc_scriptdll  , mc_forceencrypt , %cname $1-)
  if (%m == $null) .echo 4 Encrypted text could not be sent, since no key is defined for this channel.
  else {
    .msg %cname $mcetagchan(%cname) %m
    var %pre | %pre = $prenickify_encrypt(%cname)
    ; log
    $mc_logparse(input,%cname,$me,$1-,$address,$true)
    if ($mchandlehalt() == $true) return
    ;.echo $prespopt2(%pre)  $+ $colour(own text) $+ %pre $1-
    ; old bad color:
    ;.echo $prespopt2(%pre)  $+ $colour(own text) $+ %pre %om
    ; new timestamp fixed color
    .echo $colour(own text) $prespopt2(%pre) %pre $1-
  }
}


alias mc_amsg {
  ; do an amsg (message to all) in all channels, and encrypt if appropriate
  ; loop through channels
  var %ccount = 1
  var %cname
  while ($chan(%ccount) != $null) {
    %cname = $chan(%ccount)
    /emsg %cname $1-
    inc %ccount
  }
}

alias eamsg {
  ; do an amsg (message to all) but ONLY in channels which are encrypted)
  var %cname
  var %isencrypting
  var %ccount = 1
  while ($chan(%ccount) != $null) {
    %cname = $chan(%ccount)
    %isencrypting = $dll( %mc_scriptdll , mc_isencrypting , %cname)
    if (%isencrypting == yes) /emsg %cname $1-
    inc %ccount
  }
}

alias mc_ame {
  ; do an ame (action to all) in all channels, and encrypt if appropriate
  ; loop through channels
  var %ccount = 1
  var %cname
  while ($chan(%ccount) != $null) {
    %cname = $chan(%ccount)
    /mc_describe %cname $1-
    inc %ccount
  }
}

; for bots&other scripts, aux. func to display encrypted or decrypted txt, as appropriate
alias enotice {
  var %m | %m = $dll( %mc_scriptdll , mc_encrypt , $1 $2-)
  if ($2- == $null) return $null
  if ($1 == $null) return $null
  var %om = $2-

  ; log
  $mc_logparse(input,$1,$me,$2-,$address,$true)
  if ($mchandlehalt() == $true) return

  if ((%m == $null) || (%m == $2-)) notice $1 $2-
  else {
    .notice $1 $mcetagchan($1) %m
    var %pre | %pre = %mc_prenick_encrypt_notice $1 %mc_postnick_encrypt_notice
    ; new fix of timestamp colors
    .echo $colour(own text) $prespopt2(%pre) %pre %om
  }
}

; plaintext command will bypass encryption   /plain text...  
alias plain { say $1- }
alias plaintext { say $1- }

alias mc_nohalts {
  unset %mc_halttext
  unset %mc_haltinput
}
; ---------------------------------------------------------------------------




















; ---------------------------------------------------------------------------
; Meow handshake routines
;   sends message of form   %mc_etag meow codeword {encrypted meow}
;   reply will be from all people using mircryption on the channel, an
;   *unencryped* reply.  to code #1
;    mcmeow-> $nick (encrypting/decrypting) [(keyphrase [mis]match)]
; send request for users to report
alias mcmeow {
  var %cname
  if ($1 != $null) %cname = $1
  else %cname = $active
  if (%cname == Status) {
    .mcmeowall
    return
  }
  %cname = $chatchan(%cname)

  .msg %cname $mcetagchan(%cname) meow meow $me %mc_scriptversion $dll( %mc_scriptdll  , mc_forceencrypt , %cname meow)
  .echo -ti2 %cname Broadcasting meow to %cname $+ ...
}


alias mcmeowall {
  var %curwincount | %curwincount = $chan(0)
  var %querycount | %querycount = $query(0)
  var %chatcount | %chatcount = $chat(0)
  var %ccount

  %ccount = 1
  while (%ccount <= %curwincount) {
    /mcmeow $chan(%ccount)
    inc %ccount
  }
  %ccount = 1
  while (%ccount <= %querycount) {
    /mcmeow $query(%ccount)
    inc %ccount
  }
  %ccount = 1
  while (%ccount <= %chatcount) {
    /mcmeow $chat(%ccount)
    inc %ccount
  }
}


alias mcmeownick {
  ; meow a specific nick about a specific channel
  var %cname
  var %nname
  %cname = $chatchan($1)
  %nname = $cleanmultiserve($2)
  ;  .msg %cname $mcetagchan(%cname) meow meownick $me %mc_scriptversion $dll( %mc_scriptdll , mc_forceencrypt , %cname meow) %nname $1
  .notice $2 $mcetagchan(%cname) meow meownick $me %mc_scriptversion $dll( %mc_scriptdll , mc_forceencrypt , %cname meow) %nname $1
  .echo -ti2 %cname Broadcasting meow to $2 on $1 ...
}


alias mchandshake {
  ; we have received a handshake request - so answer it ($1 is codeword)

  ;echo 4 -s in mchandshake 1 = $1 and 2 = $2 and 3 = $3 and 4 = $4 and 5 = $5 and 6 = $6

  if ($1 == meow || $1 == meownick) {
    ; standard meow type harmless handshake request - user wants to know if we are encrypting/decrypting/ have same keyphrase or no
    ; $2 is requester, $3 is optional an encrypted word of meow , $4 is target channel, $5 is nick target for meownick

    var %encstatus
    var %myencstatus
    var %matchstatus | %matchstatus = $null
    var %posttag | %posttag = $null
    var %cname | %cname = $chan
    var %replyto | %replyto = $chan
    if (%cname == $null) {
      %cname = $nick
      %replyto = $me
    }


    ; make sure nick names arent too long just in case they have old dll
    if (%len(%cname) > 60) %cname=$left(%cname,60)

    if ($1 == meownick) {
      ; a meownick broadcast is a private notice someone sends to do a meow just to you, about a common channel

      %cname = $6
      %replyto = %cname
      if (%cname == $null) return

      var %menname = $cleanmultiserve($me)
      if ($5 != %menname) {
        ; its a meow for a specific nick, but not for us, so we ignore
        .echo -sti2 [=^.^=] $3 $nick (illegal meownick to $5 about channel %cname $+ )
        return
      }

      ; only allow someone to meow us about a channel that we are both on
      if ($ialchan($nick , %cname , 1) == $null) {
        .echo -sti2 [=^.^=] $3 $nick (illegal meownick about channel %cname $+ )
        return
      }
    }

    ; only allow someone to meow us about a channel that we are both on
    if ($nick != %cname && $ialchan($nick , %cname , 1) == $null) {
      .echo -sti2 [=^.^=] $3 $nick (illegal meow about channel %cname $+ )
      return
    }

    var %ecs1 | %ecs1 = $dll( %mc_scriptdll , mc_isencrypting , %cname)
    var %ecs2 | %ecs2 = $dll( %mc_scriptdll , mc_isdecrypting , %cname)
    if ( (%ecs1 == yes ) && (%ecs2 == yes) ) %encstatus = crypting
    else if (%ecs2 == yes) %encstatus = decrypting only
    else %encstatus = no encryption for this channel

    var %keystatus
    if (%encstatus != no encryption for this channel) {
      %ecs1 = $dll( %mc_scriptdll ,mc_decrypt, %cname $4)
      if (%ecs1 == meow) {
        %matchstatus = (key match)
        %posttag = %mc_meowtag_match
      }
      else {
        %matchstatus = (key mismatch)
        %posttag = %mc_meowtag_mismatch
      }
      %myencstatus = %encstatus %matchstatus
      %encstatus = %myencstatus %posttag
    }
    else %encstatus = %encstatus %mc_meowtag

    ; custom me
    var %menick
    if ((%mc_meowtag_nick == $null) || (%mc_meowtag_nick == $me)) %menick = $me
    else %menick = %mc_meowtag_nick
    %menick = $mc_cleanspaces(%menick)

    ; send reply
    var %shouldreply = $null
    if (%mc_meowreplymode == always) %shouldreply = yes
    if (%mc_meowreplymode == noinfo) %shouldreply = yes
    if ( ( %mc_meowreplymode == match ) && ( %ecs1 == meow ) ) %shouldreply = yes
    if (%shouldreply == yes) {
      ; new test, send reply directly to user that meowed, not to channel as spam
      if (%mc_meowreplymode == noinfo) %encstatus = meow
      var %sendreplyto = $nick
      if (%sendreplyto == $null) %sendreplyto = $2
      if (%sendreplyto != $null) {
        ./notice %sendreplyto $mcetagchan($2) meow meowreply $2 %replyto $chr(91) $+ %mc_scriptversion $+ $chr(93) %menick -> %encstatus
      }
      else {
        %sendreplyto = %cname
        ./msg %sendreplyto $mcetagchan($2) meow meowreply $2 %replyto $chr(91) $+ %mc_scriptversion $+ $chr(93) %menick -> %encstatus
      }
      ;
      .echo -sti2 [=^.^=] [ $3 ] $2 -> $1 %cname %myencstatus
    }
    else {
      .echo -sti2 [=^.^=] [ $3 ] $2 -> $1 %cname %myencstatus (no reply sent)
    }
  }

  if ($1 == meowreply) {
    ; show the reply we have received, if it is in answer to a question we asked
    if ($me == $2) {
      var %cname = $cleanmultiserve($3)
      var %nname1 = $cleanmultiserve($nick)
      var %nname2 = $cleanmultiserve($5)
      if ( (%nname1 != $null) && (%nname2 != $null) && (%nname1 != %nname2) ) {
        .echo -ti2 %cname [=^.^=] $4 %nname1 ( $+ $5 $+ ) $6-
      }
      else {
        .echo -ti2 %cname [=^.^=] $4-
      }
      ; is this a meow upgrade advert?
      if (%mc_temp_mcmeowupgradeadvert != $null) {
        $mcmeowupgradecheck(%nname1,$4);
      }
    }
  }
}


; helper func to help you set your meow reply taglines
alias setmeowtaglines {
  var %tnewtag
  if (%mc_meowtag != $null) %tnewtag = $input(Tagline for replies to default meow broadcasts:,1,Meow Broadcast Reply Tagline,%mc_meowtag)
  else %tnewtag = $input(Tagline for replies to default meow broadcasts:,1,Meow Broadcast Reply Tagline)
  if (%tnewtag != $null) %mc_meowtag = %tnewtag

  if (%mc_meowtag_mismatch != $null) %tnewtag = $input(Tagline for replies to key-mismatch meow broadcasts:,1,Meow Broadcast Reply Tagline,%mc_meowtag_mismatch)
  else %tnewtag = $input(Tagline for replies to key-mismatch meow broadcasts:,1,Meow Broadcast Reply Tagline)
  if (%tnewtag != $null) %mc_meowtag_mismatch = %tnewtag

  if (%mc_meowtag_match != $null) %tnewtag = $input(Tagline for replies to key-match meow broadcasts:,1,Meow Broadcast Reply Tagline,%mc_meowtag_match)
  else %tnewtag = $input(Tagline for replies to key-match meow broadcasts:,1,Meow Broadcast Reply Tagline)
  if (%tnewtag != $null) %mc_meowtag_match = %tnewtag

  if (%mc_meowtag_nick != $null) %tnewtag = $input(Custom nick to display in meow replies (leave blank for none):,1,Meow Reply Custom Nick,%mc_meowtag_nick)
  else %tnewtag = $input(Custom nick to display in meow replies (leave blank for none):,1,Meow Reply Custom Nick)
  if (%tnewtag != $null) %mc_meowtag_nick = %tnewtag
}
; ---------------------------------------------------------------------------






; ---------------------------------------------------------------------------
alias mcmeowupgradeadvert {
  var %cname
  if ($1 != $null) %cname = $1
  else %cname = $active
  if (%cname == Status) {
    .mcmeowall
    return
  }
  %cname = $chatchan(%cname)

  %mc_temp_mcmeowupgradeadvert = running
  .msg %cname $mcetagchan(%cname) meow meow $me %mc_scriptversion $dll( %mc_scriptdll  , mc_forceencrypt , %cname meow)
  .echo -ti2 %cname Broadcasting meow to %cname $+ ...
  .timer 1 15 .unset %mc_temp_mcmeowupgradeadvert
}



alias mcmeowupgradecheck {
  ; if person has older version than us, let them know.
  ; if we have older version than them, let us know
  var %nickname = $1
  var %replytext = $2
  ;echo -ti2 nick = %nickname  replytext = %replytext

  if ($left(%replytext,1) != $chr(91)) return
  if ($right(%replytext,1) != $chr(93)) return
  var %textlen = $len(%replytext)
  %textlen = %textlen - 2
  %replytext = $mid(%replytext,2,%textlen)

  ; ignore special versions
  var %lastchar = $right(%replytext,1)
  %lastchar = $asc(%lastchar)
  if (%lastchar < 48 || %lastchar > 57) return

  ; ignore known old non-real-client versions
  if ( $mid(%replytext,3,2) == 00 ) return

  ; same version as us?
  if (%replytext == %mc_scriptversion) {
    ; same version as us
    ;echo 4 user ' %nickname ' has same version as us
    return
  }

  ; compare version #s
  var %userhasnewer = $mc_newerversion (%replytext,%mc_scriptversion)
  if (%userhasnewer == $true) {
    ; user version is newer than us
    ;echo 4 user ' %nickname ' has newer version than us
    if (%mc_temp_mcmeowupgradeadvert != $null) %mc_temp_mcmeowupgradeadvert = running_wehaveold
    return
  }

  ; user has older version than us
  echo 4 Meow Version Advert: Notifying %nickname that they have an old version of mircryption and should update.
  .notice %nickname a meow from $me has detected that you have an older version of mircryption.  Use /mcupdate or visit www.mircryption.sourceforge.net to download the lastest update or the updater utility.
}



alias mc_newerversion {
  ; args are %webversion,%currentversion
  var %webversion = $1
  var %currentversion = $2
  var %webversion_word = $null
  var %currentversion_word = $null

  ;echo 4 -s comparing webversion %webversion vs current version %currentversion

  ; we expect these version strings to be of form numbers separated by dots, ie #.# or #.#.# or #.#.#.#, and we stop on shorted string
  while ((%webversion != $null) && (%currentversion != $null)) {
    ; pick off leftmost word of both versionstrings
    %webversion_word = $gettok(%webversion,1,46)
    %webversion = $deltok(%webversion,1,46)
    %currentversion_word = $gettok(%currentversion ,1,46)
    %currentversion = $deltok(%currentversion ,1,46)
    ;echo DEBUGTEST compareversion webv = %webversion_word vs. curv = %currentversion_word
    if ( %currentversion_word isnum ) {
      if (%webversion_word < %currentversion_word) return $false
      if (%webversion_word > %currentversion_word) return $true
    }
    else return $true
  }

  if (%webversion != $null) return $true
  return $false
}
; ---------------------------------------------------------------------------












































; ---------------------------------------------------------------------------
; MS Agent replacement speech elements, part 1

alias mc_msagent {
  ; main agent speaking procedure
  ; $1 is speaker, $2 is channel they speaking in, $3 is text type (text,action,topic,part,quit,join,other) $4- is text they said. use $3==other to just speak the $4- text
  var %agentname
  var %agentid
  var %agentfile
  var %tosay
  var %toact
  var %endpos
  var %slen
  var %speaker | %speaker = $1

  ; echo -s DEBUGTEST mc_msagent 1= $1 2= $2 3= $3 4- = $4-

  ; are they disabling all ms agent features
  if (%mc_agent_enable != yes) return

  ; here is a clever trick, to prevent non-ending errors, we turn off agent feature and then turn it back on after gload - if gload fails, it will stay off :)
  %mc_agent_enable = no

  if (%speaker == $me) %speaker = mynick

  ; First check if there is a specific agent assigned for this speaker+channel, if so, use it
  %agentname = mc_agent_char_ $+ %speaker $+ $2
  %agentfile = [ % ] $+ %agentname
  %agentfile = $eval( [ %agentfile ] )

  if (%agentfile == $null) {
    ; First check if there is a specific agent assigned for this speaker, if so, use it
    %agentname = mc_agent_char_ $+ %speaker
    %agentfile = [ % ] $+ %agentname
    %agentfile = $eval( [ %agentfile ] )
    if (%agentfile == $null) {
      ; Else check if there is a specific agent assigned to this channel, if so, use it
      %agentname = mc_agent_char_ $+ $2
      %agentfile = [ % ] $+ %agentname
      %agentfile = $eval( [ %agentfile ] )
      if ((%agentfile == $null) && (($3 == query) || ($3 == queryaction))) {
        ; If not, if there's a generic one set for all queries, use that one
        %agentname = mc_agent_char_query
        %agentfile = [ % ] $+ %agentname
        %agentfile = $eval( [ %agentfile ] )
      }
      if (%agentfile == $null) {
        ; If not, if there's a default character use that one
        %agentname = mc_agent_char_default
        %agentfile = [ % ] $+ %agentname
        %agentfile = $eval( [ %agentfile ] )
      }
    }
  }

  ; added here to renable speech in case we return here 5/12/04
  %mc_agent_enable = yes

  ; they can disable speech for any channel by using disable as the agent file name
  if ((%agentfile == disable) || (%agentfile == $null)) return
  ; temporary disable
  if ($left(%agentfile , 1) == - ) return

  ; disableuntil it works
  %mc_agent_enable = no

  ; we mow use agent file as agent name, so that we dont try to open multiple copies of same agent file
  %agentid = %agentfile

  if ($agent( %agentid ).fname == $null) {
    ; A kuldge to load the agent if it is not loaded - fname is blank if agent is not loaded

    .gload %agentid %agentfile

    var %agentopts | %agentopts = %mc_agent_options
    var %opt1
    var %opt2
    while (%agentopts != $null) {
      %opt1 = $gettok(%agentopts , 1 , 32)
      %opt2 = $gettok(%agentopts , 2 , 32)
      .gopts %opt1 %agentid %opt2
      %agentopts = $deltok(%agentopts , 1-2 , 32)
    }
    if (%mc_agent_size != $null) /gsize %agentid %mc_agent_size
    if (%mc_agent_move != $null) /gmove %agentid %mc_agent_move
  }

  ; Decide what to say based on form of speech
  if ($3 == topic ) %tosay = $1 changes $2 topic to $4-
  else if ($3 == join ) %tosay = $1 has joined $2
  else if ($3 == part ) %tosay = $1 has left $2
  else if ($3 == quit ) %tosay = $1 quits irc
  else if (($3 == action) || ($3 == queryaction)) {
    if ($right($4- , 1) == $chr(93)) {
      ; user can end an action with a [ACTION] to force an action
      %endpos = $pos($4- , $chr(91))
      if (%endpos >= 1) {
        %endpos = %endpos + 1
        %slen = $len($4-) - %endpos
        %toact = $mid($4- , %endpos, %slen )
        %slen = %endpos - 2
        %tosay = $1 $left($4- , %slen)
      }
    }
    if (%toact == $null) {
      %tosay = $1 $4-
      if (%mc_agent_actionanimations == yes) %toact = $smartanimations(%agentfile , $4-)
    }
    ; update the last speaker
    set %mc_agent_lastspeaker_ [ $+ [ $eval(%agentfile) ] ] $1
  }
  else if (($3 == query) || ($3 == channel) || ($3 == text)) {
    ; now we do a new trick, the variable %mc_agent_smartnames == yes, means that we dont repeat the "[nick] says: " part if the same agent is speaking for same person again
    if (%mc_agent_speechanimations == yes) %toact = $smartanimations(%agentfile , $4-)
    if (%mc_agent_smartnames == yes) {
      var %agentspeakervar
      var %agentlastspeaker
      %agentspeakervar = [ % ] $+ mc_agent_lastspeaker_ $+ %agentfile
      %agentlastspeaker = $eval( [ %agentspeakervar ] )
      if (%agentlastspeaker == $1) %tosay = $4-
      else {
        %tosay = $1 says: $4-
        set %mc_agent_lastspeaker_ [ $+ [ $eval(%agentfile) ] ] $1
      }
    }
    else %tosay = $1 says: $4-
  }
  else if ($3 == other ) %tosay = $4-
  else {
    ; unkown situation
    %tosay = $1 $4-
  }

  ; now say it
  %tosay = $replace(%tosay , $chr(124) , $chr(46) )
  %tosay = $lower(%tosay)
  if (%tosay != $null && %tosay != $1) {
    ; first stop any current animations (otherwise they queue up and can get slow).  might be nice to stop all characters animations?
    .gstop %agentid play
    ;and now run the current one
    .gtalk %mc_agent_talkoptions %agentid %tosay
  }

  ; movement?
  if ($4 == moves && %mc_agent_agentscanmove == yes ) {
    if (%tosay == $1 moves left) {
      var %delta = $agent(%agentid).w
      var %x = $agent(%agentid).x + %delta
      var %y = $agent(%agentid).y
      .gmove %agentid %x %y 1
      %toact = $null
    }
    else if (%tosay == $1 moves right) {
      var %delta = $agent(%agentid).w
      var %x = $agent(%agentid).x - %delta
      var %y = $agent(%agentid).y
      .gmove %agentid %x %y 1
      %toact = $null
    }
    else if (%tosay == $1 moves up) {
      var %delta = $agent(%agentid).h
      var %x = $agent(%agentid).x
      var %y = $agent(%agentid).y - %delta
      .gmove %agentid %x %y 1
      %toact = $null
    }
    else if (%tosay == $1 moves down) {
      var %delta = $agent(%agentid).h
      var %x = $agent(%agentid).x
      var %y = $agent(%agentid).y + %delta
      .gmove %agentid %x %y 1
      %toact = $null
    }              
  }

  ; play animations
  if (%toact != none && %toact != $null) {
    ; echo animation %toact engaged.
    .gplay %agentid %toact
  }

  ; restore this variable which we disabled at top
  %mc_agent_enable = yes
}


on *:AGENT: {
  ; provide an option to unload or hide agents after they speak
  if (%mc_agent_enable != yes) return
  if (%mc_agent_afterspeech == unload) .gunload $agentname
  else if (%mc_agent_afterspeech == hide) .ghide $agentname
}


alias mcspeech {
  ; enable, disable, or toggle ms agent speech functions
  if (($1 == $null) && (%mc_agent_enable != yes)) %mc_agent_enable = yes
  else if (($1 == $null) && (%mc_agent_enable == yes)) %mc_agent_enable = no
  else if (($1 == on) || ($1 == yes)) %mc_agent_enable = yes
  else if (($1 == off) || ($1 == no)) %mc_agent_enable = no
  if (%mc_agent_enable == yes) {
    echo -s Mircryption MS Agent speech functions now enabled.
    /mc_msagent dummy dummy other Mircryption speech functions now enabled.   
  }
  else {
    echo -s Mircryption MS Agent speech functions now disabled.
    var %varval , %agentfile
    var %vcount | %vcount = $var(%mc_agent_char_*,0)
    var %hashtable
    var %tempvar
    while (%vcount > 0) {
      %varval = $var(%mc_agent_char_* , %vcount)
      %agentfile = $eval( [ %varval ] )
      if ($pos( %agentfile , .acs ) > 1) {
        if ($agent( %agentfile ).fname != $null) .gunload %agentfile
        %hashtable = $replace(%agentfile , .acs , .aal)
        %tempvar = $hget(%hashtable)
        if (%tempvar != $null) {
          ; free the hash table for the agent - note that this isnt really nesc. to stop speech, but saves memory
          /hfree %hashtable
        }
      }
      %vcount = %vcount - 1
    }
  }
}
; ---------------------------------------------------------------------------



; ---------------------------------------------------------------------------
; MS Agent replacement speech elements, part 2 - fun animations

alias smartanimations {
  ; examine the text and pick some animaitons to play based on text content.  $1 is agentid,  $2- is action sentence
  ; return 'none' if no animations
  var %anims
  var %hashtable
  var %tempvar
  var %eadded

  ; first repace all punctuation with spaces  
  var %sentence | %sentence = $2-
  %sentence = $replace( %sentence , $chr(44), $chr(32))
  %sentence = $replace( %sentence , $chr(45), $chr(32))
  %sentence = $replace( %sentence , $chr(46), $chr(32))
  %sentence = $replace( %sentence , $chr(63), [ $chr(32) $+ _q_ $+ $chr(32) ] )
  %sentence = $replace( %sentence , $chr(33), [ $chr(32) $+ _e_ $+ $chr(32) ] )
  %sentence = _ $+ $chr(32) $+ %sentence $+ $chr(32) $+ _

  ; if we dont already have a hashtable for this character, load or create
  %hashtable = $replace($1 , .acs , .aal)
  %tempvar = $hget(%hashtable)
  if (%tempvar == $null) {
    if ($exists($scriptdir $+ msagentdefault.aal) || $exists(%hashtable)) {
      ; has table not yet built, so make it
      .hmake [ %hashtable ] 100
      %eadded = %eadded + [ $addhashanimfile($1 , %hashtable , " $+ $scriptdir $+ msagentdefault.aal") ]
      %eadded = %eadded + [ $addhashanimfile($1 , %hashtable , %hashtable) ]
      if (%eadded == 0) /hfree %hashtable
      else %tempvar = %hashtable
    }
  }
  if (%tempvar == $null) return none

  ; now we walk through it, searching for regex matches of keys, and adding animations if we get a hit

  var %total = $hget(%hashtable,0).item , %x = 0
  var %i , %ii , %data , %dataword
  var %totalpat
  ; echo -s total hashtable lenth is %total
  while (%total > 0) {
    %ii = $hget(%hashtable , %total).item
    %i = $gettok(%ii , 1 , 32)
    %data = $hget(%hashtable , %total).data
    if (%data == $null) %data = $hget(%hashtable , %ii)
    ; %data is comma separated patterns, we want to check for a match of any
    %totalpat = $numtok(%data , 44)
    ; echo -s animation %i , data is %data , and pats is %totalpat
    while (%totalpat > 0) {
      %dataword = $gettok(%data , %totalpat , 44)
      ; echo -s checking if pattern %dataword matches string
      if (%dataword iswm %sentence) {
        ; yes we got a match
        %anims = %anims %i
        ; echo -s got a match on %i with data %data
        /break
      }
      dec %totalpat
    }
    dec %total
  }

  ; echo smartanimations for agent $1 is %anims and string was %sentence
  ; now return a single animation if only one qualifies, or pick a random one from the list
  if (%anims == $null) return none
  var %animcount | %animcount = $numtok(%anims,32)
  if (%animcount > 1) {
    %animcount = $rand(1 , %animcount)
    %anims = $gettok(%anims , %animcount , 32)
  }

  return %anims
}


alias addhashanimfile {
  ; add a file into hash table
  ; $1 is agent id , $2 is hashtablename , $3 is file name
  var %hashtable = $2
  var %agentid = $1
  var %eadded

  if ($exists($3) == $false) return 0

  ; make a temp hash table and load defaults into it
  .hmake temphash 200
  .hload temphash $3

  ; now walk through our animtions, and pick off the ones from this file that we support
  var %acount , %count
  var %aname
  var %dindex
  var %dval

  %acount = $agent($1 , 0).anim
  %count = 1
  %acount = $agent(%agentid , 0).anim
  while (%count <= %acount) {
    %aname = $agent(%agentid , %count).anim
    %dindex = $hfind(temphash , %aname , 1)
    ; echo -s testing anim %count is %aname dindex is %dindex
    if (%dindex != $null) {
      ; echo -s got a match on default %aname
      %dval = $hget(temphash , %dindex)
      .hadd %hashtable %aname %dval
      inc %eadded
    }
    inc %count
  }

  ; echo -s Mircryption msagent support addeded %eadded animation actions to $1 from $3

  ; free the default table
  /hfree temphash
  return %eadded
}


alias isvalidanimation {
  ; is the animation a valid one to play exists for the agent
  ; $1 is agentid , $2 is animation to play
  ; return $2 if it is a vlid animaiton, or none if not
  var %acount
  var %aname
  %acount = $agent($1 , 0).anim

  ; echo -s In isavlid with $1 and $2 and %acount
  while (%acount > 0) {
    %aname = $agent($1 , %acount).anim
    ;echo -s checking against animation %acount which is %aname
    if (%aname == $2) return $2
    dec %acount
  }
  return none
}


; helper function to create a .aal file listing animations for an agent, useful if you want to make your own custom .aal file for an agent
; this is not called by any normal mircryption functionm you run this manually to create a .acs file
alias makeanimlistfile {
  ; $1 is agent file name including .acs
  var %agentid = $1
  var %acount
  var %aname
  var %count = 1

  if ($pos(%agentid , $chr(46)) == $null ) %agentid = %agentid $+ .acs

  var %filename = $replace(%agentid , .acs , .aal)
  ; echo -s Checking filename %filename
  if ($exists(%filename) && $2 != overwrite ) {
    echo -s File %filenme already exists, it will not be overwritten.  Use  /makeanimlistfile <agentname> overwrite'  to foce overwrite
    return
  }

  if ($agent( %agentid ).fname == $null) {
    ; A kuldge to load the agent if it is not loaded - fname is blank if agent is not loaded
    .gload %agentid %agentid
  }

  write -c %filename
  %acount = $agent(%agentid , 0).anim
  while (%count <= %acount) {
    %aname = $agent(%agentid , %count).anim
    echo Writing animation %count which is %aname
    write %filename %aname
    write %filename %aname
    inc %count
  }
}



alias msagent_rescue {
  ; bring an agent back on screen. $1 is agent
  var %agentid | %agentid = $1
  if ($pos(%agentid , $chr(46)) == $null ) %agentid = %agentid $+ .acs
  .gmove %agentid 100 100 1
}

alias msagent_rollcall /msagent_rolecall $1-

alias msagent_rolecall {
  ; line up agents

  var %varval , %agentfile
  var %vcount | %vcount = $var(%mc_agent_char_*,0)
  var %hashtable
  var %tempvar
  var %x | %x = 5
  var %y | %y = 100
  var %ox , %oy
  var %movedyet
  var %delta
  var %justification

  if ($1 == v) %justification = v
  else %justification = h

  .hmake temphash 20

  %vcount = $var(%mc_agent_char_*,0)
  if (%justification == h) {
    %ox = 60
    %oy = 170
  }
  else {
    %ox = 80
    %oy = 80
  }
  %x = %ox
  %y = %oy
  while (%vcount > 0) {
    %varval = $var(%mc_agent_char_* , %vcount)
    %agentfile = $eval( [ %varval ] )
    if ($pos( %agentfile , .acs ) > 1) {
      if ($agent( %agentfile ).fname != $null) {
        ; ok, go
        if (%justification == h) {
          %delta = $agent(%agentfile).h
          %delta = %delta / 2
          %y = %oy - %delta
        }
        else {
          %delta = $agent(%agentfile).w
          %delta = %delta / 2
          %x = %ox - %delta
        }
        %movedyet = $hfind(temphash , [ %agentfile ] , 1)
        if (%movedyet == $null) {
          .gmove %agentfile %x %y 1
          if (%justification == h) {
            %delta = $agent(%agentfile).w
            %delta = %delta / 1.5
            %x = %x + %delta
          }
          else {
            %delta = $agent(%agentfile).h
            %delta = %delta
            %y = %y + %delta
          }
          .hadd temphash [ %agentfile ] yes
        }
      }
    }
    %vcount = %vcount - 1
  }
  .hfree temphash
}

; ---------------------------------------------------------------------------

















; ---------------------------------------------------------------------------
; preliminary functions for an advanced feature which is not finished yet,
; meant to allow the script to smartly encrypt only parts of sentences
; like if you want to talk to a bot
alias mc_bindinit {
  ; initialize the plaintext hash table
  .hmake mc_plaintext_hashtable 50
}

alias mc_plainbinding {
  ; new generic mechanism for indicating certain outgoing stuff should not be encrypted (like commands to bots) 8/25/02
  ; return true if $1- is a command that should NOT be encrypted
  var %tablecount = $hget( mc_plaintext_hashtable , 0 ).item
  var %ccount
  var %tableword
  var %firstword = $gettok($1-,1,32)

  %firstword = $lower(%firstword)

  ;/echo in plainbinding with %tablecount

  %ccount = 1
  while (%ccount <= %tablecount ) {
    %tableword = $hget( mc_plaintext_hashtable , %ccount ).item
    ;/echo comparing ' $+ %tableword $+ ' versus ' $+ %firstword $+ '
    if (%tableword == %firstword) {
      return $true
    }
    inc %ccount
  }

  return $false
}

alias mc_bind {
  ; helper for mc_plainbinding above
  ; idea is that you can basically just paste the eggdrop tcl bind commands into a script 
  ; format for eggdrop tcl is :    "bind pub - !lalalalala"
  ; format for here is:   ".mc_bind pub - !lalalalala"
  ; we add these strings to a hash table which mc_plainbinding looks up
  var %matchprefix
  var %matchword
  var %txt = $1-

  ; split it up
  %txt = $replace(%txt , $chr(32) $+ $chr(45) , $chr(45) )
  %txt = $replace(%txt , $chr(45) $+ $chr(32) , $chr(45) )

  var %dashpos = $pos(%txt , $chr(45))
  if (%dashpos < 1) return

  %dashpos = %dashpos - 1
  %matchprefix = $left(%txt, %dashpos )
  %dashpos = %dashpos + 1
  var %slen = $len(%txt) - %dashpos
  %matchword = $right(%txt,%slen)

  ; now we only want first word of matchword (unless this is one of the rare multiword binds)
  %matchword = $gettok(%matchword,1,32)
  %matchword = $lower(%matchword)
  ;/echo dashpos is %dashpos and matchprefix is ' $+ %matchprefix $+ ' and matchword is ' $+ %matchword $+ '

  ; now add it to hash table of plaintext
  .hadd mc_plaintext_hashtable %matchword %matchprefix
}
; ---------------------------------------------------------------------------






; ---------------------------------------------------------------------------
; md5 hash functions (for md5 jump join)

alias mc_md5 {
  ; simple md5 helper function
  var %md5result
  %md5result = $dll( %mc_scriptdll , mc_md5, $1- )
  /echo -s md5 hash of $1- is %md5result
}

alias mcjumpjoin {
  var %md5chan
  var %sourcechan
  var %ekey
  var %m
  var %om
  var %jumpstring
  var %curgmt_ctime
  var %curgmt_date
  var %retv
  var %partone

  ; get the source channel
  %sourcechan = $1
  if (%sourcechan == $null) %sourcechan = $input(Name of #channel to use for basis of md5 jump-join?,1,MD5 jump-join)
  if (%sourcechan == $null) return

  ; get encryption key for source channel
  %ekey = $dll( %mc_scriptdll  , mc_displaykey , %sourcechan)
  if (%ekey == $null) {
    %sourcechan = $chr(35) $+ %sourcechan
    %ekey = $dll( %mc_scriptdll  , mc_displaykey , %sourcechan)
  }
  if (%ekey == $null) {
    .echo 4 -t no mircryption keyphrase found for channel %sourcechan
    return
  }

  ; ok, now what text do we hash to get our md5 jumpjoin channel name?
  ; the first part USED TO BE the base channel name
  ; but to aid autochannel jumping, we are going to stop that, and just use a constant - its not important since we are encrypting the date
  ; it just means that the new jumpjoin channel is unique corresponding to encryption phrase and date.
  %partone = %sourcechan
  ; %partone = jumpjoinconstant

  ; the second part will be the either the (current) date or a user specified stirng
  if ($2 != $null) %jumpstring = $2-
  else {
    %curgmt_ctime = $ctime
    %curgmt_date = $asctime(%curgmt_ctime,dd/mm/yy)	
    ; now verify date jumpstring with user and let them change it
    %jumpstring = %curgmt_date
    %jumpstring = $input(String to use for basis of md5 jump-join (defaults to gmt DD/MM/YY)?,1,MD5 jump-join,%jumpstring)
    if (%jumpstring = $null) {
      ; attempt to bleach variable from memory
      %ekey = $str(x , [ $len(%ekey ) ] )
      return
    }
  }

  ; then rather than hashing this info, we first encrypt it using the base channel pass, and THEN md5 it
  ; if your $2- starts with the word ONLY then only the stuff after $2 will be used for basing channel to jump to,
  ;  not channel name, which is good for jumping based on query keyname which isnt the same on both peoples computer.
  if ($2 == ONLY) %om = $3-
  else %om = %partone $+ %jumpstring

  ; encrypt text to hash
  %m = $dll( %mc_scriptdll  , mc_encrypt , %sourcechan %om)
  if ( $left(%m,17) == Mircryption_Error) {
    ; error encrypting output
    .echo 4 -t %m
  }
  else if ((%m == %om) || (%m == $null)) {
    .echo 4 -t error encrypting text to hash
    ; attempt to bleach variable from memory
    %ekey = $str(x , [ $len(%ekey ) ] )
    return
  }

  ; now hash our special text to get our new channel name
  %md5chan = $dll( %mc_scriptdll , mc_md5, %m )

  ; we could be naughty and re-encrypt the hash to disguise the fact that this is an md5 named channel?
  ; but we dont do that for now.

  %md5chan = $chr(35) $+ mcd5 $+ %md5chan

  ; set key for the new channel
  %retv = $dll( %mc_scriptdll  , mc_setkey , %md5chan %ekey)

  ; now join the new channel and tell them so
  .echo 4 -t joining channel %md5chan based on jumpstring " $+ %jumpstring $+ ", and transferring mircryption passphrase for %sourcechan $+ , and setting mode +ps.
  .join %md5chan
  .mode %md5chan +psn-t
  ; attempt to bleach variable from memory
  %ekey = $str(x , [ $len(%ekey ) ] )
}
; ---------------------------------------------------------------------------








; ---------------------------------------------------------------------------
; User can mute a channel - provided by request

alias mc_ischannelmute {
  var %cvname = % $+ mc_mutedchan_ $+ $1
  if ( [ [ %cvname ] ] == $true) return $true
  return $false
}

alias mcmute {
  var %cname = $active
  var %cvname = % $+ mc_mutedchan_ $+ %cname
  if ( [ [ %cvname ] ] == $true) {
    echo 5 Channel %cname is now UN-muted. Call /mcmute again to mute.
    unset [ %cvname ]
  }
  else {
    .set [ [ %cvname ] ] $true
    echo 5 Channel %cname is now MUTED. Call /mcmute again to unmute.
  }
}
; ---------------------------------------------------------------------------









; ---------------------------------------------------------------------------
; helper function for bnc log decrypting
alias mc_bncdecryptpad {
  ; present a memo for user to paste some bnc log lines to decrypt ($1 is channel or nick name used if decrypting backlog)
  set %mc_decryptpadchan $1
  .dialog -m mc_mybnclogpad mc_bnclogpad_dialog
}

; Main update dialog
dialog mc_bnclogpad_dialog {
  title Mircryption Backlog Decryptor Pad - %mc_decryptpadchan
  size -1 -1 300 122
  option dbu
  text "Paste in the full lines from your window or bnc /playprivatelog and click ok.", 2, 2 4 247 9
  button "Ok", 6, 252 2 46 11, ok
  button "Cancel", 3, 252 15 46 11, cancel
  edit "", 7, 2 28 296 92, multi hsbar vsbar return default
}

on 1:dialog:mc_mybnclogpad:sclick:6: {
  ; decrypt
  var %linecount = $did(7,mc_mybnclogpad).lines
  var %thisline

  var %count = 1
  while (%count <= %linecount) {
    %thisline = $did(7,mc_mybnclogpad,%count).text
    .mc_bncdecryptstring %thisline
    %count = %count + 1
  }
  set %mc_decryptpadchan $null
}

alias mc_bncdecryptstring {
  ; decrypt a bnc log entry string $1- and echo it
  ; sample entry: [16:05:47] <-psyBNC> Sun Jun 8 16:07:38 :(mouser!renchler@goes.to.lanwars.be) mcps ZoVHK.GB.3c.
  ; our strategy is walk forward till we see :( then grab the nick till the !
  ; and grab everything after the mcps at the end
  var %prefix
  var %messagenick
  var %mcpsmessage
  var %decryptedmessage
  var %fullstring = $1-
  var %ekey
  var %mcpstok,%mcpos
  var %remlength

  ;echo DEBUG %fullstring 

  ; locate prefix
  %mcpstok = mcps
  %mcpos = $pos(%fullstring,%mcpstok,1)
  if ((%mcpos == $null) || (%mcpos == 0)) {
    %mcpstok = +OK
    %mcpos = $pos(%fullstring,%mcpstok,1)
  }
  if ((%mcpos == $null) || (%mcpos == 0)) {
    return $false
  }

  ; separate prefix from mcps
  %mcpos = %mcpos - 1
  %prefix = $left(%fullstring,%mcpos);
  %mcpos = %mcpos + 1
  %mcpos = %mcpos + $len(%mcpstok)
  %remlength = $len(%fullstring) - %mcpos
  %remlength = %remlength
  %mcpsmessage = $right(%fullstring,%remlength)
  ;echo DEBUG %prefix :::: %mcpsmessage

  ; now grab nick
  %mcpstok = : $+ $chr(40)
  %mcpos = $pos(%prefix,%mcpstok,1)
  if ((%mcpos == $null) || (%mcpos == 0)) {
    ; if we cant find the nick form then this isnt a bnc log.. SO we try to just decrypt it as backlog
    ; echo -s TRYING NEW DECRYPTPAD with %mc_decryptpadchan and %fullstring
    if (%mc_decryptpadchan != $null) {
      %mcpsmessage = mcps %mcpsmessage
      %decryptedmessage = $dll( %mc_scriptdll  , mc_decrypt2 , %mc_decryptpadchan %mcpsmessage)
      echo -h %mc_decryptpadchan [backlog] %prefix %decryptedmessage
      return $true
    }
    return $false
  }


  var %mcpos2
  %mcpos2 = $pos(%prefix,!,1)
  if ((%mcpos2 == $null) || (%mcpos2 == 0)) return $false
  %mcpos = %mcpos + 2
  %remlength = %mcpos2 - %mcpos
  %messagenick = $mid(%prefix,%mcpos,%remlength)
  ;echo DEBUG message nick is ' $+ %messagenick $+ '

  ; correct for multiserve nicks
  %ekey = $dll( %mc_scriptdll  , mc_displaykey , %messagenick )
  if (%ekey == $null) {
    %mcpstok = $chr(126)
    %mcpos = $pos(%fullstring,%mcpstok,1)
    if (%mcpos > 0) {
      ;%mcpos = %mcpos - 1
      ;%ekey = $mid(%fullstring,2,%mcpos)
      ;%mcpos = %mcpos - 1
      var %prefixednick = $mid(%fullstring,1,%mcpos)
      %prefixednick = %prefixednick $+ %messagenick
      ;echo DEBUG trying efnet prefixed nick of ' $+ %prefixednick $+ '
      var %ekey = $dll( %mc_scriptdll , mc_displaykey , %prefixednick )
      if (%ekey != $null) %messagenick = %prefixednick 
    }
  }

  ; clean any suffix on the encrypted message provided by a bnc hash <666>
  if ($right(%mcpsmessage,1) == $chr(62)) {
    ;echo DEBUG found > at the end
    var %searchstr = $chr(60)
    var %searchcount = $pos(%mcpsmessage,%searchstr,0)
    if (%searchcount > 0) {
      var %searchpos = $pos(%mcpsmessage,%searchstr,%searchcount)
      %searchpos = %searchpos - 2
      ;echo DEBUG found < at the end at pos %searchpos
      %mcpsmessage = $left(%mcpsmessage,%searchpos)
    }
  }


  ; if prefix has timestamp, remove it
  if ($left(%prefix,1) == $chr(91) ) {
    %mcpos = $pos(%prefix,$chr(93),1)
    if ((%mcpos != $null) && (%mcpos != 0)) {
      %remlength = $len(%prefix) - %mcpos
      var %mcalt = $mid(%prefix,%mcpos,%remlength)
      %prefix = $right(%prefix,%remlength)
      ;echo DEBUG has prefix timestamp: %remlength and pos: %mcpos so alt would be %mcalt
    }
  }


  ; now display it
  ;echo DEBUG messageto decrypt is ' $+ %mcpsmessage $+ '
  if ( (%messagenick != $null) || (%mcpsmessage != $null) ) {
    %mcpsmessage = mcps %mcpsmessage
    %decryptedmessage = $dll( %mc_scriptdll  , mc_decrypt2 , %messagenick %mcpsmessage)
    ;%decryptedmessage = $dll( %mc_scriptdll  , mc_decrypt , %messagenick %mcpsmessage)
    ;echo got back from decrypt is %decryptedmessage
    var %mcpsdecryptedmessage = mcps %decryptedmessage
    if ( (%decryptedmessage == $null) || (%decryptedmessage == %mcpsmessage) || (%mcpsmessage == %mcpsdecryptedmessage) )  %decryptedmessage = *COULD NOT BE DECRYPTED* %mcpsmessage
    if ($window(-psyBNC).wid != $null) {
      var %wname = $chr(45) $+ psyBNC
      ;      echo $chr(45) $+ psyBNC %prefix (e) %decryptedmessage
      echo -h %wname [-psyBNC] %prefix %decryptedmessage
      return $true
    }
    else echo %prefix (e) %decryptedmessage
  }

  return $false
}
; ---------------------------------------------------------------------------




; ---------------------------------------------------------------------------
alias mcprefixchan {
  ; change prefix of a channel ($1 is chan/nick, $2 is new prefix)
  if ($1 == $null) return

  if ($1 == "___ALL___") {
    if ($2 == $null) {
      echo 4 Encryption prefix for all channels now set to default (mcps)
      set %mc_etag mcps
      return
    }
    set %mc_etag $2
    echo 4 Encryption prefix for all channels now set to $2
    return
  }

  if ($2 == $null) {
    ; switch to default by eraseing 
    echo 4 Encryption prefix for $1 is now set to default (mcps)
    unset  % $+ [ mc_etag_ $+ [ $1 ] ] 
  } 
  else {
    ; switch to defa
    echo 4 Encryption prefix for $1 is now set to $2
    set [ % $+ [ mc_etag_ $+ [ $1 ] ] ] $2
  } 
}
; ---------------------------------------------------------------------------

















; ---------------------------------------------------------------------------
; some startup and uninstall helper funcs

alias setmcvariables {
  ; default persistant variables - if they are blank they will be set here. after that you can set
  ;  them programmaticaly in a script OR in the alt-R variables section, and they will preserver
  ;  even if you install a new version.
  ; see note below about why this function MUST be called on startup and reload events, to set proper keyfile name.

  ; keyfile name
  ; new change - we default to local MircryptionKeys if it exists - this saves confusion
  var %localkeyfile = $scriptdir $+ MircryptionKeys.txt
  if ( $exists(%localkeyfile) ) %mc_keyfile = %localkeyfile
  if (%mc_keyfile == $null) %mc_keyfile = $scriptdir $+ MircryptionKeys.txt
  else if ( $exists(%mc_keyfile) ) {
    ; file already exists
  }
  else %mc_keyfile = $scriptdir $+ MircryptionKeys.txt

  ; IMPORTANT ----> this MUST be called on start of script in order to set the proper keyfile for use by the dll
  ; set name of key file - without a full path this defaults to mirc directory
  ; but you can use a full explicit directory if you have multiple mircs that want to share a single keyfile.
  ;     var %keyfilename = $shortfn(%mc_keyfile)
  var %keyfilename = %mc_keyfile
  var %tmp = $dll( %mc_scriptdll , mc_setkeyfile , %keyfilename )

  ; If the variable %mc_keypassphrase exists, we try to unlock keyfile with it, so user does not have to enter it when mirc starts.
  ; VERY IMPORTANT!!! -> This is a big security risk - it means that if someone gains access to the files on your computer,
  ;  they can use your keyfile and thus decrypt all traffic on all your channels.  Use only if you are sure your machine is
  ;  secure.  We recommend you instead enter the passphrase manually once per irc session.
  if (%mc_keypassphrase != $null) /keypassphrase %mc_keypassphrase

  ; the following line checks the variable %mc_requirespass.  if it is set to yes, then no user can run mirc without
  ;  immediately entering the master passphrase.  note that this can be bypassed simply by modifying this script,
  ;  so is provided for minimal tamper protection only.
  if (%mc_requirespass == yes) /mc_requirepassphrase
  else %mc_requirespass = no

  ; set default values for variables
  setmcvariables_defaults
  mc_cleanbadvars

  ; temp global for keeping track if we are broadcasting a meow advert  
  .unset %mc_temp_mcmeowupgradeadvert
}


; called on startup

alias setmcvariables_defaults {
  ; set default variables

  ; indendation modes - use a number for indentation amount (2 is mirc default, 11 lines up after max nick size, nick means left-align under current nick (default) )
  if (%mc_indent == $null) %mc_indent = none
  if (%mc_indentplus == $null) %mc_indentplus = 0

  ; user can set which character at begining of line means reverse encryption (i like ' but am told its too easy to hit accidentally)
  if (%mc_reversechar == $null) %mc_reversechar = `

  ; an option to never encrypt text starting with ! which is useful for talking to bots
  if (%mc_encryptbangs == $null) %mc_encryptbangs = yes
  ; usually we want to leave this on

  ; user can change the tag used on OUTGOING text to indicate that text is encrypted.
  ;  normally this is "mcps", but you can change it IF you and your friends AGREE on something else.
  ;if (%mc_etag == $null) %mc_etag = mcps
  ; we use +OK default from now on
  if (%mc_etag == $null) %mc_etag = +OK

  ; we also provide a list of COMMA separated, incoming tags that if they are the first word in a string indicate a mircryption encrypted text
  if (%mc_dtags == $null) %mc_dtags = mcps,+OK

  ; options for responding to meow broadcasts (can be: always | never | match | noinfo)
  ; always = always reply and say whether crypting, keymatch,etc.
  ; never = never reply to meow broadcasts
  ; match = only repond when key matches
  ; noinfo = always respond, but never send info about encryption status or whether keys match
  if (%mc_meowreplymode == $null) %mc_meowreplymode = always

  ; user can decide whether to migrate passphrases for personal queries automatically when a user changes nick (yes | no | private)
  ; the private mode of tracknicks will ignore nick changes except in private queries or chats
  if (%mc_tracknicks == $null) %mc_tracknicks = no
  if (%mc_tracknicks_replace == $null) %mc_tracknicks_replace = no

  ; we can autocorrect user mistyping \ when they mean to type / for a command
  if (%mc_correctbackslashes == $null) %mc_correctbackslashes = no

  ; max topic length before we warn user (this changes for dif server
  if (%mc_maxtopiclen == $null) %mc_maxtopiclen = 115

  ; grab topic length automatically from the server on connect
  if (%mc_maxtopiclenautograb == $null) %mc_maxtopiclenautograb = yes

  ; name of the log viewer
  if (%mc_mircryptedfileviewerexe == $null) %mc_mircryptedfileviewerexe = MircryptedFileViewer.exe

  ; some ms agent speech default variables - create and set to defaults if they dont exist
  if (%mc_agent_enable == $null) %mc_agent_enable = no
  if (%mc_agent_afterspeech == $null) %mc_agent_afterspeech = nothing
  if (%mc_agent_options == $null) %mc_agent_options = -e off -h off
  if (%mc_agent_talkoptions == $null) %mc_agent_talkoptions = -lu
  if (%mc_agent_speakevents == $null) %mc_agent_speakevents = yes
  if (%mc_agent_actionanimations == $null) %mc_agent_actionanimations = yes
  if (%mc_agent_speechanimations == $null) %mc_agent_speechanimations = yes
  if (%mc_agent_replacemirc == $null) %mc_agent_replacemirc = yes
  if (%mc_agent_smartnames == $null) %mc_agent_smartnames = no
  if (%mc_agent_agentscanmove == $null) %mc_agent_agentscanmove = yes
  if (%mc_warnings == $null) %mc_warnings = yes
  if (%mc_agent_char_default == $null) %mc_agent_char_default = merlin.acs
  if (%mc_agent_char_mynick == $null) %mc_agent_char_mynick = disable

  ; link to nhtmln dll file by necroman, a web browser support dll
  if ((%mc_nhtmln_dllfilename == $null) || (!$exists(%mc_nhtmln_dllfilename))) %mc_nhtmln_dllfilename = nHTMLn_2.92.dll

  ; see the :notice: event description; incoming notices get displayed in $active in some cases where this is too wierd
  ;  so this fix puts them in status
  if (%mc_fixmircnoticebug = $null) %mc_fixmircnoticebug = yes

  ; ok now we set some hotkeys BUT only if they dont already exist - this is very important because it can case mirc to
  ;  sometimes exit this procedure prematurely if the hotkeys are already assigned.

  ; a hotkey for the (encrypted) textpad?
  if (%mc_textpadhotkey == $null) %mc_textpadhotkey = /sF11
  ;if (!$isalias(%mc_textpadhotkey)) alias %mc_textpadhotkey /textpad

  ; disable encrypted actions (for compatibility)
  if (%mc_eactiondisable == $null) %mc_eactiondisable = no

  ; does user want us to take over display of normal incoming/outgoing text (for better indenting)
  if (%mc_takeovernormal == $null) %mc_takeovernormal = no

  ; for auto setting window backgrounds based on crypt
  if (%mc_winback_options == $null) %mc_winback_options = -p
  if (%mc_winback_enabled == $null) %mc_winback_enabled = no
  if (%mc_winback_image_crypt == $null) %mc_winback_image_crypt = mircryption/winbackgrounds/mc_crypted.bmp
  if (%mc_winback_image_decryptonly == $null) %mc_winback_image_decryptonly = mircryption/winbackgrounds/mc_uncrypted.bmp
  if (%mc_winback_image_plain == $null) %mc_winback_image_plain = .

  ; for disabling titlebar stuff
  if (%mc_dontfixtitlebars == $null) %mc_dontfixtitlebars = no

  ; for disabling new nick coloring based on addressbook rules
  if (%mc_disablenickcolor == $null) %mc_disablenickcolor = no

  ; override takeover of ctcp
  if (%mc_blockctcp == $null) %mc_leavectcp = yes
  if (%mc_blockctcp_ping == $null) %mc_blockctcp_ping = yes

  ; self nick coloring is off by default
  if (%mc_enablenickcolorown == $null) %mc_enablenickcolorown = no

  ; treat channel names as different if they on dif bnc server prefixes?
  if (%mc_uniqueserverkeys == $null) %mc_uniqueserverkeys = no

  ; new stripping before signal
  if (%mc_cleansignal == $null) %mc_cleansignal = no

  ; do multispace -> 160 fix? use: yes, no, onlydoubles
  if (%mc_multispacefix == $null) %mc_multispacefix = yes

  ; split line size
  if (%mc_splitlinelen == $null) %mc_splitlinelen = 250
}


alias mc_cleanbadvars {
  ; delete any permanent variables introduced due to bug
  if (%cname != $null) unset %cname
  if (%nname != $null) unset %nname
  if (%retv != $null) unset %retv
}


alias setmctimers {  
  ; set window watcher timer - for fixing up captions of windows as they change from encrypted status to not
  ;  really annoying that we have to do it this way, but is a useful features
  %mc_curwincount = 0
  %mc_chatcount = 0
  %mc_querycount = 0
  .setmctimers2
}

alias setmctimers2 {
  ; every 2 seconds do a quick check for new query windows to fixup
  .timermcWindowWatcher 0  2 /mc_windowchangewatch
  ; every 10 seconds refresh captions of all windows no matter what
  .timermcWindowWatcher2 0  10 /mcfixalltopics periodic
}


; uninstall helper
alias mc_uninstall {
  ; uninstall script
  ; stop all timers
  .timermcWindowWatcher off
  .timermcWindowWatcher2 off
  ; erase all permanent variables related to script

  if ($1 != silent) {
    ; verify they really want to install it
    var %confirmer
    %confirmer = $input(Type the word 'uninstall' to confirm uninstallation:,1,Uninstall Mircryption)
    if (%confirmer != uninstall) {
      echo 4 -s Uninstallation of mircryption canceled.
      return
    }
    ; now unload the related scripts which dont work without mircryption
    .unload -rs mircryption\mpgp.mrc
    .unload -rs mircryption\mcboard.mrc
    .unload -rs mircryption\mcupdater.mrc
  }

  echo 4 -s Mircryption script $nopath($script) has been uninstalled.
  echo 4 -s To reinstall, type /load -rs mircryption\mircryption.mrc
  .dll -u  %mc_scriptdll
  .unload -rs mircryption.mrc
  .unload -rs mircryption\mircryption.mrc
  .unload -rs $script

  ; should we kill all mircryption variables? better not - let user delete these manually since they might want to keep them.
  ;unset %mc_*
  echo 4 -s All mircryption scripts have been uninstalled, but to ease reinstallation, all mircryption-related variables have been left in your alt+R variables list; to remove these, delete all variables begining with %mc_,%mcu_,%mcb_,%mpgp_.

  halt
}
; ---------------------------------------------------------------------------



































; ---------------------------------------------------------------------------
; helper functions

alias removefirstword {
  ; helper function, remove first word from string BUT preserve prefix spaces in remainder of string
  var %str | %str = $1-
  var %firstword = $gettok(%str,1,32)
  var %elen | %elen = $len($1-)
  %elen = %elen - $len(%firstword)
  %elen = %elen - 1
  if (%elen > 0) %str = $right(%str , %elen)
  else %str = $null
  return %str
}


alias cleanmultiserve {
  var %retv = $1-
  var %ppos

  ; 01/27/07 - make sure its safe length
  ; thanks to www.rainbowcrack-online.com and ircfuz for finding this dangerous possibility
  ;  more serious buffer overflow checks are also now in the dll as well
  if ( $len(%retv) > 60 ) %retv = $left(%retv,60)

  if (%mc_uniqueserverkeys == yes) {
    return %retv
  }

  %ppos = $pos( %retv , ~#, 1)
  if (%ppos == $null) %ppos = $pos( %retv , '#, 1)

  if (%ppos != $null) {
    var %len = $calc($len(%retv) - %ppos)
    %retv = $right(%retv , %len)
  }
  return %retv
}


alias mc_chanexists {
  var %querycount | %querycount = $query(0)
  var %chatcount | %chatcount = $chat(0)
  var %cname = $1
  var %ccount = 1

  while (%ccount <= %chatcount) {
    if ($chat(%ccount) == %cname) return $true
    inc %ccount
  }
  %ccount = 1
  while (%ccount <= %querycount) {
    if ($query(%ccount) == %cname) return $true
    inc %ccount
  }

  return $false
}


alias chatchan {
  ; chat channels have '=' in front of their names, we remove that

  var %cname = $1

  ; 01/27/07 - make sure its safe length
  ; thanks to www.rainbowcrack-online.com and ircfuz for finding this dangerous possibility
  ;  more serious buffer overflow checks are also now in the dll as well
  if ( $len(%cname) > 60 ) %cname = $left(%cname,60)


  if ($left(%cname , 1) == $chr(61)) {
    ; chat channel names have = in front, we remove that
    var %clen = $len(%cname)
    dec %clen
    %cname = $right(%cname , %clen)
  }
  else if ( $len(%cname) < 5 ) {
    ;
  }
  else if ( ( $left(%cname,4)  == chat ) && ( $mid(%cname,5,1) == $chr(32) ) ) {
    var %clen = $len(%cname)
    %clen = %clen - 5
    %cname = $right(%cname , %clen)
  }

  ; new add network name? - new 11/28/06
  if (%mc_uniqueserverkeys == yes) {
    var %ppos = $pos( %cname , ~#, 1)
    if (%ppos == $null) {
      %cname = %cname $+ ~# $+ $network
    }
    return %cname
  }

  if ($true) {
    ; new ability to alias channel names for encryption key lookup purposes - 11/28/06
    var %cnamen =  %cname $+ ~# $+ $network 
    ;echo DEBUGTEST2 cnamen is %cnamen
    var %aliasval = [ % $+ [ mc_cnamealias_ $+ [ %cnamen ] ] ]
    if ( %aliasval != $null) {
      %cname = %aliasval
      ;echo DEBUGTEST3 in with %aliasval
    }
    if ( %aliasval == $null) {
      ;echo DEBUGTESTb in with %aliasval
      %aliasval = [ % $+ [ mc_cnamealias_ $+ [ %cname ] ] ]
      if ( %aliasval != $null) {
        %cname = %aliasval
        ;echo DEBUGTEST3c in with %aliasval
      }
    }

    ;echo DEBUGTEST5 in with $1 out with %cname
  }

  ;echo DEBUGTEST5b in with $1 out with %cname

  return %cname
}


alias /mc_http {
  ; open the web page passed as $1
  if ($isalias(http)) /http $1-
  else /run $1-
}


; this will soon be converted to color nicks based on meow replies
alias meownicklist {
  var %line 1
  :LOOP
  if ($nick($1,%line) isvo $1) { cline 5 $1 $nick($1,%line) }
  if ($nick($1,%line) isop $1) { cline 4 $1 $nick($1,%line) }
  if ($nick($1,%line) isreg $1) { cline 6 $1 $nick($1,%line) }
  if ($nick($1,%line) == $me) && ($hget(theme,listbox.own) != $null) { cline 3 $1 $nick($1,%line) }
  if ($ignore(0) > 0) && ($ignore == $true) {
    var %temp5 1
    :loop2
    if ($ignore(%temp5) iswm $address($nick($1,%line),5)) && (channel isin $ignore(%temp5).type) { cline 14 $1 $nick($1,%line) }
    inc %temp5 1
    if (%temp5 <= $ignore(0)) { goto loop2 }
  }
  if ($nick($1,%line) == $null) { goto done }
  inc %line
  goto loop
  :DONE
  haltdef
}


;Multi-Kreate Directory by zack^ from www.mircscripts.org
; this is used with the encrypted logger to properly create directory trees
;Idea: Create mutliple levels of directories at once.
;Usage: /mkd <folderpath>
;Example: /mkd system/seen script
alias mc_mkd {
  if (!$1) {
    echo -a *** Syntax: /mkd <folderpath> Example: /mkd hello/whats/up
  }
  else {
    var %_ $replace($1-,$chr(47),$chr(92)),%' 2,%" $gettok(%_,1,92)
    ; v5.91 does not like this:     var %tempstr = $+(",%",")
    var %tempstr = " $+ %" $+ "
    if ($pos(%tempstr,:,1) == $null) {
      ;v5.91 does not like this:    .mkdir $+(",%",")
      .mkdir " $+ %" $+ "
    }
    while ($gettok(%_,%',92)) {
      ;v5.91 does not like this:          %" = $+(%",\,$ifmatch)
      %" = %" $+ \ $+ $ifmatch
      ;v5.91 does not like this:  .mkdir $+(",%",")
      .mkdir " $+ %" $+ "
      inc %'
    }
  }
}


alias mcactiondisable {
  ; return true if encrypted actions are disabled (useful for compatibility with other scripts
  if (%mc_eactiondisable == yes) return $true
  return $false
}


alias mc_cleanspaces {
  ; change any spaces to some other character
  var %spacestring = $chr(32)
  var %retstring = $replace($1-,%spacestring,_)
  return %retstring
}
; ---------------------------------------------------------------------------



; ---------------------------------------------------------------------------
; window background images

alias mc_updatewinbackground {
  ; new option (6/15/04) allows users to specify that crypted channels have certain images as background
  ; $1 is channel name, configure with vars: %mc_winback_options , %mc_winback_enabled , %mc_winback_image_crypt , %mc_winback_image_decryptonly , %mc_winback_image_plain

  ; /echo -s DEBUG: updating window background for $1

  ; skip any special windows
  if ($mid($1,1,1) == @) return

  ; if disabled, do nothing (note it does NOT clear images, in case use has customized their own)
  if (%mc_winback_enabled != yes && %mc_winback_enabled != clear) return

  ; this option is used to force clearing of any background images
  if (%mc_winback_enabled == clear) {
    /background -x $1
    return
  }

  ; figure out if they encrypting or decrypting or neither
  var %wname = $1
  var %cname = $chatchan($1)
  var %ecs1 | %ecs1 = $dll( %mc_scriptdll , mc_isencrypting , %cname)
  var %ecs2
  if (%ecs1 != yes) %ecs2 = $dll( %mc_scriptdll , mc_isdecrypting , %cname)
  else %ecs2 = yes

  ; ok if they are encrypting, use one image, if not another
  var %winbackimagename
  if (%ecs1 == yes) {
    %winbackimagename = %mc_winback_image_crypt
  }
  else if (%ecs2 == yes) {
    %winbackimagename = %mc_winback_image_decryptonly
  }
  else {
    %winbackimagename = %mc_winback_image_plain
  }

  if (%winbackimagename == $null) /background -x %wname
  else if (%winbackimagename == .) /background -x %wname
  else if ($exists(%winbackimagename) == $false) {
    /echo -s WARNING: mircryption cannot show the window background image %winbackimagename because the file does not exist; see the options in menu Mircryption -> More Commands -> Window Background Options
    /background -x %wname
  }
  else {
    /background %mc_winback_options %wname %winbackimagename
    ; /echo -s DEBUG: fixing window with ' /background %mc_winback_options %wname %winbackimagename '
  }
}


alias mc_winbackground_enable {
  if ($1 == yes) %mc_winback_enabled = yes
  else if ($1 == no) %mc_winback_enabled = no
  else if (%mc_winback_enabled == no) %mc_winback_enabled = yes
  else if (%mc_winback_enabled == yes) %mc_winback_enabled = no
  if (%mc_winback_enabled == no) %mc_winback_enabled = clear
  mcfixalltopics
  if (%mc_winback_enabled == clear) %mc_winback_enabled no
}


alias mc_winbackground_setimagefiles {
  ; let user configure files to use
  ; %mc_winback_options , %mc_winback_image_crypt , %mc_winback_image_decryptonly , %mc_winback_image_plain
  var %newval

  if (%mc_winback_image_crypt != $null) %newval = $input(Image to use for crypted channels (try mircryption/winbackgrounds/mc_crypted.bmp or use . for none):,1,Crypted Channel Image,%mc_winback_image_crypt)
  else %newval= $input(Image to use for crypted channels (try mircryption/winbackgrounds/mc_crypted.bmp or use . for none):,1,Crypted Channel Image)
  if (%newval != $null) %mc_winback_image_crypt = %newval
  if ($exists(%newval) == $false) {
    %mc_winback_image_crypt = mircryption/winbackgrounds/mc_crypted.bmp
  }

  if (%mc_winback_image_decryptonly != $null) %newval = $input(Image to use for decrypt-only channels (try mircryption/winbackgrounds/mc_uncrypted.bmp or use . for none):,1,Decrypt-only Channel Image,%mc_winback_image_decryptonly)
  else %newval= $input(Image to use for decrypt-only channels (try mircryption/winbackgrounds/mc_uncrypted.bmp or use . for none):,1,Decrypted-only Channel Image)
  if (%newval != $null) %mc_winback_image_decryptonly = %newval
  if ($exists(%newval) == $false) {
    %mc_winback_image_decryptonly = mircryption/winbackgrounds/mc_uncrypted.bmp
  }

  if (%mc_winback_image_plain != $null) %newval = $input(Image to use for non-crypted channels (try mircryption/winbackgrounds/mc_uncrypted.bmp or use . for none):,1,Non-crypted Channel Image,%mc_winback_image_plain)
  else %newval= $input(Image to use for non-crypted channels (try mircryption/winbackgrounds/mc_uncrypted.bmp or use . for none):,1,Non-crypted Channel Image)
  if (%newval != $null) %mc_winback_image_plain = %newval
  if ($exists(%newval) == $false) {
    %mc_winback_image_plain = mircryption/winbackgrounds/mc_uncrypted.bmp
  }

  if (%mc_winback_options != $null) %newval = $input(Mirc /background image options.  Choose from -c (center)  -f (fill)  -n (normal)  -r (stretch)  -t (tile)  -p (picture):,1,Mirc /background command options,%mc_winback_options)
  else %newval= $input(Mirc /background image options.  Choose from -c (center)  -f (fill)  -n (normal)  -r (stretch)  -t (tile)  -p (picture):,1,Mirc /background command options)
  if (%newval != $null) %mc_winback_options = %newval
  if (%mc_winback_options == $null) %mc_winback_options = -p

  ; now enable and refresh
  %mc_winback_enabled = yes
  mcfixalltopics
}
; ---------------------------------------------------------------------------














; ---------------------------------------------------------------------------
; functions to detect whether an incoming line is mircrypted or not
; usually this is so if the first word is "mcps" but we use a function
; starting with version 3.7, to allow greater flexibility
alias mc_isetag {
  var %firstword | %firstword = $gettok( $1 , 1 , 32)
  if (%firstword == $null) %firstword = $1

  ; always recognize mcps as a decryptable dtag
  if (%firstword == mcps) return $true

  ; always identify the outgoing etag as a decryptable dtag
  if (%firstword == %mc_etag) return $true

  ; %mc_dtags might be a list of COMMA separated keywords which all indicate mircryption encrypted text
  if ($istok(%mc_dtags,%firstword,44)) return $true

  return $false
}

alias mc_isetag2 {
  ; new mircryption codeing is to use start and end tags with decrypt verification
  var %tagstart = $chr(171) $+ m $+ $chr(171)
  if ( $pos( $1- , %tagstart , 1 ) > 0 ) return $true
  return $false
}

alias mc_isetag3 {
  ; new mircryption codeing is to use start and end tags with decrypt verification
  var %tagstart = $chr(171) $+ m $+ $chr(171)
  if ( $pos( $1- , %tagstart , 1 ) > 0 ) return $true

  var %firstword | %firstword = $gettok( $1 , 1 , 32)
  if (%firstword == $null) %firstword = $1

  ; always recognize mcps as a decryptable dtag
  if (%firstword == mcps) return $true
  if (%firstword == +OK) return $true

  ; always identify the outgoing etag as a decryptable dtag
  if (%firstword == %mc_etag) return $true

  ; %mc_dtags might be a list of COMMA separated keywords which all indicate mircryption encrypted text
  if ($istok(%mc_dtags,%firstword,44)) return $true

  return $false
}
; ---------------------------------------------------------------------------















































; ---------------------------------------------------------------------------
;## Logging routines based on original code for a script called "log.mrc"
;##  aka (advanced logging) v1.0 by ash (ash@scripters-austnet.org).
;## This version is now modified to work with mircryption, to record
;##  encrypted channel text.
;## Other changes:
;##  Added ability to use dates in filenames.
;##  Added option for noencrypt
;##  Added event type topic
;##  Added help
;##  Added function to ask use for rule text/num if not specified on add/del
;##  Added support for indicating whether text to be displayed is encrypted
;##  Trying to add support for Sesstion Start and Session End tags(?)
;## More.. see help file
; ---------------------------------------------------------------------------


; ---------------------------------------------------------------------------
; name of file holding log rules
alias mc_logfile { return mclog.cfg }

; name of key used to store encrypted passphrase for logging
alias mc_loggingkey { return _mcloggingkey }
; ---------------------------------------------------------------------------


; ---------------------------------------------------------------------------
; display some help about creating logging rules
alias mcloghelp {
  echo 7 -si4 - 
  echo 7 -si4 . NOTE: For detailed info see help file (Help->Help Files->MircryptionSuite).
  echo 7 -si4 .  
  echo 7 -si4 . Encrypted logging is based on original code for a script called "log.mrc"
  echo 7 -si4 .  aka (advanced logging) v1.0 by ash (ash@scripters-austnet.org).
  echo 7 -si4 .
  echo 7 -si4 . /mclog add RULETEXT.. (see below for log rule format)
  echo 7 -si4 . /mclog del RULENUM
  echo 7 -si4 . /mclog list
  echo 7 -si4 . 
  echo 7 -si4 . Rules are of the form:
  echo 7 -si4 .   log <events> in <targets> from <nicknames> to <output> [options]
  echo 7 -si4 . 
  echo 7 -si4 . <events> - input,text,notice,snotice,join,part,action,kick,quit,nick,mode,topic,all (prefix with ! to negate).
  echo 7 -si4 . <targets> - channel, nickname (for query), a '#' or '?' to match all channel/queries.  Seperate targets by commas.
  echo 7 -si4 . <nicknames> - user(s) triggering the event, seperated by commas.  Use * for wildcard.  Prefix nicks with @ or + to indicate that they must be opped or voiced.
  echo 7 -si4 . <output> - output is where the log is sent to.  This can be a file, a window, a #channel/nick, or a command.
  echo 7 -si4 ... Each output is prefixed by type, ie: "window @hi" or "irc nick/#chan" or "file &t.&w.log"
  echo 7 -si4 ... Special characters usable in file name:
  echo 7 -si4 ......  &a  - value of $active (active window)
  echo 7 -si4 ......  &c  - value of $chan
  echo 7 -si4 ......  &t  - Target (usefull for rules involving both channels AND queries)
  echo 7 -si4 ......  &n  - Nickname
  echo 7 -si4 ......  &w  - Network
  echo 7 -si4 ......  &dd - date (format yyyy_mm_dd)
  echo 7 -si4 ......  &dm - date (format mmm_yyyy)
  echo 7 -si4 ......  &dfyyyy = $asctime(yyyy)
  echo 7 -si4 ......  &dfyy = $asctime(yy)
  echo 7 -si4 ......  &dfmmmm = $asctime(mmmm)
  echo 7 -si4 ......  &dfmmm = $asctime(mmm)
  echo 7 -si4 ......  &dfmm = $asctime(mm)
  echo 7 -si4 ......  &dfm = $asctime(m)
  echo 7 -si4 ......  &dfdddd = $asctime(dddd)
  echo 7 -si4 ......  &dfddd = $asctime(ddd)
  echo 7 -si4 ......  &dfdd = $asctime(dd)
  echo 7 -si4 ......  &dfd = $asctime(d)
  echo 7 -si4 ......  &dpw - month section (1-4) , &dpt - month section (1-8)
  echo 7 -si4 ......  &dsd - date as subdir format yyy\mmm
  echo 7 -si4 . <options> - extra options (strip,notimestamp,noencrypt,stop)
  echo 7 -si4 ....... strip = remove mirc colors, noencrypt = dont encrypt file, stop = dont trigger subsequent log rules for event
  echo 7 -si4 .
  echo 7 -si4 . Example rules:
  echo 7 -si4 ... "log all in #,? from * to file Logs\&t.&w.log"
  echo 7 -si4 ...... Standard mirc logging
  echo 7 -si4 ... "log join,part in #mircryption,# from * to file Logs\modes.&c.log strip notimestamp"
  echo 7 -si4 ...... This will log all joins and parts in #mircryption or any other channel (#) from any nickname to the file modes.<#channelname>.log with no timestamp. The 'strip' on the end means that control codes are stripped from every event.
  echo 7 -si4 ... "log !notice,all in !#freetibet,#,? from * to file &t.&w.log"
  echo 7 -si4 ...... Prevent logging of notices and all text in channel #freetibet (negated parameters *must* come first)
  echo 7 -si4 - 
}
; ---------------------------------------------------------------------------


; ---------------------------------------------------------------------------
; management function, load configuration file into hash table, add/del rule
;  /mclog add RULE...
;  /mclog del RULENUM
;  /mclog list
;  /mclog flush
;  /mclog reload

alias mclog {
  if ($left($1,1) == -) { var %s = $1 | tokenize 32 $2- }
  if ($1 == reload) {
    if (q !isin %s) { mc_logecho reloading log rule configuration file. }
    if ($hget(log)) { hfree log }
    hmake log 20
    mc_logaddendsessions
    hmake usedlogfiles 10
    if ($exists($mc_logfile)) {
      var %c = 1
      while (%c <= $lines($mc_logfile)) {
        hadd log $mc_logid $read($mc_logfile,tn,%c)
        inc %c
      }
      if (%c > 1) {
        if (qq !isin %s) echo 7 -si2 MircryptionSuite - Advanced Encrypted Logging is active.
      }
    }
    else {
      write $mc_logfile
      if (q !isin $1-) { 
        mc_logecho no logging configuration file (mclog.cfg) found, so a blank one was created.  Encrypted logging will remain inactive until you add rules.
      }
    }
  }
  if ($1 == add) {
    var %ruletext = $2-
    if (%ruletext == $null) {
      ; ask user for rule
      %ruletext = $input(Rule to add:,1,Add new logging rule)
    }
    var %firstword = $gettok(%ruletext,1,32)
    if ((%firstword != nolog) && (%firstword != log)) {
      echo 4 Logging rule %ruletext is not understood, all log rules should begin with "log ..." or "nolog ..." (to disable)
    }
    else {
      write $mc_logfile %ruletext
      if ($hget(log)) { 
        hadd log $mc_logid %ruletext
        mc_logecho rule added: %ruletext
      }
    }
  }
  if ($1 == change) {
    var %rulenum = $3
    if (%ruletext == $null) {
      ; ask user for rule
      %rulenum = $input(Number of the rule to change:,1,Change a logging rule)
      if (%rulenum == $null) return
    }
    var %ruletext = $2-
    if (%ruletext == $null) {
      ; ask user for rule
      var %oldrule = $hget(log,%rulenum).data
      %ruletext = $input(New Rule (should start with log, or nolog to diable):,1,Modify logging rule,%oldrule)
      if (%ruletext == $null) return
    }
    var %firstword = $gettok(%ruletext,1,32)
    if ((%firstword != nolog) && (%firstword != log)) {
      echo 4 Logging rule %ruletext is not understood, all log rules should begin with "log ..." or "nolog ..." (to disable)
    }
    else {
      ; first delete
      if ($hget(log,%rulenum).item) {
        hdel log $hget(log,%rulenum).item
      }
      ; now add  the rule
      write -l $+ %rulenum $mc_logfile %ruletext
      if ($hget(log)) { 
        hadd log $mc_logid %ruletext
        mc_logecho rule %rulenum changed to %ruletext
        ; now we must force a reload
        .timer 1 1 mclog -q -qq reload
      }
    }
  }
  if ($1 == list) {
    if ($hget(log)) {
      var %d = $hget(log,0).item
      if (%d) {
        mc_logecho there $iif(%d == 1,is,are) %d active logging rule $+ $iif(%d > 1,s):
        var %c = 1
        while (%c <= %d) {
          mc_logecho %c $+ . $hget(log,%c).data
          inc %c
        }      
      }
      else {
        mc_logecho no active logging rules.
      }
    }
    else {
      mc_logecho the logger is not currently running - to start it do /log restart
    }
  }
  if ($1 == flush) {
    .remove $mc_logfile
    hdel -w log *
  }
  if ($1 == del) || ($1 == delete) {
    var %ruletext = $2-
    if (%ruletext == $null) {
      ; ask user for rule
      %ruletext = $input(Rule # to delete:,1,Delete existing logging rule)
    }
    if (%ruletext isnum) {
      if ($hget(log,%ruletext).item) {
        if (q !isin %s) { mc_logecho deleted %ruletext $+ . $hget(log,%ruletext).data }
        hdel log $hget(log,%ruletext).item
        write -d $+ %ruletext $mc_logfile
      }
    }
    else {
      var %c = 1
      while (%c <= $hget(log,0).item) {
        if ($hget(log,%c).data == %ruletext) {
          mc_logecho deleted: %c $+ .  $ifmatch
          hdel log $hget(log,%c).item
          write -d $+ %c $mc_logfile
        }
        inc %c
      }
    }
  }
  halt
}
; ---------------------------------------------------------------------------


; ---------------------------------------------------------------------------
; logging helper functions

alias mc_logecho {
  echo $colour(info) -ta mircryption logger: $1-
}

alias mc_logid {
  if ($hget(log)) {
    var %c = 1
    var %t = 0
    while (%c <= $hget(log,0).item) {
      if ($right($hget(log,%c).item,-1) > %t) {
        %t = $ifmatch
      }  
      inc %c
    }
    ;v5.91 does not like this:    var %retv = $+(r,$calc(%t + 1))
    var %retv = r $+ $calc(%t + 1)
    return %retv
  }
}
; ---------------------------------------------------------------------------


; ---------------------------------------------------------------------------
; parse a line of text and figure out where to save it
; $1 = event type (text,notice,action,join,topic,part,kick,quit,nick,mode)
; $2 = target (chan)
; $3 = target ? (nick)
; $4 = text
; $5 = $address (blank in current version)
; $6 = $true if it was originally encrypted or $false if not

alias mc_logparse {
  ; fixup target
  var %debuglog = $false
  var %savedtolog = $false

  var %arg2 = $2
  var %arg3 = $3
  var %activea = $active
  var %chanval = $chan
  if (%arg2 == $null) %arg2 = $chan
  if (%arg2 == $null) %arg2 = $active
  if (%arg2 == Status Window) %arg2 = Status_Window
  ;  if (%chanval == $null) %chanval = %arg2
  if (%activea == Status Window) %activea = Status_Window

  ; for debugging
  if (%debuglog) {
    echo 5 DebugLogging:  event= $1 , in= %arg2 , from= %arg3 (&c = $chan , &a = %activea )
  }

  if ($6) {
    ; Trigger signal for other scripts that want to handle decrypted text.
    ; Only triggers for text that was received encrypted or outgoing crypted, which
    ;  allows other scripts to be written to trigger on incoming encrypted text, without having to modify mircryption.
    if ($version >= 6.0) {
      ;set global channel,nick replacement, for replacement in signals
      if ($chan != $null) %mc_chan = $chan
      else %mc_chan = %arg2
      if ($nick != $null) %mc_nick = $nick
      else %mc_nick = %arg3
      .signal MircryptionSignal $1 %arg2 %arg3 $4
    }
  }

  ; new replacement signal triggered on encrypted AND noncrypted and which can be halted
  ; Trigger signal for other scripts that want to handle decrypted text.
  ; Only triggers for text that was received encrypted or outgoing crypted, which
  ;  allows other scripts to be written to trigger on incoming encrypted text, without having to modify mircryption.
  if ($version >= 6.0) {
    ;set global channel,nick replacement, for replacement in signals
    if ($chan != $null) %mc_chan = $chan
    else %mc_chan = %arg2
    if ($nick != $null) %mc_nick = $nick
    else %mc_nick = %arg3

    ; ATTN: new 12/8/05 - mouser - strip colors and stuff before signaling?
    ;.signal -n MircryptionSignalAll $1 %arg2 %arg3 $6 $4
    var %clean4 = $4
    if (%mc_cleansignal == yes) {
      %clean4 = $strip(%clean4)
      var %find_str = $chr(160)
      var %rep_str = $chr(32)
      %clean4 = $replace(%clean4,%find_str,%rep_str)
    }
    .signal -n MircryptionSignalAll $1 %arg2 %arg3 $6 %clean4
  }

  var %c = 1
  var %temptext
  while (%c <= $hget(log,0).item) {
    var %r = $hget(log,%c).data
    var %firstword = $gettok(%r,1,32)
    if (%firstword == nolog) {
      ; disable this rule
    }
    else if (%firstword == log) {
      var %e = $gettok(%r,2,32)
      if ($mc_log.event($1,%e)) {
        var %t = $gettok(%r,$calc($findtok(%r,in,32) + 1),32)
        if ($mc_log.target(%arg2,%t)) {
          var %n = $gettok(%r,$calc($findtok(%r,from,32) + 1),32)
          if ($mc_log.from(%arg3,%arg2,%n)) {
            ; this rule matches
            var %o = $gettok(%r,$calc($findtok(%r,to,32) + 1),32)
            var %f = $gettok(%r,$calc($findtok(%r,to,32) + 2),32)

            ; mirc v5.91 does not like this:  var %options = $gettok(%r,$+($calc($findtok(%r,to,32) + 3),-),32)
            var %temptoky = $calc($findtok(%r,to,32) + 3) $+ -
            var %options = $gettok(%r,%temptoky,32)
            var %log = $mc_log.line(%options,$1,%arg2,%arg3,$4,$5,$6,$7)

            if (%o == file) {
              ; figure out filename
              var %pbuf = ;z`

              ; old method
              var %dateday = %pbuf $+ $asctime(yyyy_mm_dd) $+ %pbuf
              var %datemonth = %pbuf $+ $asctime(mmm_yyyy) $+ %pbuf
              var %datesubdirs = %pbuf $+ $asctime(yyyy\mmm) $+ %pbuf
              var %daynum = %pbuf $+ $asctime(d) $+ %pbuf

              ; new method
              var %datef_yyyy = %pbuf $+ $asctime(yyyy) $+ %pbuf
              var %datef_yy = %pbuf $+ $asctime(yy) $+ %pbuf
              var %datef_mmmm = %pbuf $+ $asctime(mmmm) $+ %pbuf
              var %datef_mmm = %pbuf $+ $asctime(mmm) $+ %pbuf
              var %datef_mm = %pbuf $+ $asctime(mm) $+ %pbuf
              var %datef_m = %pbuf $+ $asctime(m) $+ %pbuf
              var %datef_dddd = %pbuf $+ $asctime(dddd) $+ %pbuf
              var %datef_ddd = %pbuf $+ $asctime(ddd) $+ %pbuf
              var %datef_dd = %pbuf $+ $asctime(dd) $+ %pbuf
              var %datef_d = %pbuf $+ $asctime(d) $+ %pbuf
              var %odaynum = $asctime(d)
              var %weekpart = %pbuf $+ $mclog_monthpart(%odaynum,7) $+ %pbuf
              var %tenpart = %pbuf $+ $mclog_monthpart(%odaynum,4) $+ %pbuf

              var %arg2f = $mc_log.safefilename(%arg2)
              var %arg3f = $mc_log.safefilename(%arg3)
              var %activeaf = $mc_log.safefilename(%activea)
              var %chanvalf = $mc_log.safefilename(%chanval)
              ;              var %filename = $replace(%f,&t,%arg2,&c,%chanval,&a,%activea,&n,%arg3,&w,$network,&dsd,%datesubdirs,&dpw,%weekpart,&dpt,%tenpart,&dd,%dateday,&dm,%datemonth,&dc,%datecustom)

              var %filename = $replace(%f,&dfyyyy,%datef_yyyy,&dfyy,%datef_yy,&dfmmmm,%datef_mmmm,&dfmmm,%datef_mmm,&dfmm,%datef_mm,&dfm,%datef_m,&dfdddd,%datef_dddd,&dfddd,%datef_ddd,&dfdd,%datef_dd,&dfd,%datef_d,&dpw,%weekpart,&dpt,%tenpart,&t,%arg2f,&c,%chanvalf,&a,%activeaf,&n,%arg3f,&w,$network,&dd,%dateday,&dm,%datemonth,&dc,%datecustom)

              ; remove pbufs
              %filename = $replace(%filename,%pbuf,$null)

              ; fix bad file chars
              %filename = $replace(%filename,*,_,?,_,$chr(34),_,$chr(32),_,<,_,>,_,|,_)

              ; we need to add a session start if file does not yet exist or is empty
              if ($hfind(usedlogfiles, %filename, 1) == $null ) {
                ; we havent written this file yet this session, so do the session start
                %temptext = Session Start: $fulldate
                ;  make the path if nesc.
                var %fpath = %filename
                ; convert forward slash to backslash
                %fpath = $replace(%fpath,$chr(47),$chr(92))
                var %lastone = $numtok(%fpath,92)
                ; remove filename from fpath
                if (%lastone > 0) {
                  %fpath = $deltok(%fpath,%lastone,92)
                  ; make the prefix dir
                  if (%fpath != $null) {
                    if (!$exists(%fpath)) mc_mkd %fpath
                  }
                }
                ; try again to write file
                if ($exists(%fpath)) {
                  write %filename %temptext
                }
                if (!$isfile(%filename)) {
                  echo 4 -si file %filename could not be opened for encrypted logging.
                }
              }


              ; write text
              ; echo Writing log entry to %filename
              write %filename %log
              %savedtolog = $true
              ; update used file hash
              hadd -m usedlogfiles %filename %filename
              ; special echo if they are logging from special custom notes channel
              if (%arg2 == @LogNotes) {
                echo 4 Logging to %filename $+ :
                if ($istok(%options,noencrypt,32)) echo < $+ $me $+ > $4
                else echo $chr(91) $+ $me $+ $chr(93) $4
              }
            }
            if (%o == window) {
              echo %f %log
            }
            if (%o == irc) {
              .msg %f %log
            }
            if (%o == command) {
              %f %log
            }
            if ($istok(%options,stop,32)) {
              ; dont process any more log rules
              return
            }
          }
        }
      }
    }
    else {
      echo 4 -si Logging rule %e is not understood, all log rules should begin with "log ..." or "nolog ..." (to disable)
    }
    inc %c
  }

  if ( (%arg2 == @LogNotes) && (%savedtolog == $false) ) {
    ; warn them that their log text was NOT logged
    echo 4 No matching rule matched for @LogNotes - logging notes were not saved.
  }
}

; add "Session Close" tags to all files we modified during this run
alias mc_logaddendsessions {
  ; to do this we need to keep a hash of all files we have modified, 'usedlogfiles'

  if ($hget(usedlogfiles) != $null) {
    var %c = 1
    var %filename
    var %logtext = Session Close: $fulldate
    while (%c <= $hget(usedlogfiles,0).item) {
      %filename = $hget(usedlogfiles,%c).data
      ;%filename = $hget(usedlogfiles,%c)
      if ($isfile(%filename)) {
        write %filename %logtext
      }
      inc %c
    }
    ; now we want to clear hash table so that we will readd session start if new logging
    hfree usedlogfiles
  }
}
; ---------------------------------------------------------------------------


; ---------------------------------------------------------------------------
; helper functions called by log_parse to decide whether to log an event

alias mc_log.event {
  var %c = 1
  while (%c <= $numtok($2,44)) {
    var %t = $gettok($2,%c,44)
    if (%t == all) { return $true }
    if ($1 == %t) { return $true }
    if (($left(%t,1) == !) && ($right(%t,-1) == $1)) { return $false }
    inc %c
  }
}

alias mc_log.target {
  var %t2 = 1
  var %tc
  while (%t2 <= $numtok($2,44)) {
    %tc = $gettok($2,%t2,44)
    if (($iif($left($1,1) == $chr(35),$chr(35),?) == %tc) || ($1 == %tc)) { return $true }
    if (($left(%tc,1) == !) && ($right(%tc,-1) == $1)) { return $false }
    inc %t2
  }
}

alias mc_log.from {
  var %t2 = 1
  var %tc
  while (%t2 <= $numtok($3,44)) {
    %tc = $gettok($3,%t2,44)
    if ($left(%tc,1) == @) { if ($1 !isop $2) { inc %t2 | continue } | else { %tc = $right(%tc,-1) } }
    if ($left(%tc,1) == +) { if ($1 !isvo $2) { inc %t2 | continue } | else { %tc = $right(%tc,-1) } }
    if (%tc iswm $1) { return $true }
    inc %t2
  }
}


alias mc_log.safefilename {
  ; remove any / and \ from filename since
  var %retv = $1-
  var %goodstr
  var %badstr
  %badstr = $chr(47)
  %goodstr = $chr(95)
  %retv = $replace(%retv,%badstr,%goodstr)
  %badstr = $chr(92)
  %goodstr = $chr(95)
  %retv = $replace(%retv,%badstr,%goodstr)
  return %retv
}
; ---------------------------------------------------------------------------


; ---------------------------------------------------------------------------
; compute text to log
; $1 = rule options
; $2 = event type (text,notice,action,join,topic,part,kick,quit,nick,mode)
; $3 = target (chan)
; $4 = target ?
; $5 = ?
; $6 = ?
; $7 = $true if it was originally encrypted or $false if not

alias mc_log.line {
  var %retv

  if (($2 == text) || ($2 == input) || ($2 == query) || ($2 == chat)) {
    if ($7) %retv = $chr(91) $+ $4 $+ $chr(93) $5
    else %retv = < $+ $4 $+ > $5
  }
  else if ($2 == notice) {
    if ($left($3,1) == $chr(35)) {
      if ($7) %retv = - $+ $4 $+ : $+ $3 $+ - $5 [e]
      else %retv = - $+ $4 $+ : $+ $3 $+ - $5
    }
    else {
      if ($7) %retv = - $+ $4 $+ - $5 [e]
      else %retv = - $+ $4 $+ - $5
    }
  }
  else if ($2 == snotice) {
    %retv = - $+ $4 $+ - *** $5
  }
  else if (($2 == action) || ($2 == queryaction)) {
    if ($7) %retv = * $4 $5 [e]
    else %retv = * $4 $5
  }
  else if ($2 == join) {
    %retv = *** $4 ( $+ $5 $+ ) has joined $3 
  }
  else if ($2 == topic) {
    if ($7) %retv = *** $4 changes topic to $5 ( $+ $3 $+ )
    else %retv = *** $4 changes topic to $5 ( $+ $3 $+ )
  }
  else if ($2 == part) {
    %retv = *** $4 ( $+ $5 $+ ) has left $3 
  }
  else if ($2 == kick) {
    %retv = *** $6 was kicked $4 ( $+ $7 $+ )
  }
  else if ($2 == quit) {
    %retv = *** $4 ( $+ $5 $+ ) quit IRC ( $+ $6 $+ )
  }
  else if ($2 == nick) {
    %retv = *** $4 ( $+ $5 $+ ) is now known as $6
  }
  else if ($2 == mode) {
    %retv = *** $4 sets mode $6
  }
  else {
    %retv = $3-
  }

  ; we have the core text to return, now post-process depending on options

  var %options = $1
  if ($istok(%options,strip,32)) { %retv = $strip(%retv) }
  if (!$istok(%options,notimestamp,32)) { %retv = $timestamp %retv }
  if (!$istok(%options,noencrypt,32)) {
    ; encrypt the text to log
    if (%mc_scriptdll != $null) {
      var %nretv = $dll( %mc_scriptdll , mc_encrypt2 , $mc_loggingkey %retv )
      if ( (%retv == %nretv) || (%nretv == $null)) {
        echo 4 -s Mircryption key for encrypted logging could not be found, please set the key, disable loggin, or add 'noencrypt' option to logging rule.
        return $null
      }
      %retv = %nretv
    }
    else {
      echo 4 -s Mircryption dll not found, so encrypted text is not logged.
      return $null
    }
  }

  ; return the result
  return %retv
}
; ---------------------------------------------------------------------------


; ---------------------------------------------------------------------------
alias setloggingkey {
  ; set the logging encryption key in mircryption keyfile

  ; key to use for storing encryption key
  var %cname = $mc_loggingkey
  var %kname

  ; get current value of key
  var %prevkey = $dll( %mc_scriptdll  , mc_displaykey , %cname)

  if ($1 == $null) {
    if (%prevkey != $null) %kname = $input(Use words and symbols (20-50 characters) and prefix with 'cbc:' to use new CBC mode:,1,Set new keyphrase for encrypting logs,%prevkey)
    else %kname = $input(Use words and symbols (20-50 characters) and prefix with 'cbc:' to use new CBC mode:,1,Set new keyphrase for encrypting logs)
    if (%kname == $null) {
      ; attempt to bleach variable from memory
      %kname = $str(x , [ $len(%kname) ] )
      return
    }
  }
  else { %kname = $1- }

  var %retv | %retv = $dll( %mc_scriptdll  , mc_setkey , %cname %kname)
  if ((%retv != $null) && (%retv != %cname)) echo 4 -s %retv
  ; attempt to bleach variable from memory
  %kname = $str(x , [ $len(%kname) ] )
}
; ---------------------------------------------------------------------------


; ---------------------------------------------------------------------------
; The original log script trapped events to record, but these are now
;  called by mircryption instead, since we want mircryption to DECODE
;  them prior to RE-ENCODING them.
;on *:text:*:*:{
;  return $mc_logparse(text,$target,$nick,$1-,$address,$false)
;}
;on *:notice:*:*:{
;  return $mc_logparse(notice,$target,$nick,$1-,$address,$false)
;}
;on *:input:*:{
;  if ($left($1,1) != /) { return $mc_logparse(text,$target,$me,$1-,$address,$false) }
;}
;on *:action:*:*:{
;  return $mc_logparse(action,$target,$nick,$1-,$address,$false)
;}
;on *:topic:*:*:{
;  return $mc_logparse(action,$target,$nick,$1-,$address,$false)
;}
; ---------------------------------------------------------------------------


; ---------------------------------------------------------------------------
; IMPORTANT - we use to have some ON event catchers here, but we moved them up to normal event catchers
;  since we just discovered (5/3/03 v1.09.33) that mirc wont trigger to the second duplicate ON event.
; ---------------------------------------------------------------------------




; ---------------------------------------------------------------------------
alias mclogviewer {
  ; launch the log viewer
  if (!$exists(%mc_mircryptedfileviewerexe)) %mc_mircryptedfileviewerexe = MircryptedFileViewer.exe
  if (!$exists(%mc_mircryptedfileviewerexe)) %mc_mircryptedfileviewerexe = mircryption\MircryptedFileViewer.exe

  if (!$exists(%mc_mircryptedfileviewerexe)) echo 4 MircryptedFileViewer.exe was not found in mircryption subdirectory.
  else {
    var %cname = $mc_loggingkey
    var %arg = $dll( %mc_scriptdll  , mc_displaykey , %cname)
    if (%arg != $null) /run %mc_mircryptedfileviewerexe . " $+ %arg $+ "
    else /run %mc_mircryptedfileviewerexe
    ; attempt to bleach variable from memory
    %arg = $str(x , [ $len(%arg) ] )
  }
}
; ---------------------------------------------------------------------------


; ---------------------------------------------------------------------------
alias mclog_monthpart {
  ; used to tell you which 'section' of the month you are in (call with '/monthpart day 7' to tell you which week #)
  var %daynum = $int($calc(($1 - 1) / $2 ))
  %daynum = %daynum + 1
  ; echo part value is %daynum
  return %daynum
}
; ---------------------------------------------------------------------------


; ---------------------------------------------------------------------------
alias mclognotes {
  ; open window for them to type notes to log
  /window -aE @LogNotes
}
; ---------------------------------------------------------------------------
















; ---------------------------------------------------------------------------
; helper for new cbc mode
alias mcbcup {
  ; upgrade key to cbc
  var %cname
  var %kname
  if ($1 == $null) {
    %cname = $active
  }
  else if ($2 == $null) {
    %cname = $1
  }

  var %wname = %cname
  %cname = $chatchan(%cname)

  if (%cname == Status Window) {
    echo 4 You cannot encrypt the status window. Erm.. Why would you want to do that anyway?
    return
  }

  var %kname = $dll( %mc_scriptdll  , mc_displaykey , %cname)
  if (%kname == $null) {
    echo 4 No key set for %cname, so it can't be upgraded
    return
  }

  if ( $left(%kname,4) == cbc: ) {
    echo 4 Key for %cname is already in cbc mode, so it can't be upgraded.
    return
  }

  %kname = cbc: $+ %kname

  var %retv | %retv = $dll( %mc_scriptdll  , mc_setkey , %cname %kname)
  if ((%retv != $null) && (%retv != %cname)) echo 4 %retv

  mcfixtopic_smart %wname
}



alias mcbcdown {
  ; downgrade key to ecb
  var %cname
  var %kname
  if ($1 == $null) {
    %cname = $active
  }
  else if ($2 == $null) {
    %cname = $1
  }

  var %wname = %cname
  %cname = $chatchan(%cname)

  if (%cname == Status Window) {
    echo 4 You cannot encrypt the status window. Erm.. Why would you want to do that anyway?
    return
  }

  var %kname = $dll( %mc_scriptdll  , mc_displaykey , %cname)
  if (%kname == $null) {
    echo 4 No key set for %cname, so it can't be upgraded
    return
  }

  if ($left(%kname,4) != cbc: ) {
    echo 4 Key for %cname is not set to cbc mode, so it can't be downgraded.
    return
  }

  %kname = $mid(%kname,5)

  var %retv | %retv = $dll( %mc_scriptdll  , mc_setkey , %cname %kname)
  if ((%retv != $null) && (%retv != %cname)) echo 4 %retv

  mcfixtopic_smart %wname
}
; ---------------------------------------------------------------------------























































; ---------------------------------------------------------------------------
; Helper function for signals.
; helper for $chan replacement on signal
alias mcchan {
  ;  echo -s in mcchan with mcchan = %mc_chan and chan = $chan
  ;  if (%mc_chan != $null) return %mc_chan
  if ($chan == $null) return %mc_chan
  return $chan
}

alias mcnick {
  ;  echo -s in mcnick with mcnick = %mc_nick and nick = $nick
  if (%mc_nick != $null)  return %mc_nick
  if ($nick == $null) return %mc_nick
  return $nick
}

alias clearmcnickchan {
  %mc_nick = $null
  %mc_chan = $null
}

alias ischanencrypted {
  if ($dll( %mc_scriptdll ,mc_isencrypting , $1) == yes)  return $true
  return $false
}
; ---------------------------------------------------------------------------




; ---------------------------------------------------------------------------
alias mchaltclear {
  ; clear mchalt flags
  unset %mc_halt_flag
  unset %mc_haltdef_flag
}

alias mchalt {
  ; set the flag saying that we should ignore this text (used by MircryptionSignalAll below)
  %mc_halt_flag = $true
}

alias mchaltdef {
  ; set the flag saying that we should ignore this text and tell mirc toignore it too (used by MircryptionSignalAll below)
  %mc_haltdef_flag = $true
}

alias mchandlehalt {
  ; handle haltdef stuff
  var %retv
  if (%mc_haltdef_flag == $true) {
    .mchaltclear
    /haltdef
    return $true
  }
  if (%mc_halt_flag == $true) {
    .mchaltclear
    return $true
  }
  return $false
}
; ---------------------------------------------------------------------------





; ---------------------------------------------------------------------------
; THIS IS ONLY FOR LEGACY USE - DONT USE THIS ONE ANYMORE
; Here is OLD OLD OLD sample signal trap for catching text after it has been decrypted.
;  you can implement this signal in your other scripts if you want to detect
;  and act on text after it is decrypted or encrypted.  check $1 for the
;  type of event.
; DONT add your code to this procedure(!!) because it will be overwritten
;  if you upgrade - instead, make your own script file with this code.
on *:SIGNAL:MircryptionSignal: {
  ; trigger signal for other scripts that want to handle decrypted text, only trigger for text that was received encrypted or outgoing crypted
  ;  this allows other scripts to be written to trigger on incoming encrypted text, without having to modify mircryption.
  ;  note, this signal is triggered on your OWN text too(!), just detect the case where $1==input.
  ; $1 = event type (input,text,query,notice,action,join,topic,part,kick,quit,nick,mode)
  ; $2 = target ($chan)
  ; $3 = speaker ($nick)
  ; $4- = decrypted text
  ;uncomment to test this
  ;/echo TRAPPED MircryptionSignal: event: $1 , target: $2 , speaker: $3 , firstword = $4, text: $4-
}
; ---------------------------------------------------------------------------


; ---------------------------------------------------------------------------
; NEW signal 4/3/04 - this does everything the above but adds two changes:
;  1) it gets called also on normal text (see $4 now)
;  2) it is called before display and you can issue a mchalt or mchaltdef command to prevent mircryption (and mirc) from handling text on return.
;
; Here is a sample signal trap for catching text BEFORE it is displayed on screen.
;  you can implement this signal in your other scripts if you want to detect
;  and act on text BEFORE it is displayed.  check $1 for the type of event.
; The most common use of this signal is to issue the /mchalt or /mchaltdef commands, which will BLOCK
;  mircryption (or mircryption and mirc) from displaying the text when you return from the signal!
; DONT add your code to this procedure(!!) because it will be overwritten
;  if you upgrade - instead, make your own script file with this code.
on *:SIGNAL:MircryptionSignalAll: {
  ; trigger signal for other scripts that want to handle decrypted text, only trigger for text that was received encrypted or outgoing crypted
  ;  this allows other scripts to be written to trigger on incoming encrypted text, without having to modify mircryption.
  ;  note, this signal is triggered on your OWN text too(!), just detect the case where $1==input.
  ; $1 = event type (input,text,query,notice,action,join,topic,part,kick,quit,nick,mode)
  ; $2 = target ($chan)
  ; $3 = speaker ($nick)
  ; $4 = is $true if text was encrypted or $false if plaintext
  ; $5- = decrypted text

  ;uncomment to test this
  ;/echo TRAPPED MircryptionSignalAll: event: $1 , target: $2 , speaker: $3 , encrypted: $4, firstword = $5, text: $5-
  ;/echo TRAPPED MircryptionSignalAll2: normal vars, chan= $chan and nick= $nick  mcchan= $mcchan  and mcnick = $mcnick

  ;if ($5 == hidethis) {
  ;  ; this test hides all lines (incoming, actions, outgoing, everything - which starts with the word hidethis)
  ;  echo 4 MircryptionSignalAll test, hiding your statement.
  ;  /mchaltdef
  ;}
  ;
  ; reminder: to make your script output encrypted in encryption channels (and normal in normal channels),
  ;  just change 'msg' to 'emsg' , 'action' to 'eaction' , 'say' to 'esay' , etc.
}
; ---------------------------------------------------------------------------


;---------------------------------------------------------------------------
; end of file
