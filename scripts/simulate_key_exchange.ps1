<#
Simulate FiSH11 X25519 key exchange between two clients using the CLI.

Usage:
  .\simulate_key_exchange.ps1 [-Sender alice] [-Receiver bob]

This script launches two background jobs that act like separate clients.
They exchange public-key tokens via temporary files in the script folder,
call the DLL via the CLI to process each other's public key token and
perform a small encrypt/decrypt roundtrip to verify the shared key.

Requirements:
- Built CLI: target\debug\fish_11_cli.exe
- Built DLL: target\debug\fish_11.dll

This script is intentionally self-contained and places temporary files in
the scripts\exchange_tmp directory. It cleans up on exit.
#>

param(
    [string]$Sendah = 'alice',
    [string]$Receiver = 'bob'
)

Set-StrictMode -Version Latest

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
$repoRoot = Resolve-Path (Join-Path $scriptDir '..')

$cliPath = Join-Path $repoRoot 'target\i686-pc-windows-msvc\debug\fish_11_cli.exe'
$dllPath = Join-Path $repoRoot 'target\i686-pc-windows-msvc\debug\fish_11.dll'

if (-not (Test-Path $cliPath)) {
    Write-Error "CLI not found at: $cliPath`nPlease build the project first (cargo build -p fish_11_cli)"
    exit 2
}
if (-not (Test-Path $dllPath)) {
    Write-Error "DLL not found at: $dllPath`nPlease build the project first (cargo build --workspace)"
    exit 2
}

$tmpDir = Join-Path $scriptDir 'exchange_tmp'
if (-not (Test-Path $tmpDir)) { New-Item -ItemType Directory -Path $tmpDir | Out-Null }

$aToB = Join-Path $tmpDir 'a_to_b.txt'
$bToA = Join-Path $tmpDir 'b_to_a.txt'
$logFile = Join-Path $tmpDir 'exchange.log'

Write-Host "Simulation starting: Sender='$Sendah' Receiver='$Receiver'"
Write-Host "CLI: $cliPath`nDLL: $dllPath`nTemp dir: $tmpDir"

Remove-Item -Force -ErrorAction SilentlyContinue $aToB,$bToA,$logFile

function Extract-Token {
    param([string]$cliOutput)
    # Find the first line that contains the X25519_INIT token
    $lines = $cliOutput -split "\r?\n"
    foreach ($l in $lines) {
        $trim = $l.Trim()
        if ($trim -match '^X25519_INIT:[A-Za-z0-9+/=]+$') { return $trim }
    }
    # If not exact match, fallback to last line starting with prefix
    foreach ($l in $lines | Select-Object -Last 5) {
        $trim = $l.Trim()
        if ($trim.StartsWith('X25519_INIT:')) { return $trim }
    }
    return $null
}

# Receiver job: waits for incoming token from sender, processes it, then returns its own token
$receiverJob = Start-Job -Name Receiver -ScriptBlock {
    param($cliPath,$dllPath,$rname,$sname,$inFile,$outFile,$logFile)

    "[$(Get-Date -Format o)] Receiver job started for $rname" | Out-File -FilePath $logFile -Append

    # ensure our keypair exists
    & $cliPath $dllPath genkey $rname | Out-Null

    Write-Output "Receiver ($rname) waiting for token file: $inFile"
    while (-not (Test-Path $inFile)) { Start-Sleep -Seconds 1 }

    $token = Get-Content -Raw -Path $inFile
    $token = $token.Trim()
    "[$(Get-Date -Format o)] Receiver got token: $token" | Out-File -FilePath $logFile -Append

    # Call processkey: process the sender's token and store shared secret as 'sender'
    $procOut = & $cliPath $dllPath processkey $sname $token | Out-String -Width 4096
    "[$(Get-Date -Format o)] Receiver processkey output:`n$procOut" | Out-File -FilePath $logFile -Append
    Write-Output "Receiver processed incoming token. Output: $($procOut.Trim())"

    # Now create and send our own token back
    $cliOut = & $cliPath $dllPath exchangekey $rname | Out-String -Width 4096
    "[$(Get-Date -Format o)] Receiver exchangekey output:`n$cliOut" | Out-File -FilePath $logFile -Append
    # extract token using same rules
    $lines = $cliOut -split "\r?\n"
    $found = $null
    foreach ($l in $lines) { if ($l.Trim().StartsWith('X25519_INIT:')) { $found = $l.Trim(); break } }
    if ($found) {
        Set-Content -Path $outFile -Value $found
        "[$(Get-Date -Format o)] Receiver wrote token to ${outFile}: ${found}" | Out-File -FilePath $logFile -Append
        Write-Output "Receiver sent token back: $found"
    } else {
        "[$(Get-Date -Format o)] Receiver failed to extract own token from CLI output" | Out-File -FilePath $logFile -Append
        Write-Output "Receiver failed to extract own token"
    }
} -ArgumentList $cliPath,$dllPath,$Receiver,$Sendah,$aToB,$bToA,$logFile

# Sender job: generate token, send to receiver, wait for response, process response
$SendahJob = Start-Job -Name Sender -ScriptBlock {
    param($cliPath,$dllPath,$sname,$rname,$outFile,$inFile,$logFile)

    "[$(Get-Date -Format o)] Sender job started for $sname" | Out-File -FilePath $logFile -Append

    # ensure our keypair exists
    & $cliPath $dllPath genkey $sname | Out-Null

    # Create our token
    $cliOut = & $cliPath $dllPath exchangekey $sname | Out-String -Width 4096
    "[$(Get-Date -Format o)] Sender exchangekey output:`n$cliOut" | Out-File -FilePath $logFile -Append
    $lines = $cliOut -split "\r?\n"
    $found = $null
    foreach ($l in $lines) { if ($l.Trim().StartsWith('X25519_INIT:')) { $found = $l.Trim(); break } }
    if (-not $found) { Write-Error "Sender failed to extract token"; exit 3 }

    # Write token for receiver
    Set-Content -Path $outFile -Value $found
    "[$(Get-Date -Format o)] Sender wrote token to ${outFile}: ${found}" | Out-File -FilePath $logFile -Append
    Write-Output "Sender sent token: $found"

    # Wait for receiver to reply
    Write-Output "Sender waiting for receiver reply file: $inFile"
    while (-not (Test-Path $inFile)) { Start-Sleep -Seconds 1 }
    $theirToken = Get-Content -Raw -Path $inFile
    $theirToken = $theirToken.Trim()
    "[$(Get-Date -Format o)] Sender got reply token: ${theirToken}" | Out-File -FilePath $logFile -Append

    # Process the receiver's token (store shared secret as 'receiver')
    $procOut = & $cliPath $dllPath processkey $rname $theirToken | Out-String -Width 4096
    "[$(Get-Date -Format o)] Sender processkey output:`n$procOut" | Out-File -FilePath $logFile -Append
    Write-Output "Sender processed reply token. Output: $($procOut.Trim())"

    # Optional test: encrypt a message for receiver and show that decrypt works
    $message = "Hello from $sname"
    $encOut = & $cliPath $dllPath encrypt $rname $message | Out-String -Width 4096
    "[$(Get-Date -Format o)] Sender encrypt output:`n$encOut" | Out-File -FilePath $logFile -Append
    $lines = $encOut -split "\r?\n"
    $encToken = $lines | Where-Object { $_ -like '+FiSH *' } | Select-Object -Last 1
    if ($encToken) {
        Write-Output "Sender encrypted message: $encToken"
        # Now ask receiver to decrypt (simulate by invoking CLI as receiver)
        $decOut = & $cliPath $dllPath decrypt $sname $encToken | Out-String -Width 4096
        "[$(Get-Date -Format o)] Sender (simulate receiver) decrypt output:`n$decOut" | Out-File -FilePath $logFile -Append
        Write-Output "Simulated decrypt output: $decOut"
    } else {
        Write-Output "No encrypted token detected in encrypt output"
    }

} -ArgumentList $cliPath,$dllPath,$Sendah,$Receiver,$aToB,$bToA,$logFile

Write-Host "Jobs started. Waiting for completion (timeout 30s)..."
Wait-Job -Job $SendahJob,$receiverJob -Timeout 30 | Out-Null

# If any jobs are still running after the timeout, stop them so we can collect output
$stillRunning = Get-Job -Id $SendahJob.Id,$receiverJob.Id | Where-Object { $_.State -eq 'Running' }
if (($stillRunning | Measure-Object).Count -gt 0) {
    Write-Host "One or more jobs did not finish within the timeout. Stopping jobs..."
    Stop-Job -Job $stillRunning -Force -ErrorAction SilentlyContinue
}

Write-Host "Collecting job output and logs..."
# Use Receive-Job without -AutoRemoveJob (it requires -Wait). Remove jobs explicitly afterwards.
Receive-Job -Job $SendahJob | ForEach-Object { Write-Host "[Sender] $_" }
Receive-Job -Job $receiverJob | ForEach-Object { Write-Host "[Receiver] $_" }

# Cleanup jobs
Remove-Job -Job $SendahJob,$receiverJob -Force -ErrorAction SilentlyContinue

Write-Host "Log content:`n"; Get-Content -Path $logFile -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }

Write-Host "Cleaning up temporary files..."
Remove-Item -Force -ErrorAction SilentlyContinue $aToB,$bToA

Write-Host "Simulation complete."
