#Requires -Version 7.0
<#
.SYNOPSIS
    Upload les binaires i686 compilés localement vers une release GitHub existante.

.DESCRIPTION
    Ce script compile les binaires i686 pour mIRC et les upload automatiquement
    vers une release GitHub draft existante.

.PARAMETER Version
    Le numéro de version de la release (ex: 1.0.0, sans le préfixe 'v')

.PARAMETER GithubToken
    Token GitHub personnel avec permission 'repo'. Si non fourni, utilise $env:GITHUB_TOKEN

.EXAMPLE
    .\scripts\upload-release-assets.ps1 -Version 1.0.0

.EXAMPLE
    $env:GITHUB_TOKEN = "ghp_xxxxxxxxxxxx"
    .\scripts\upload-release-assets.ps1 -Version 1.0.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Version,

    [Parameter(Mandatory = $false)]
    [string]$GithubToken = $env:GITHUB_TOKEN
)

$ErrorActionPreference = "Stop"

# --- Configuration ---
$RepoOwner = "ggielly"
$RepoName = "fish_11"
$Target = "i686-pc-windows-msvc"
$PackageName = "fish_11-windows-i686.zip"

# --- Validation ---
if ([string]::IsNullOrWhiteSpace($GithubToken)) {
    Write-Error "GitHub token requis! Utilisez -GithubToken ou définissez `$env:GITHUB_TOKEN"
    exit 1
}

if (-not (Test-Path "Cargo.toml")) {
    Write-Error "Ce script doit être exécuté depuis la racine du projet fish_11"
    exit 1
}

Write-Host "🚀 Upload des binaires i686 vers GitHub Release v$Version" -ForegroundColor Cyan
Write-Host ""

# --- 1. Compilation ---
Write-Host "📦 Compilation des binaires i686..." -ForegroundColor Yellow

try {
    cargo build --release --target $Target --workspace
    if ($LASTEXITCODE -ne 0) {
        throw "Échec de la compilation"
    }
}
catch {
    Write-Error "Erreur lors de la compilation: $_"
    exit 1
}

Write-Host "✅ Compilation réussie" -ForegroundColor Green
Write-Host ""

# --- 2. Création du package ---
Write-Host "📦 Création du package de release..." -ForegroundColor Yellow

$ReleaseDir = "release_package"
if (Test-Path $ReleaseDir) {
    Remove-Item $ReleaseDir -Recurse -Force
}
New-Item -ItemType Directory -Force -Path $ReleaseDir | Out-Null

# Copier les DLLs
Copy-Item "target/$Target/release/fish_11.dll" $ReleaseDir/
Copy-Item "target/$Target/release/fish_11_inject.dll" $ReleaseDir/

# Copier le CLI
Copy-Item "target/$Target/release/fish_11_cli.exe" $ReleaseDir/

# Copier le script mIRC
Copy-Item "scripts/mirc/fish_11.mrc" $ReleaseDir/

# Copier la documentation
Copy-Item "README.md" $ReleaseDir/
Copy-Item "LICENSE" $ReleaseDir/
if (Test-Path "docs/INSTALLATION.md") {
    Copy-Item "docs/INSTALLATION.md" $ReleaseDir/
}

# Créer le fichier INI template
@"
[fish11]
encrypt_notice=false
encrypt_action=false
process_incoming=true
process_outgoing=true
mark_encrypted= 12`$chr(183)
no_fish10_legacy=false
plain_prefix=+p 
mark_position=1
"@ | Out-File -FilePath "$ReleaseDir/fish_11.ini" -Encoding ASCII

# Créer INSTALL.txt
@"
FiSH_11 Installation Instructions
==================================

Version: $Version
Build date: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')

Installation:
1. Copy all files to your mIRC directory
2. In mIRC, type: /load -rs fish_11.mrc
3. Configure settings in fish_11.ini if needed

Files included:
- fish_11.dll (core cryptographic library)
- fish_11_inject.dll (network injection hooks)
- fish_11.mrc (mIRC script interface)
- fish_11_cli.exe (command-line testing tool)
- fish_11.ini (configuration template)

For detailed documentation, see README.md and INSTALLATION.md

Quick Start:
1. Exchange keys with a contact: /fish11_X25519_INIT nickname
2. Verify fingerprint with your contact
3. Start chatting - messages are encrypted automatically!

"@ | Out-File -FilePath "$ReleaseDir/INSTALL.txt" -Encoding UTF8

# Créer l'archive ZIP
$ZipPath = $PackageName
if (Test-Path $ZipPath) {
    Remove-Item $ZipPath -Force
}
Compress-Archive -Path "$ReleaseDir/*" -DestinationPath $ZipPath

Write-Host "✅ Package créé: $ZipPath" -ForegroundColor Green
Write-Host ""

# --- 3. Récupérer l'ID de la release ---
Write-Host "🔍 Recherche de la release v$Version..." -ForegroundColor Yellow

$Headers = @{
    "Authorization" = "Bearer $GithubToken"
    "Accept"        = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
}

try {
    $ApiUrl = "https://api.github.com/repos/$RepoOwner/$RepoName/releases/tags/v$Version"
    $Release = Invoke-RestMethod -Uri $ApiUrl -Headers $Headers -Method Get
    $ReleaseId = $Release.id
    $UploadUrl = $Release.upload_url -replace '\{.*\}', ''
    
    Write-Host "✅ Release trouvée: $($Release.name) (ID: $ReleaseId)" -ForegroundColor Green
    Write-Host "   Draft: $($Release.draft)" -ForegroundColor Gray
    Write-Host ""
}
catch {
    Write-Error "Release v$Version non trouvée. Créez d'abord la release avec un tag git."
    exit 1
}

# --- 4. Upload de l'asset ---
Write-Host "📤 Upload de $PackageName..." -ForegroundColor Yellow

$UploadHeaders = @{
    "Authorization" = "Bearer $GithubToken"
    "Accept"        = "application/vnd.github+json"
    "Content-Type"  = "application/zip"
}

$UploadUri = "$UploadUrl?name=$PackageName"

try {
    $Asset = Invoke-RestMethod -Uri $UploadUri -Headers $UploadHeaders -Method Post -InFile $ZipPath
    Write-Host "✅ Upload réussi!" -ForegroundColor Green
    Write-Host "   Asset URL: $($Asset.browser_download_url)" -ForegroundColor Gray
    Write-Host ""
}
catch {
    Write-Error "Échec de l'upload: $_"
    exit 1
}

# --- 5. Nettoyage ---
Write-Host "🧹 Nettoyage..." -ForegroundColor Yellow
Remove-Item $ReleaseDir -Recurse -Force
Remove-Item $ZipPath -Force

Write-Host ""
Write-Host "✨ Terminé!" -ForegroundColor Green
Write-Host "   Release: https://github.com/$RepoOwner/$RepoName/releases/tag/v$Version" -ForegroundColor Cyan
Write-Host ""
Write-Host "⚠️  N'oubliez pas de publier la release draft sur GitHub!" -ForegroundColor Yellow

