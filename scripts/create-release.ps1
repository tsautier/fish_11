#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Script d'aide pour créer une release FiSH_11

.DESCRIPTION
    Ce script automatise le processus de release :
    - Vérifie que tout compile
    - Met à jour la version
    - Crée le commit et le tag
    - Pousse vers GitHub

.PARAMETER Version
    Version à créer (format: 1.2.3, sans le 'v')

.PARAMETER Message
    Message de release (optionnel)

.PARAMETER SkipTests
    Skip les tests (non recommandé)

.EXAMPLE
    .\create-release.ps1 -Version 1.2.3 -Message "Ajout du support FCEP-1"
#>

param(
    [Parameter(Mandatory=$true)]
    [string]$Version,
    
    [Parameter(Mandatory=$false)]
    [string]$Message = "Release $Version",
    
    [Parameter(Mandatory=$false)]
    [switch]$SkipTests = $false
)

$ErrorActionPreference = "Stop"

# Couleurs pour les messages (ASCII safe pour compatibilité PS 5.1)
function Write-Info { Write-Host "[INFO]  $args" -ForegroundColor Cyan }
function Write-Success { Write-Host "[OK] $args" -ForegroundColor Green }
function Write-Warning { Write-Host "[WARN]  $args" -ForegroundColor Yellow }
function Write-Error { param($msg) Write-Host "[ERROR] $msg" -ForegroundColor Red }

# Vérifier que la version est au bon format
if ($Version -notmatch '^\d+\.\d+\.\d+$') {
    Write-Error "Format de version invalide. Utilisez: X.Y.Z (ex: 1.2.3)"
    exit 1
}

$TagName = "v$Version"

Write-Info "Création de la release $TagName"
Write-Info "Message: $Message"
Write-Host ""

# 1. Vérifier qu'on est sur main et à jour
Write-Info "Vérification de la branche..."
$CurrentBranch = git rev-parse --abbrev-ref HEAD
if ($CurrentBranch -ne "main") {
    Write-Error "Vous devez être sur la branche 'main' pour créer une release"
    exit 1
}

git fetch origin
$LocalCommit = git rev-parse HEAD
$RemoteCommit = git rev-parse origin/main
if ($LocalCommit -ne $RemoteCommit) {
    Write-Error "Votre branche n'est pas à jour avec origin/main. Faites 'git pull' d'abord."
    exit 1
}
Write-Success "Branche 'main' à jour"

# 2. Vérifier qu'il n'y a pas de modifications non commitées
$GitStatus = git status --porcelain
if ($GitStatus) {
    Write-Error "Il y a des modifications non commitées. Committez ou stashez d'abord."
    exit 1
}
Write-Success "Pas de modifications en attente"

# 3. Vérifier que le tag n'existe pas déjà
$ExistingTag = git tag -l $TagName
if ($ExistingTag) {
    Write-Error "Le tag $TagName existe déjà. Choisissez une autre version."
    exit 1
}
Write-Success "Tag $TagName disponible"

# 4. Mise à jour de la version dans globals.rs
Write-Info "Mise à jour de la version dans fish_11_core/src/globals.rs..."
$GlobalsFile = "fish_11_core/src/globals.rs"
$GlobalsContent = Get-Content $GlobalsFile -Raw
$NewGlobalsContent = $GlobalsContent -replace 'pub const BUILD_VERSION: &str = "[^"]+";', "pub const BUILD_VERSION: &str = `"$Version`";"

if ($GlobalsContent -eq $NewGlobalsContent) {
    Write-Warning "La version n'a pas été modifiée dans globals.rs"
} else {
    Set-Content -Path $GlobalsFile -Value $NewGlobalsContent -NoNewline
    Write-Success "Version mise à jour dans globals.rs"
}

# 5. Tests et vérifications
if (-not $SkipTests) {
    Write-Info "Vérification du formatage..."
    cargo fmt --all -- --check
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Le formatage n'est pas correct. Exécutez 'cargo fmt --all'"
        exit 1
    }
    Write-Success "Formatage correct"

    Write-Info "Vérification avec clippy..."
    #cargo clippy --workspace --all-targets --
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Clippy a trouvé des problèmes"
        exit 1
    }
    Write-Success "Clippy OK"

    Write-Info "Compilation en mode release (i686)..."
    cargo build --release --target i686-pc-windows-msvc --workspace
    if ($LASTEXITCODE -ne 0) {
        Write-Error "La compilation a échoué"
        exit 1
    }
    Write-Success "Compilation réussie"

    Write-Info "Exécution des tests..."
    cargo test --workspace
    if ($LASTEXITCODE -ne 0) {
        Write-Error "Les tests ont échoué"
        exit 1
    }
    Write-Success "Tests réussis"
} else {
    Write-Warning "Tests ignorés (SkipTests activé)"
}

# 6. Vérifier les exports DLL
Write-Info "Vérification des exports DLL..."
$DllPath = "target/i686-pc-windows-msvc/release/fish_11.dll"
$InjectDllPath = "target/i686-pc-windows-msvc/release/fish_11_inject.dll"

if (Test-Path $DllPath) {
    $Exports = dumpbin /EXPORTS $DllPath 2>&1 | Select-String "FiSH11"
    if ($Exports.Count -lt 5) {
        Write-Warning "Peu d'exports trouvés dans fish_11.dll ($($Exports.Count))"
    } else {
        Write-Success "Exports DLL OK ($($Exports.Count) fonctions)"
    }
}

if (Test-Path $InjectDllPath) {
    $InjectExports = dumpbin /EXPORTS $InjectDllPath 2>&1 | Select-String "FiSH11"
    if ($InjectExports.Count -lt 2) {
        Write-Warning "Peu d'exports trouvés dans fish_11_inject.dll ($($InjectExports.Count))"
    } else {
        Write-Success "Exports injection DLL OK ($($InjectExports.Count) fonctions)"
    }
}

# 7. Créer le commit
Write-Info "Création du commit de release..."
git add .
git commit -m "Release $TagName

$Message
"
if ($LASTEXITCODE -ne 0) {
    Write-Error "Échec du commit"
    exit 1
}
Write-Success "Commit créé"

# 8. Créer le tag
Write-Info "Création du tag $TagName..."
$TagMessage = @"
Version $Version

$Message

Compiled on: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Commit: $(git rev-parse --short HEAD)
"@

git tag -a $TagName -m $TagMessage
if ($LASTEXITCODE -ne 0) {
    Write-Error "Échec de la création du tag"
    exit 1
}
Write-Success "Tag $TagName créé"

# 9. Confirmation avant push
Write-Host ""
Write-Info "Prêt à pousser vers GitHub:"
Write-Host "  - Commit: $(git log -1 --oneline)"
Write-Host "  - Tag: $TagName"
Write-Host ""
$Confirm = Read-Host "Voulez-vous pousser vers GitHub? (y/N)"

if ($Confirm -ne 'y' -and $Confirm -ne 'Y') {
    Write-Warning "Push annulé. Pour annuler les changements:"
    Write-Host "  git reset --hard HEAD~1"
    Write-Host "  git tag -d $TagName"
    exit 0
}

# 10. Push vers GitHub
Write-Info "Push du commit vers origin/main..."
git push origin main
if ($LASTEXITCODE -ne 0) {
    Write-Error "Échec du push du commit"
    exit 1
}
Write-Success "Commit poussé"

Write-Info "Push du tag $TagName..."
git push origin $TagName
if ($LASTEXITCODE -ne 0) {
    Write-Error "Échec du push du tag"
    Write-Warning "Le commit a été poussé mais pas le tag. Pour réessayer:"
    Write-Host "  git push origin $TagName"
    exit 1
}
Write-Success "Tag poussé"

# Attendre que GitHub Actions crée la release draft

Write-Host ""
Write-Success "Tag $TagName poussé avec succès!"
Write-Host ""
Write-Info "Attente de la création de la release draft sur GitHub..."
Write-Host "   (GitHub Actions doit compiler le CLI Linux et créer la release)"
Write-Host ""

$WaitForDraft = Read-Host "Attendre la création de la release draft avant l'upload i686? (y/N)"
if ($WaitForDraft -eq 'y' -or $WaitForDraft -eq 'Y') {
    Write-Info "Surveillance de GitHub Actions..."
    Write-Host "   URL: https://github.com/ggielly/fish_11/actions"
    Write-Host ""
    Write-Host "Appuyez sur Entrée quand la release draft est créée..." -NoNewline
    Read-Host
}

# 12. Upload des binaires i686
Write-Host ""
Write-Info "Upload des binaires Windows i686..."

if (-not $env:GITHUB_TOKEN) {
    Write-Warning "Variable d'environnement GITHUB_TOKEN non définie"
    Write-Host "   Pour configurer un token:"
    Write-Host "   1. Créez un token sur: https://github.com/settings/tokens"
    Write-Host "   2. Donnez la permission 'repo'"
    Write-Host "   3. Définissez: `$env:GITHUB_TOKEN = 'ghp_xxxxxxxxxxxx'"
    Write-Host ""
    $SkipUpload = Read-Host "Sauter l'upload automatique? (y/N)"
    if ($SkipUpload -eq 'y' -or $SkipUpload -eq 'Y') {
        Write-Info "Upload manuel requis. Exécutez:"
        Write-Host "   .\scripts\upload-release-assets.ps1 -Version $Version"
        exit 0
    }
    exit 1
}

try {
    & "$PSScriptRoot\upload-release-assets.ps1" -Version $Version
    Write-Success "Binaires i686 uploadés avec succès!"
}
catch {
    Write-Error "Échec de l'upload: $_"
    Write-Warning "Vous pouvez réessayer manuellement avec:"
    Write-Host "   .\scripts\upload-release-assets.ps1 -Version $Version"
    exit 1
}

# 13. Fin
Write-Host ""
Write-Success "Release $TagName créée et publiée avec succès!"
Write-Host ""
Write-Info "Prochaines étapes:"
Write-Host "  1. Vérifier la release: https://github.com/ggielly/fish_11/releases/tag/$TagName"
Write-Host "  2. Publier la release draft (elle est encore en mode draft)"
Write-Host "  3. Annoncer la release! 🎉"
Write-Host ""

# Ouvrir le navigateur sur la release
$OpenBrowser = Read-Host "Ouvrir la release sur GitHub? (y/N)"
if ($OpenBrowser -eq 'y' -or $OpenBrowser -eq 'Y') {
    Start-Process "https://github.com/ggielly/fish_11/releases/tag/$TagName"
}
