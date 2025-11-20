#!/usr/bin/env pwsh
<#
.SYNOPSIS
    Script de test pour vérifier que tout compile avant une release

.DESCRIPTION
    Ce script effectue toutes les vérifications nécessaires sans créer de commit/tag.
    Utile pour tester avant de lancer une vraie release.

.EXAMPLE
    .\test-release-build.ps1
#>

$ErrorActionPreference = "Stop"

function Write-Info { Write-Host "ℹ️  $args" -ForegroundColor Cyan }
function Write-Success { Write-Host "✅ $args" -ForegroundColor Green }
function Write-Error { param($msg) Write-Host "❌ $msg" -ForegroundColor Red }

Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host "  FiSH_11 - Test de build pre-release" -ForegroundColor Yellow
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Yellow
Write-Host ""

$StartTime = Get-Date

# 1. Vérifier Rust et les targets
Write-Info "Vérification de l'environnement Rust..."
$RustVersion = rustc --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Rust n'est pas installé ou pas dans le PATH"
    exit 1
}
Write-Host "  $RustVersion" -ForegroundColor Gray

$CargoVersion = cargo --version 2>&1
Write-Host "  $CargoVersion" -ForegroundColor Gray

# Vérifier que le target i686 est installé
$Targets = rustup target list --installed 2>&1
if ($Targets -notcontains "i686-pc-windows-msvc") {
    Write-Info "Installation du target i686-pc-windows-msvc..."
    rustup target add i686-pc-windows-msvc
}
Write-Success "Environnement Rust OK"
Write-Host ""

# 2. Formatage
Write-Info "Vérification du formatage..."
$FormatStart = Get-Date
cargo fmt --all -- --check
if ($LASTEXITCODE -ne 0) {
    Write-Error "Le code n'est pas correctement formaté"
    Write-Host "Pour corriger : cargo fmt --all" -ForegroundColor Yellow
    exit 1
}
$FormatTime = (Get-Date) - $FormatStart
Write-Success "Formatage OK ($([math]::Round($FormatTime.TotalSeconds, 1))s)"
Write-Host ""

# 3. Clippy
Write-Info "Analyse statique avec Clippy..."
$ClippyStart = Get-Date
cargo clippy --workspace --all-targets -- -D warnings 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Clippy a trouvé des problèmes"
    Write-Host "Pour voir les détails : cargo clippy --workspace --all-targets" -ForegroundColor Yellow
    exit 1
}
$ClippyTime = (Get-Date) - $ClippyStart
Write-Success "Clippy OK ($([math]::Round($ClippyTime.TotalSeconds, 1))s)"
Write-Host ""

# 4. Compilation i686 (release)
Write-Info "Compilation Windows i686 (release)..."
Write-Host "  Ceci peut prendre plusieurs minutes..." -ForegroundColor Gray

$BuildStart = Get-Date

Write-Host "  - fish_11_core..." -ForegroundColor Gray
cargo build --release --target i686-pc-windows-msvc -p fish_11_core 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Échec de compilation de fish_11_core"
    exit 1
}

Write-Host "  - fish_11_dll..." -ForegroundColor Gray
cargo build --release --target i686-pc-windows-msvc -p fish_11_dll 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Échec de compilation de fish_11_dll"
    exit 1
}

Write-Host "  - fish_11_inject..." -ForegroundColor Gray
cargo build --release --target i686-pc-windows-msvc -p fish_11_inject 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Échec de compilation de fish_11_inject"
    exit 1
}

Write-Host "  - fish_11_cli..." -ForegroundColor Gray
cargo build --release --target i686-pc-windows-msvc -p fish_11_cli 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Échec de compilation de fish_11_cli"
    exit 1
}

$BuildTime = (Get-Date) - $BuildStart
Write-Success "Compilation OK ($([math]::Round($BuildTime.TotalSeconds, 1))s)"
Write-Host ""

# 5. Vérification des fichiers générés
Write-Info "Vérification des artefacts..."
$TargetDir = "target/i686-pc-windows-msvc/release"

$RequiredFiles = @(
    "$TargetDir/fish_11.dll",
    "$TargetDir/fish_11_inject.dll",
    "$TargetDir/fish_11_cli.exe"
)

$AllFilesExist = $true
foreach ($File in $RequiredFiles) {
    if (Test-Path $File) {
        $Size = (Get-Item $File).Length / 1KB
        Write-Host "  ✅ $(Split-Path $File -Leaf) ($([math]::Round($Size, 1)) KB)" -ForegroundColor Green
    } else {
        Write-Host "  ❌ $(Split-Path $File -Leaf) - MANQUANT" -ForegroundColor Red
        $AllFilesExist = $false
    }
}

if (-not $AllFilesExist) {
    Write-Error "Certains fichiers sont manquants"
    exit 1
}
Write-Success "Tous les artefacts sont présents"
Write-Host ""

# 6. Vérification des exports DLL
Write-Info "Vérification des exports DLL..."

# fish_11.dll
$CoreExports = dumpbin /EXPORTS "$TargetDir/fish_11.dll" 2>&1 | Select-String "FiSH11"
Write-Host "  fish_11.dll : $($CoreExports.Count) exports FiSH11_*" -ForegroundColor Gray
if ($CoreExports.Count -lt 5) {
    Write-Error "Trop peu d'exports dans fish_11.dll"
    exit 1
}

# fish_11_inject.dll
$InjectExports = dumpbin /EXPORTS "$TargetDir/fish_11_inject.dll" 2>&1 | Select-String "FiSH11"
Write-Host "  fish_11_inject.dll : $($InjectExports.Count) exports FiSH11_*" -ForegroundColor Gray
if ($InjectExports.Count -lt 2) {
    Write-Error "Trop peu d'exports dans fish_11_inject.dll"
    exit 1
}

Write-Success "Exports DLL OK"
Write-Host ""

# 7. Tests unitaires
Write-Info "Exécution des tests..."
$TestStart = Get-Date
cargo test --workspace 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Certains tests ont échoué"
    Write-Host "Pour voir les détails : cargo test --workspace" -ForegroundColor Yellow
    exit 1
}
$TestTime = (Get-Date) - $TestStart
Write-Success "Tests OK ($([math]::Round($TestTime.TotalSeconds, 1))s)"
Write-Host ""

# 8. Test du CLI
Write-Info "Test du CLI..."
$CliOutput = & "$TargetDir/fish_11_cli.exe" --version 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "  $CliOutput" -ForegroundColor Gray
    Write-Success "CLI fonctionne"
} else {
    Write-Error "Le CLI ne fonctionne pas correctement"
    exit 1
}
Write-Host ""

# 9. Création d'un package test
Write-Info "Création d'un package de test..."
$TestDir = "target/test-release"
if (Test-Path $TestDir) {
    Remove-Item -Recurse -Force $TestDir
}
New-Item -ItemType Directory -Force -Path $TestDir | Out-Null

Copy-Item "$TargetDir/fish_11.dll" "$TestDir/"
Copy-Item "$TargetDir/fish_11_inject.dll" "$TestDir/"
Copy-Item "$TargetDir/fish_11_cli.exe" "$TestDir/"
Copy-Item "scripts/mirc/fish_11.mrc" "$TestDir/"
Copy-Item "README.md" "$TestDir/"
Copy-Item "LICENSE" "$TestDir/"

$PackagePath = "target/fish_11-test-package.zip"
if (Test-Path $PackagePath) {
    Remove-Item -Force $PackagePath
}
Compress-Archive -Path "$TestDir/*" -DestinationPath $PackagePath

$PackageSize = (Get-Item $PackagePath).Length / 1MB
Write-Success "Package créé : $PackagePath ($([math]::Round($PackageSize, 2)) MB)"
Write-Host ""

# 10. Résumé final
$TotalTime = (Get-Date) - $StartTime

Write-Host ""
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Green
Write-Host "  ✅ Tous les tests sont passés !" -ForegroundColor Green
Write-Host "═══════════════════════════════════════════════════" -ForegroundColor Green
Write-Host ""
Write-Host "Temps total : $([math]::Round($TotalTime.TotalMinutes, 1)) minutes" -ForegroundColor Cyan
Write-Host ""
Write-Host "Détails :" -ForegroundColor White
Write-Host "  - Formatage     : $([math]::Round($FormatTime.TotalSeconds, 1))s" -ForegroundColor Gray
Write-Host "  - Clippy        : $([math]::Round($ClippyTime.TotalSeconds, 1))s" -ForegroundColor Gray
Write-Host "  - Compilation   : $([math]::Round($BuildTime.TotalSeconds, 1))s" -ForegroundColor Gray
Write-Host "  - Tests         : $([math]::Round($TestTime.TotalSeconds, 1))s" -ForegroundColor Gray
Write-Host ""
Write-Host "Package de test : $PackagePath" -ForegroundColor Yellow
Write-Host "Vous pouvez tester ce package avec mIRC avant de créer la release officielle." -ForegroundColor Yellow
Write-Host ""
Write-Success "Prêt pour la release ! Utilisez .\scripts\create-release.ps1"
Write-Host ""
