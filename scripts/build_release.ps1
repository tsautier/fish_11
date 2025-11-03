# This script builds the entire FiSH_11 workspace in release mode for the 32-bit Windows target,
# then packages the essential files into a ZIP archive for distribution.

# Stop on any error
$ErrorActionPreference = "Stop"

Write-Host "Starting FiSH_11 release build and packaging..." -ForegroundColor Green

# 1. Build the project in release mode.
# The target is automatically picked up from .cargo/config.toml
Write-Host "[1/4] Building workspace in release mode..."

cargo build --workspace --release

if ($LASTEXITCODE -ne 0) {
    Write-Host "Cargo build failed!" -ForegroundColor Red
    exit 1
}

Write-Host "Build completed successfully." -ForegroundColor Green

# 2. Define paths
$releaseDir = "./target/i686-pc-windows-msvc/release"
$mrcScriptPath = "./scripts/mirc/fish_11.mrc"
$zipOutputFile = "$releaseDir/FiSH_11_release.zip"

# 3. Copy the mIRC script to the release directory
Write-Host "[2/4] Copying mIRC script to release folder..."
Copy-Item -Path $mrcScriptPath -Destination $releaseDir

# 4. Create the ZIP archive
Write-Host "[3/4] Creating ZIP archive..."
$filesToZip = @(
    "$releaseDir/fish_11.dll",
    "$releaseDir/fish_11_inject.dll",
    "$releaseDir/fish_11_cli.exe",
    "$releaseDir/fish_11.mrc"
)

# Use -Force to overwrite any existing ZIP file
Compress-Archive -Path $filesToZip -DestinationPath $zipOutputFile -Force

Write-Host "[4/4] Packaging complete!"
Write-Host "Release package created at: $zipOutputFile" -ForegroundColor Green
