#Requires -Modules Git
<#
.SYNOPSIS
    Crée une nouvelle branche Git avec un type, un numéro de version auto-incrémenté et une description.
.DESCRIPTION
    Ce script offre un menu interactif pour choisir le type de branche (feature, fix, etc.),
    demande une description, trouve le numéro de version le plus élevé parmi les branches existantes
    (locales et distantes) qui correspondent au motif "<type>/<nombre>-...",
    et en crée une nouvelle avec un numéro incrémenté.
.PARAMETER Description
    Une courte description pour la nouvelle branche. Si non fournie, le script la demandera.
    Les espaces seront remplacés par des tirets.
.EXAMPLE
    .\new-branch.ps1 -Description "add login page"
    # Demandera le type de branche via un menu.
    # Crée une branche comme "feature/124-add-login-page"

.EXAMPLE
    .\new-branch.ps1
    # Demandera interactivement le type et la description.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $false, Position = 0)]
    [string]$Description
)

# --- Fonctions utilitaires ---

# Fonction pour afficher un menu interactif
function Show-Menu {
    param (
        [string[]]$Options,
        [int]$DefaultSelection = 0
    )

    $selectedIndex = $DefaultSelection
    while ($true) {
        Clear-Host # Ou Write-Host "`n`n`n`n`n`n`n`n`n`n`n`n`n`n`n`n`n`n`n`n`n`n`n`n`n`n`n`n`n`n" pour effacer
        Write-Host "Please select a branch type using arrow keys and Enter:"
        for ($i = 0; $i -lt $Options.Count; $i++) {
            if ($i -eq $selectedIndex) {
                Write-Host " > $($Options[$i])" -ForegroundColor Cyan
            } else {
                Write-Host "   $($Options[$i])"
            }
        }

        $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")

        switch ($key.VirtualKeyCode) {
            # Up arrow
            38 {
                $selectedIndex--
                if ($selectedIndex -lt 0) { $selectedIndex = $Options.Count -1 }
            }
            # Down arrow
            40 {
                $selectedIndex++
                if ($selectedIndex -ge $Options.Count) { $selectedIndex = 0 }
            }
            # Enter
            13 {
                return $Options[$selectedIndex]
            }
            # Escape (optional: to exit menu)
            27 {
                Write-Error "Operation cancelled by user."
                exit 1
            }
        }
    }
}

# --- Validation initiale ---
try {
    git rev-parse --is-inside-work-tree | Out-Null
}
catch {
    Write-Error "ERROR: Not a Git repository, or 'git' command not found."
    exit 1
}

# --- Sélection du type de branche ---
$branchTypes = @("feature", "fix", "refactor", "docs", "style", "test", "ci", "chore")
$selectedType = Show-Menu -Options $branchTypes
Write-Host "✅ Selected branch type: $selectedType`n"

# --- Obtenir la description de la branche ---
if ([string]::IsNullOrWhiteSpace($Description)) {
    $Description = Read-Host "📝 Please enter a short description for the new branch (e.g., add-user-profile-page)"
}

if ([string]::IsNullOrWhiteSpace($Description)) {
    Write-Error "ERROR: Description cannot be empty."
    exit 1
}

# --- Trouver le dernier numéro de version pour le type sélectionné ---
Write-Host "-> Analyzing existing branches for the highest version number for type '$selectedType' ..."
# Pattern: <type>/<number>-<description>
$pattern = "$selectedType/(\d+)-" # Regex to capture the number after the type and before the description
$highestVersion = 0

# Retrieve all branches, local and remote
git branch --all | ForEach-Object {
    $branchName = $_.Trim().Replace("* ", "") # Clean branch name

    if ($branchName -match $pattern) {
        $currentVersion = [int]$matches[1]
        if ($currentVersion -gt $highestVersion) {
            $highestVersion = $currentVersion
        }
    }
}

$newVersion = $highestVersion + 1
Write-Host "✅ Highest version for '$selectedType' is $highestVersion. New version will be $newVersion."

# --- Préparer le nom final de la branche ---
# Convert to lowercase, replace spaces/punctuation with hyphens, remove invalid characters
$slug = $Description.ToLower().Trim() -replace '\s+', '-' -replace '[^a-z0-9-]', ''
$branchName = "$selectedType/$newVersion-$slug"

Write-Host "`n✨ Proposed new branch name: " -NoNewline
Write-Host "$branchName" -ForegroundColor Green

# --- Confirmation ---
$confirm = Read-Host "❓ Do you want to create this branch? (y/n)"
if ($confirm -notmatch "^[yY]$") {
    Write-Host "Operation cancelled by user."
    exit 0
}

# --- Création de la branche ---
try {
    git checkout -b $branchName
    Write-Host "`n🎉 Success! You are now on branch '$branchName'."
}
catch {
    Write-Error "ERROR: Failed to create branch '$branchName'. A branch with this name might already exist or another Git error occurred."
    exit 1
}
