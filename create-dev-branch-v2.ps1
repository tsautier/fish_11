# =============================================================================
# create-dev-branch-v2.ps1
#
# Crée une nouvelle branche de développement avec un numéro de sprint incrémenté
# et propose interactivement la création du tag associé.
#
# Usage:
#   .\create-dev-branch-v2.ps1
# =============================================================================

param()

# --- Configuration ---
$tagPrefix = "dev-"
$branchPrefix = "dev/sprint-"

# --- Logique Principale ---
try {
    # 1. Synchronisation et recherche du dernier numéro
    Write-Host "🔄 Synchronisation des tags avec le dépôt distant..."
    git fetch --tags --quiet

    Write-Host "🔍 Recherche du dernier numéro de sprint depuis les tags..."
    $lastTagNumber = git tag -l ($tagPrefix + "*") |
                      ForEach-Object {
                          if ($_ -match "$($tagPrefix)(\d+)") { [int]$Matches[1] }
                      } |
                      Sort-Object -Descending |
                      Select-Object -First 1

    $nextNumber = if ($null -eq $lastTagNumber) {
        Write-Host -ForegroundColor Yellow "   Aucun tag '$($tagPrefix)*' trouvé. Initialisation du sprint à 1."
        1
    } else {
        $lastTagNumber + 1
    }

    Write-Host -ForegroundColor Green "✅ Prochain numéro de sprint disponible : $nextNumber"
    Write-Host "" # Ligne vide pour l'aération

    # 2. Création de la branche
    $description = Read-Host -Prompt "🖊️ Entrez une courte description pour la branche (ex: refactor-api-auth)"
    if ([string]::IsNullOrWhiteSpace($description)) {
        throw "La description ne peut pas être vide."
    }

    $sanitizedDescription = $description.ToLower() -replace '\s+', '-' -replace '[^a-z0-9-]', ''
    $branchName = "$($branchPrefix)$($nextNumber)-$($sanitizedDescription)"
    $tagName = "$($tagPrefix)$($nextNumber)"

    Write-Host "🌱 Création de la nouvelle branche : $branchName"
    git checkout -b $branchName
    Write-Host -ForegroundColor Green "🎉 Branche '$branchName' créée avec succès. Vous êtes maintenant dessus."
    Write-Host ""

    # 3. Menu interactif pour la création du tag
    #-------------------------------------------------
    Write-Host -ForegroundColor Cyan "--- Gestion du Tag de Sprint ---"
    Write-Host "Le tag '$tagName' peut être créé pour marquer officiellement le début de ce sprint."
    Write-Host "Ce tag sera visible par toute l'équipe."
    Write-Host ""
    Write-Host "   [1] Créer le tag localement et le pousser sur 'origin' (recommandé pour la visibilité)"
    Write-Host "   [2] Créer le tag localement seulement (vous le pousserez manuellement plus tard)"
    Write-Host "   [3] Ne pas créer de tag pour le moment (défaut)"
    Write-Host ""
    #-------------------------------------------------

    $choice = ""
    $validChoice = $false
    while (-not $validChoice) {
        $choice = Read-Host -Prompt "Votre choix [1, 2, 3] (défaut: 3)"
        if ([string]::IsNullOrWhiteSpace($choice)) {
            $choice = "3" # Option par défaut
        }

        switch ($choice) {
            "1" {
                Write-Host "   Création du tag '$tagName' localement..."
                git tag $tagName
                Write-Host "   Poussée du tag '$tagName' sur 'origin'..."
                git push origin $tagName
                Write-Host -ForegroundColor Green "   Tag créé et poussé avec succès."
                $validChoice = $true
            }
            "2" {
                Write-Host "   Création du tag '$tagName' localement..."
                git tag $tagName
                Write-Host -ForegroundColor Green "   Tag créé localement. N'oubliez pas de le pousser plus tard avec 'git push origin $tagName'."
                $validChoice = $true
            }
            "3" {
                Write-Host "   Aucun tag n'a été créé."
                $validChoice = $true
            }
            default {
                Write-Warning "Choix invalide. Veuillez entrer 1, 2, ou 3."
            }
        }
    }

    Write-Host ""
    Write-Host -ForegroundColor Green "✅ Opération terminée."

} catch {
    Write-Error "❌ Une erreur critique est survenue : $($_.Exception.Message)"
    # En cas d'erreur (ex: la branche existe déjà), s'assurer de ne pas laisser l'utilisateur dans un état incertain.
    # On pourrait ajouter ici `git status` pour montrer l'état actuel.
}
