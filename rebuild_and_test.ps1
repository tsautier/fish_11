# Script de rebuild et déploiement pour fish_11
# Usage: .\rebuild_and_test.ps1

Write-Host "=== FiSH_11 Rebuild & Deploy ===" -ForegroundColor Cyan
Write-Host ""

# Étape 1: Compiler fish_11_dll
Write-Host "[1/3] Compilation de fish_11_dll..." -ForegroundColor Yellow
cargo build -p fish_11_dll
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERREUR: La compilation de fish_11_dll a échoué!" -ForegroundColor Red
    exit 1
}
Write-Host "✓ fish_11_dll compilée avec succès" -ForegroundColor Green
Write-Host ""

# Étape 2: Compiler fish_11_inject
Write-Host "[2/3] Compilation de fish_11_inject..." -ForegroundColor Yellow
cargo build -p fish_11_inject
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERREUR: La compilation de fish_11_inject a échoué!" -ForegroundColor Red
    exit 1
}
Write-Host "✓ fish_11_inject compilée avec succès" -ForegroundColor Green
Write-Host ""

# Étape 3: Copier les DLLs
Write-Host "[3/3] Copie des DLLs vers mIRC..." -ForegroundColor Yellow
.\copydll.bat
if ($LASTEXITCODE -ne 0) {
    Write-Host "ERREUR: La copie des DLLs a échoué!" -ForegroundColor Red
    exit 1
}
Write-Host "✓ DLLs copiées avec succès" -ForegroundColor Green
Write-Host ""

Write-Host "=== Prêt pour les tests ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Prochaines étapes:" -ForegroundColor White
Write-Host "  1. Redémarrer mIRC complètement" -ForegroundColor Gray
Write-Host "  2. Charger le script: /load -rs scripts\mirc\fish_11.mrc" -ForegroundColor Gray
Write-Host "  3. Tester l'échange de clés: /fish11_X25519_INIT <nick>" -ForegroundColor Gray
Write-Host "  4. Vérifier dans les logs que X25519_INIT passe sans modification" -ForegroundColor Gray
Write-Host "  5. Envoyer un message chiffré et vérifier le déchiffrement auto" -ForegroundColor Gray
Write-Host ""
