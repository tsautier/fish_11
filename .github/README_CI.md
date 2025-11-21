# GitHub Actions Workflows

Ce dossier contient les workflows GitHub Actions pour l'automatisation CI/CD du projet FiSH_11.

## Workflows disponibles

### 🔄 ci.yml - Continuous Integration
**Déclenché sur :** Push et Pull Request sur `main`

Effectue :
- Tests de formatage (`cargo fmt`)
- Analyse statique (`cargo clippy`)
- Compilation sur Linux (x86_64)
- **Compilation sur Windows (i686)** pour mIRC
- Tests unitaires
- Audit de sécurité (`cargo audit`)
- Génération de documentation

### 🚀 release.yml - Création de Release
**Déclenché sur :** Tags `v*.*.*` (ex: `v1.0.0`, `v1.2.3`)

Compile et publie :
- **Windows (i686)** : Package complet avec DLLs et script mIRC
  - `fish_11.dll` - Bibliothèque cryptographique principale
  - `fish_11_inject.dll` - Hooks d'injection réseau
  - `fish_11.mrc` - Script d'interface mIRC
  - `fish_11_cli.exe` - Outil de test en ligne de commande
  - `fish_11.ini` - Template de configuration
  - Documentation (README, INSTALL, LICENSE)

- **Linux (x86_64)** : Outil CLI uniquement
  - `fish_11_cli` - Version Linux pour tests

La release est créée automatiquement avec :
- Notes de version générées
- Artefacts attachés (ZIP Windows + TAR.GZ Linux)
- Instructions d'installation incluses

### 📝 rust.yml - Build simple
Workflow basique pour vérification rapide (peut être supprimé si ci.yml suffit).

## Comment créer une release

### Méthode 1 : Via tag Git (recommandé)

```powershell
# 1. Mettre à jour la version dans fish_11_core/src/globals.rs
# Modifier BUILD_VERSION = "1.2.3"

# 2. Commit des changements
git add .
git commit -m "Bump version to 1.2.3"

# 3. Créer et pousser le tag
git tag v1.2.3
git push origin v1.2.3

# 4. Le workflow release.yml se déclenche automatiquement
# 5. La release apparaît sur https://github.com/ggielly/fish_11/releases
```

### Méthode 2 : Déclenchement manuel

1. Aller sur GitHub → Actions → "Create Release"
2. Cliquer sur "Run workflow"
3. Sélectionner la branche
4. Cliquer sur "Run workflow"

## Structure des artefacts de release

### Windows Package (`fish_11-windows-i686.zip`)
```
fish_11-windows-i686.zip
├── fish_11.dll                 # Bibliothèque crypto principale
├── fish_11_inject.dll          # Injection réseau
├── fish_11_cli.exe             # Outil CLI
├── fish_11.mrc                 # Script mIRC
├── fish_11.ini                 # Configuration par défaut
├── README.md                   # Documentation principale
├── LICENSE                     # Licence GPL-v3
├── INSTALLATION.md             # Guide d'installation (si présent)
└── INSTALL.txt                 # Instructions rapides
```

### Linux Package (`fish_11_cli-linux-x86_64.tar.gz`)
```
fish_11_cli-linux-x86_64.tar.gz
├── fish_11_cli                 # Binaire CLI
├── README.md
├── LICENSE
└── INSTALL.txt
```

## Maintenance des workflows

### Ajout d'une nouvelle dépendance système
Si une dépendance Windows est nécessaire, modifier `release.yml` :
```yaml
- name: Install dependencies
  run: |
    choco install <package>
```

### Modification de la cible de compilation
Pour changer l'architecture (ex: x86_64 au lieu de i686) :
```yaml
targets: x86_64-pc-windows-msvc  # au lieu de i686-pc-windows-msvc
```

### Tests supplémentaires
Ajouter dans `ci.yml` → `jobs` → `test-linux` → `steps` :
```yaml
- name: Run integration tests
  run: cargo test --test integration_tests
```

## Debugging des workflows

### Voir les logs détaillés
1. Aller sur Actions → Sélectionner le workflow
2. Cliquer sur le job qui a échoué
3. Déplier les étapes pour voir les logs

### Tester localement avec act
```powershell
# Installer act (https://github.com/nektos/act)
choco install act-cli

# Tester le workflow CI
act -j build-windows-i686

# Tester le workflow Release
act -j build-windows-i686 -e release-event.json
```

### Cache Cargo
Le cache améliore les temps de build. Pour le vider :
1. GitHub → Settings → Actions → Caches
2. Supprimer les caches obsolètes

## Statuts des badges

Ajouter dans le README principal :
```markdown
![CI](https://github.com/ggielly/fish_11/workflows/Continuous%20Integration/badge.svg)
![Release](https://github.com/ggielly/fish_11/workflows/Create%20Release/badge.svg)
```

## Sécurité

- `GITHUB_TOKEN` est automatiquement fourni (pas besoin de secret)
- Les permissions sont explicitement définies (`contents: write`)
- Les artefacts sont conservés 7 jours pour les releases, 3 jours pour CI

## Support des plateformes

| Plateforme | Architecture | Support | Workflow |
|------------|--------------|---------|----------|
| Windows | i686 (32-bit) | ✅ Complet | release.yml, ci.yml |
| Windows | x86_64 (64-bit) | ⚠️ Possible mais non testé | - |
| Linux | x86_64 | ✅ CLI uniquement | release.yml, ci.yml |
| macOS | arm64/x86_64 | ❌ Non supporté | - |

## Ressources

- [GitHub Actions Docs](https://docs.github.com/en/actions)
- [Rust Book - CI](https://doc.rust-lang.org/book/appendix-04-useful-development-tools.html#continuous-integration)
- [actions-rs/toolchain](https://github.com/actions-rs/toolchain) (deprecated, on utilise dtolnay/rust-toolchain)
- [softprops/action-gh-release](https://github.com/softprops/action-gh-release)
