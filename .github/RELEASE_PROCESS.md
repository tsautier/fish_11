# Guide de Release FiSH_11

## Processus de release complet

### 1. Préparation

Avant de créer une release, vérifiez :

```powershell
# Vérifier que tout compile en i686
cargo build --release --target i686-pc-windows-msvc --workspace

# Vérifier les tests
cargo test --workspace

# Vérifier le formatage
cargo fmt --all -- --check

# Vérifier clippy
cargo clippy --workspace -- -D warnings
```

### 2. Mise à jour de la version

Modifier `fish_11_core/src/globals.rs` :

```rust
pub const BUILD_VERSION: &str = "1.2.3"; // Nouvelle version
```

### 3. Commit et tag

```powershell
# Commit des changements
git add .
git commit -m "Release v1.2.3

- Feature: Description des nouvelles fonctionnalités
- Fix: Description des corrections
- Breaking: Description des changements cassants (si applicable)
"

# Pousser les changements
git push origin main

# Créer le tag
git tag -a v1.2.3 -m "Version 1.2.3

Principales modifications:
- Nouvelle fonctionnalité X
- Correction du bug Y
- Amélioration de Z
"

# Pousser le tag (déclenche le workflow release)
git push origin v1.2.3
```

### 4. Vérification du workflow

1. Aller sur https://github.com/ggielly/fish_11/actions
2. Vérifier que le workflow "Create Release" s'est déclenché
3. Attendre la fin de la compilation (environ 10-15 minutes)

### 5. Vérification de la release

1. Aller sur https://github.com/ggielly/fish_11/releases
2. Vérifier que la release v1.2.3 existe
3. Télécharger `fish_11-windows-i686.zip`
4. Extraire et vérifier le contenu :
   - `fish_11.dll` présent
   - `fish_11_inject.dll` présent
   - `fish_11.mrc` présent
   - `fish_11_cli.exe` présent
   - `INSTALL.txt` présent

### 6. Test de la release

```powershell
# Extraire dans un dossier temporaire
Expand-Archive fish_11-windows-i686.zip -DestinationPath C:\temp\fish11_test

# Vérifier les exports DLL
dumpbin /EXPORTS C:\temp\fish11_test\fish_11.dll | Select-String "FiSH11"
dumpbin /EXPORTS C:\temp\fish11_test\fish_11_inject.dll | Select-String "FiSH11"

# Tester le CLI
C:\temp\fish11_test\fish_11_cli.exe --version
```

### 7. Annonce de la release

Si tout fonctionne, annoncer la release :
- Sur le README (ajouter un badge avec la dernière version)
- Sur les canaux IRC pertinents
- Sur les forums/communautés utilisatrices

## Gestion des versions

Format : `vMAJOR.MINOR.PATCH`

- **MAJOR** : Changements cassants de l'API
- **MINOR** : Nouvelles fonctionnalités rétrocompatibles
- **PATCH** : Corrections de bugs

Exemples :
- `v1.0.0` : Première release stable
- `v1.1.0` : Ajout du support FCEP-1
- `v1.1.1` : Correction d'un bug dans FCEP-1
- `v2.0.0` : Refonte majeure de l'API

## Rollback en cas de problème

Si la release a un problème majeur :

```powershell
# 1. Supprimer le tag local et distant
git tag -d v1.2.3
git push origin :refs/tags/v1.2.3

# 2. Supprimer la release sur GitHub
# Aller sur https://github.com/ggielly/fish_11/releases
# Cliquer sur "Delete" pour la release

# 3. Corriger le problème
git revert <commit-problematique>
# ou
git reset --hard HEAD~1  # ATTENTION : perte de commits

# 4. Recréer le tag avec un incrément de patch
git tag v1.2.4
git push origin v1.2.4
```

## Checklist avant release

- [ ] Tous les tests passent (`cargo test --workspace`)
- [ ] Le code compile en i686 (`cargo build --release --target i686-pc-windows-msvc`)
- [ ] Pas de warnings clippy (`cargo clippy --workspace -- -D warnings`)
- [ ] Le formatage est correct (`cargo fmt --all -- --check`)
- [ ] La version est mise à jour dans `globals.rs`
- [ ] Le CHANGELOG est à jour (si vous en avez un)
- [ ] Les nouvelles fonctionnalités sont documentées
- [ ] Les tests manuels sur mIRC ont été effectués
- [ ] La documentation README est à jour

## Test manuel du workflow localement

Pour tester sans créer de vraie release :

```powershell
# Installer act (https://github.com/nektos/act)
choco install act-cli

# Créer un fichier d'événement test
@'
{
  "ref": "refs/tags/v1.2.3-test",
  "repository": {
    "name": "fish_11",
    "owner": {
      "login": "ggielly"
    }
  }
}
'@ | Out-File -Encoding UTF8 test-release-event.json

# Exécuter le workflow localement
act push --eventpath test-release-event.json -j build-windows-i686
```

## Automatisation future

Pour aller plus loin :

1. **Changelog automatique** : Utiliser [git-cliff](https://github.com/orhun/git-cliff)
2. **Version bump automatique** : Script PowerShell qui met à jour `globals.rs`
3. **Tests d'intégration** : Workflow qui teste les DLLs avec mIRC headless
4. **Signature des binaires** : Code signing avec certificat Windows

## Ressources

- [Semantic Versioning](https://semver.org/)
- [GitHub Releases](https://docs.github.com/en/repositories/releasing-projects-on-github/managing-releases-in-a-repository)
- [GitHub Actions - Release](https://github.com/marketplace/actions/gh-release)
