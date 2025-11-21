# Processus de Release FiSH_11

## 🎯 Vue d'ensemble

GitHub Actions ne supporte pas nativement la compilation i686 (32-bit Windows). Pour contourner cette limitation, le processus de release est divisé en deux parties :

1. **GitHub Actions** : Compile le CLI Linux x64 et crée une release draft
2. **Machine locale** : Compile les DLLs i686 et les upload vers la release

## 📋 Prérequis

### Sur votre machine Windows

```powershell
# Installer la cible i686
rustup target add i686-pc-windows-msvc

# Configurer un token GitHub
# 1. Créer un token sur: https://github.com/settings/tokens
# 2. Permissions requises: 'repo' (full control)
# 3. Définir la variable d'environnement:
$env:GITHUB_TOKEN = "ghp_votre_token_ici"
```

## 🚀 Méthode 1 : Script automatique (Recommandé)

Le script `create-release.ps1` automatise tout le processus :

```powershell
# Créer une release complète
.\scripts\create-release.ps1 -Version 1.2.3 -Message "Description de la release"

# Le script va :
# 1. ✅ Vérifier que tout compile
# 2. ✅ Mettre à jour la version dans globals.rs
# 3. ✅ Créer le commit et le tag
# 4. ✅ Pousser vers GitHub
# 5. ⏳ Attendre que GitHub Actions crée la release draft
# 6. 📦 Compiler les binaires i686 localement
# 7. 📤 Uploader les binaires vers la release
```

## 🔧 Méthode 2 : Processus manuel

### Étape 1 : Créer le tag

```powershell
# Mettre à jour la version
code fish_11_core\src\globals.rs
# Modifier: pub const BUILD_VERSION: &str = "1.2.3";

# Commit et tag
git add .
git commit -m "Release 1.2.3"
git tag -a v1.2.3 -m "Release 1.2.3"
git push origin main
git push origin v1.2.3
```

### Étape 2 : Attendre GitHub Actions

GitHub Actions va automatiquement :
- Compiler le CLI Linux x64
- Créer une release **draft** sur GitHub
- Ajouter le CLI Linux à la release

**Suivi de la progression** : https://github.com/ggielly/fish_11/actions

⏱️ Temps estimé : 5-10 minutes

### Étape 3 : Upload des binaires i686

Une fois la release draft créée :

```powershell
# Upload automatique
.\scripts\upload-release-assets.ps1 -Version 1.2.3

# Le script va :
# - Compiler les DLLs en i686
# - Créer le package fish_11-windows-i686.zip
# - Uploader vers la release GitHub
```

### Étape 4 : Publier la release

1. Aller sur : https://github.com/ggielly/fish_11/releases
2. Cliquer sur la release draft
3. Vérifier le contenu :
   - ✅ `fish_11-windows-i686.zip` (DLLs + mIRC script)
   - ✅ `fish_11_cli-linux-x86_64.tar.gz` (CLI Linux)
4. Éditer les notes de release si nécessaire
5. Cliquer sur **"Publish release"**

## 📦 Contenu des packages

### Windows i686 (`fish_11-windows-i686.zip`)

```
fish_11.dll             - Core cryptographic library
fish_11_inject.dll      - Network injection hooks
fish_11_cli.exe         - CLI tool for testing
fish_11.mrc             - mIRC script interface
fish_11.ini             - Configuration template
INSTALL.txt             - Installation instructions
README.md               - Documentation
LICENSE                 - License file
INSTALLATION.md         - Detailed installation guide
```

### Linux x64 (`fish_11_cli-linux-x86_64.tar.gz`)

```
fish_11_cli             - CLI tool (stripped)
INSTALL.txt             - Usage instructions
README.md               - Documentation
LICENSE                 - License file
```

## 🔍 Vérification

Après la publication, vérifier que :

```powershell
# 1. Les binaires téléchargent correctement
Invoke-WebRequest -Uri "https://github.com/ggielly/fish_11/releases/download/v1.2.3/fish_11-windows-i686.zip" -OutFile "test.zip"

# 2. Les DLLs exportent bien les fonctions
dumpbin /EXPORTS target\i686-pc-windows-msvc\release\fish_11.dll | Select-String "FiSH11"
dumpbin /EXPORTS target\i686-pc-windows-msvc\release\fish_11_inject.dll | Select-String "FiSH11"

# 3. Le CLI fonctionne
.\fish_11_cli.exe --help
```

## 🐛 Dépannage

### Erreur : "Release v1.2.3 not found"

La release draft n'a pas encore été créée par GitHub Actions. Attendre que le workflow se termine.

### Erreur : "GitHub token required"

```powershell
# Définir le token
$env:GITHUB_TOKEN = "ghp_votre_token_ici"

# Ou passer en paramètre
.\scripts\upload-release-assets.ps1 -Version 1.2.3 -GithubToken "ghp_xxxx"
```

### Erreur : "target may not be installed"

```powershell
# Installer la cible i686
rustup target add i686-pc-windows-msvc

# Vérifier l'installation
rustup target list | Select-String "i686"
```

### Compilation i686 échoue

```powershell
# Vérifier que le toolchain est installé
rustup show

# Réinstaller si nécessaire
rustup toolchain install stable-i686-pc-windows-msvc
rustup default stable-i686-pc-windows-msvc
```

## 📝 Checklist complète

Avant de créer une release :

- [ ] Tous les tests passent : `cargo test --workspace`
- [ ] Code formaté : `cargo fmt --all -- --check`
- [ ] Clippy OK : `cargo clippy --workspace -- -D warnings`
- [ ] Version mise à jour dans `fish_11_core/src/globals.rs`
- [ ] CHANGELOG.md mis à jour (si applicable)
- [ ] Documentation à jour
- [ ] Token GitHub configuré : `$env:GITHUB_TOKEN`
- [ ] Cible i686 installée : `rustup target add i686-pc-windows-msvc`

Après la release :

- [ ] Release publiée (pas en draft)
- [ ] Binaires téléchargent correctement
- [ ] Release notes complètes
- [ ] Tag git créé et poussé
- [ ] Annonce de la release (si applicable)

## 🔗 Liens utiles

- **Releases** : https://github.com/ggielly/fish_11/releases
- **Actions** : https://github.com/ggielly/fish_11/actions
- **Créer un token** : https://github.com/settings/tokens
- **Documentation** : https://github.com/ggielly/fish_11/tree/main/docs

## 💡 Alternatives futures

Si vous souhaitez compiler i686 sur GitHub Actions à l'avenir, voici quelques options :

### Option A : Self-hosted runner

Héberger votre propre runner Windows avec la cible i686 installée.

```yaml
runs-on: self-hosted
```

### Option B : Docker avec cross-compilation

Utiliser un conteneur Docker avec les outils i686.

```yaml
- name: Setup i686 toolchain
  run: |
    apt-get update
    apt-get install -y gcc-multilib
    rustup target add i686-pc-windows-msvc
```

### Option C : Compiler sur Linux avec wine

Cross-compiler depuis Linux vers Windows i686 (complexe).

Pour l'instant, la méthode locale est la plus simple et fiable. 🎯
