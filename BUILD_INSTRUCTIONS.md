# Instructions de compilation pour FiSH 11

## Configuration Multiplateforme

Ce projet est configuré pour une compilation par défaut sur Windows, avec support optionnel pour Linux/BSD/macOS via le script `build-unified.sh`.

## Compilation sur Windows

**Méthode recommandée (par défaut) :**
```bash
cargo build --workspace
```

Cette commande utilise la configuration par défaut pour Windows (`x86_64-pc-windows-msvc`).

## Compilation sur Linux/BSD/macOS

**Méthode recommandée :**
```bash
./build-unified.sh
```

### Options disponibles :
- `-h, --help` : Affiche l'aide
- `-i, --install` : Installe Rust si non présent
- `-c, --check` : Vérifie seulement l'environnement
- `-t, --target` : Spécifie une cible manuellement (ex: `aarch64-unknown-linux-gnu`)

### Exemples :
```bash
# Compilation normale pour la plateforme actuelle
./build-unified.sh

# Installation de Rust si nécessaire puis compilation
./build-unified.sh -i

# Vérification seulement de l'environnement
./build-unified.sh -c

# Compilation pour une cible spécifique
./build-unified.sh -t aarch64-unknown-linux-gnu
```

## Configuration Technique

### Cargo.toml
La configuration par défaut est définie dans `[workspace.metadata]` :
```toml
[workspace.metadata]
default-target = "x86_64-pc-windows-msvc"
```

### Détection de Plateforme
Le script `build-unified.sh` détecte automatiquement :
- **OS** : Linux, macOS, FreeBSD, OpenBSD, NetBSD, DragonFly
- **Architecture** : x86_64, aarch64, i686, etc.

### Vérifications Automatiques
Le script vérifie :
- Présence de Rust (rustc) et Cargo
- Version minimale de Rust (1.60+ recommandé)
- Linkers appropriés (gcc/clang pour Linux, cc pour BSD, clang pour macOS)

### Gestion des Erreurs
- Messages colorés (désactivables)
- Codes de retour appropriés
- Détection et blocage sur Windows (redirection vers cargo build)

## Structure du Projet

```
fish_11/
├── Cargo.toml              # Configuration workspace (Windows par défaut)
├── build-unified.sh        # Script de build pour Linux/BSD/macOS
├── fish_11_core/           # Code core (multiplateforme)
├── fish_11_dll/            # Code spécifique DLL (Windows)
├── fish_11_cli/            # Interface CLI
└── fish_11_inject/         # Code d'injection
```

## Bonnes Pratiques

1. **Pour Windows** : Utilisez toujours `cargo build --workspace`
2. **Pour Linux/BSD/macOS** : Utilisez toujours `./build-unified.sh`
3. **Pour le développement** : Testez régulièrement sur les deux environnements
4. **Pour le CI/CD** : Utilisez le script pour les builds Linux/BSD

## Résolution des Problèmes

### Erreur : "Ce script est conçu pour Linux/BSD/macOS seulement"
Vous essayez d'exécuter le script sur Windows. Utilisez simplement :
```bash
cargo build --workspace
```

### Erreur : "Rust n'est pas installé"
Utilisez l'option `-i` pour installer Rust automatiquement :
```bash
./build-unified.sh -i
```

### Erreur : "Aucun linker disponible"
Installez les outils de développement pour votre plateforme :
- **Linux** : `sudo apt install build-essential` (Debian/Ubuntu)
- **BSD** : `pkg install gcc` ou `pkg install clang`
- **macOS** : `xcode-select --install`

## Notes Importantes

- Le script `build-unified.sh` est **POSIX compliant** et fonctionne avec `sh`, `dash`, etc.
- La configuration par défaut reste inchangée pour Windows
- Aucune modification manuelle de configuration n'est nécessaire pour les builds multiplateformes
- Le script gère automatiquement les features spécifiques à chaque plateforme
