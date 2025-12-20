#!/bin/sh
# Script de build unifié pour FiSH 11 (Linux, BSD, macOS)
# POSIX compliant - fonctionne avec sh, dash, etc.

set -e

# Couleurs pour les messages (désactivables)
if [ -t 1 ]; then
    RED='\033[31m'
    GREEN='\033[32m'
    YELLOW='\033[33m'
    BLUE='\033[34m'
    RESET='\033[0m'
else
    RED=''
    GREEN=''
    YELLOW=''
    BLUE=''
    RESET=''
fi

# Fonctions utilitaires
log_info() {
    printf "${BLUE}[INFO]${RESET} %s\n" "$1"
}

log_success() {
    printf "${GREEN}[SUCCESS]${RESET} %s\n" "$1"
}

log_warning() {
    printf "${YELLOW}[WARNING]${RESET} %s\n" "$1" >&2
}

log_error() {
    printf "${RED}[ERROR]${RESET} %s\n" "$1" >&2
}

detect_os() {
    case "$(uname -s)" in
        Linux*)    echo "linux";;
        Darwin*)   echo "macos";;
        FreeBSD*)  echo "freebsd";;
        OpenBSD*)  echo "openbsd";;
        NetBSD*)   echo "netbsd";;
        DragonFly*) echo "dragonfly";;
        *)         echo "unknown";;
    esac
}

detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64) echo "x86_64";;
        aarch64|arm64) echo "aarch64";;
        i386|i686) echo "i686";;
        *) echo "$(uname -m)";;
    esac
}

check_command() {
    command -v "$1" >/dev/null 2>&1
}

check_rust_toolchain() {
    log_info "Vérification de la toolchain Rust..."
    
    if ! check_command rustc; then
        log_error "Rust (rustc) n'est pas installé."
        return 1
    fi
    
    if ! check_command cargo; then
        log_error "Cargo n'est pas installé."
        return 1
    fi
    
    RUSTC_VERSION=$(rustc --version)
    CARGO_VERSION=$(cargo --version)
    
    log_info "Version de Rust: $RUSTC_VERSION"
    log_info "Version de Cargo: $CARGO_VERSION"
    
    # Vérification version minimale (1.60+ recommandé)
    RUSTC_MAJOR=$(echo "$RUSTC_VERSION" | sed 's/rustc //;s/\..*//;s/\..*//')
    if [ "$RUSTC_MAJOR" -lt 60 ]; then
        log_warning "Version de Rust ancienne (< 1.60). Certaines fonctionnalités peuvent ne pas être disponibles."
    fi
    
    return 0
}

check_linker() {
    OS=$(detect_os)
    
    case "$OS" in
        linux)
            if ! check_command gcc && ! check_command clang; then
                log_error "Aucun linker disponible (gcc ou clang requis)."
                return 1
            fi
            ;;
        freebsd|openbsd|netbsd|dragonfly)
            if ! check_command cc; then
                log_error "Linker système (cc) non trouvé."
                return 1
            fi
            ;;
        macos)
            if ! check_command clang; then
                log_error "Clang non trouvé (requis pour macOS)."
                return 1
            fi
            ;;
        *)
            log_error "OS non supporté pour la détection du linker."
            return 1
            ;;
    esac
    
    return 0
}

install_rust() {
    log_info "Installation de Rust via rustup..."
    
    if ! check_command curl; then
        log_error "curl est requis pour installer Rust."
        return 1
    fi
    
    # Installation de rustup
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    
    # Ajout au PATH pour la session courante
    if [ -d "$HOME/.cargo/bin" ]; then
        PATH="$HOME/.cargo/bin:$PATH"
        export PATH
    fi
    
    if ! check_rust_toolchain; then
        log_error "Échec de l'installation de Rust."
        return 1
    fi
    
    log_success "Rust installé avec succès."
    return 0
}

setup_target() {
    OS=$(detect_os)
    ARCH=$(detect_arch)
    
    case "$OS" in
        linux)    TARGET="${ARCH}-unknown-linux-gnu";;
        macos)    TARGET="${ARCH}-apple-darwin";;
        freebsd)  TARGET="${ARCH}-unknown-freebsd";;
        openbsd)  TARGET="${ARCH}-unknown-openbsd";;
        netbsd)   TARGET="${ARCH}-unknown-netbsd";;
        dragonfly) TARGET="${ARCH}-unknown-dragonfly";;
        *)
            log_error "OS non supporté: $OS"
            return 1
            ;;
    esac
    
    log_info "Cible de compilation: $TARGET"
    echo "$TARGET"
    return 0
}

build_project() {
    TARGET=$1
    
    log_info "Lancement de la compilation pour $TARGET..."
    
    # Configuration spécifique à la cible
    case "$TARGET" in
        *-linux-*)    EXTRA_FLAGS="--features linux-support";;
        *-apple-*)    EXTRA_FLAGS="--features macos-support";;
        *-freebsd*)   EXTRA_FLAGS="--features bsd-support";;
        *-openbsd*)   EXTRA_FLAGS="--features bsd-support";;
        *-netbsd*)    EXTRA_FLAGS="--features bsd-support";;
        *-dragonfly*) EXTRA_FLAGS="--features bsd-support";;
        *)            EXTRA_FLAGS="";;
    esac
    
    # Compilation en mode release
    cargo build --release --target "$TARGET" $EXTRA_FLAGS
    
    if [ $? -ne 0 ]; then
        log_error "Échec de la compilation."
        return 1
    fi
    
    log_success "Compilation réussie!"
    log_info "Binaire disponible dans: target/$TARGET/release/"
    
    return 0
}

show_help() {
    cat <<EOF
Utilisation: $0 [OPTIONS]

Options:
  -h, --help       Affiche cette aide
  -i, --install    Installe Rust si non présent
  -c, --check      Vérifie seulement l'environnement
  -t, --target     Spécifie une cible manuellement (ex: x86_64-unknown-linux-gnu)

Exemples:
  $0                    # Compilation normale
  $0 -i                 # Installe Rust si nécessaire puis compile
  $0 -c                 # Vérifie seulement l'environnement
  $0 -t aarch64-unknown-linux-gnu  # Compile pour une cible spécifique
EOF
}

# Parsing des arguments
INSTALL_RUST=false
CHECK_ONLY=false
CUSTOM_TARGET=""

while [ $# -gt 0 ]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -i|--install)
            INSTALL_RUST=true
            shift
            ;;
        -c|--check)
            CHECK_ONLY=true
            shift
            ;;
        -t|--target)
            CUSTOM_TARGET="$2"
            shift 2
            ;;
        *)
            log_error "Option inconnue: $1"
            show_help
            exit 1
            ;;
    esac
done

# Programme principal
log_info "=== Script de build unifié pour FiSH 11 ==="
log_info "OS détecté: $(uname -s)"
log_info "Architecture: $(uname -m)"

# Vérification de l'environnement
if ! check_linker; then
    exit 1
fi

if ! check_rust_toolchain; then
    if [ "$INSTALL_RUST" = true ]; then
        if ! install_rust; then
            exit 1
        fi
    else
        log_error "Rust n'est pas installé. Utilisez l'option -i pour l'installer."
        exit 1
    fi
fi

if [ "$CHECK_ONLY" = true ]; then
    log_success "Environnement vérifié avec succès."
    exit 0
fi

# Détermination de la cible
if [ -n "$CUSTOM_TARGET" ]; then
    TARGET="$CUSTOM_TARGET"
else
    TARGET=$(setup_target)
    if [ $? -ne 0 ]; then
        exit 1
    fi
fi

# Compilation
if ! build_project "$TARGET"; then
    exit 1
fi

log_success "Build terminé avec succès!"
exit 0
