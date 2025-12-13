# Analyse et Refactoring du Système de Log pour FiSH_11

## Table des Matières
1. [État Actuel du Système de Log](#état-actuel-du-système-de-log)
2. [Problèmes Identifiés](#problèmes-identifiés)
3. [Objectifs de Refactoring](#objectifs-de-refactoring)
4. [Architecture Proposée](#architecture-proposée)
5. [Plan de Migration Étape par Étape](#plan-de-migration-étape-par-étape)
6. [Code Robuste et Partagé](#code-robuste-et-partagé)
7. [Fonctionnalités de Recherche](#fonctionnalités-de-recherche)
8. [Implémentation Technique](#implémentation-technique)
9. [Tests et Validation](#tests-et-validation)
10. [Documentation et Maintenance](#documentation-et-maintenance)

## État Actuel du Système de Log

### Composants Principaux

1. **fish_11_dll/src/logging.rs**
   - `FileLogger` : Logger personnalisé qui écrit dans un fichier
   - `init_logger()` : Initialisation du logger avec gestion thread-safe
   - Fonctions de log structuré : `log_module_init()`, `log_function_entry()`, etc.
   - Niveau de log forcé à `LevelFilter::Debug` en mode debug

2. **fish_11_dll/src/logging_macros.rs**
   - Macros conditionnelles : `log_debug!`, `log_trace!` désactivées en mode release
   - Macros de base : `log_info!`, `log_warn!`, `log_error!` toujours actives
   - Vérification systématique de l'initialisation du logger

3. **fish_11_inject/src/helpers_inject.rs**
   - `TimestampLogger` : Logger similaire mais indépendant
   - Initialisation séparée avec `init_logger()`
   - Niveau de log à `LevelFilter::Trace` pour le debug

4. **fish_11_inject/src/hook_ssl.rs**
   - Utilisation intensive de `log::debug!`, `log::info!`, `log::error!`
   - Logs détaillés pour le débogage SSL avec `#[cfg(debug_assertions)]`
   - Gestion des erreurs et logs de diagnostic

### Utilisation Actuelle

- **DLL Core** : Logs d'initialisation, de configuration et de cycle de vie
- **DLL Functions** : Logs d'entrée/sortie de fonctions avec trace IDs
- **SSL Hooks** : Logs détaillés des opérations SSL avec prévisualisation hexadécimale
- **Socket Operations** : Logs des opérations réseau et des échanges de données

## Problèmes Identifiés

### 1. Duplication de Code
- Deux implémentations de logger indépendantes (`FileLogger` et `TimestampLogger`)
- Logique similaire mais code dupliqué pour l'écriture de fichiers et la gestion des mutex
- Macros de log redéfinies dans différents modules

### 2. Inconsistance des Niveaux de Log
- Niveaux de log différents entre les modules (Debug vs Trace)
- Pas de configuration centralisée des niveaux de log
- Difficulté à maintenir une politique de log cohérente

### 3. Gestion des Erreurs Insuffisante
- Erreurs de log silencieuses (écriture de fichier, verrouillage)
- Pas de mécanisme de fallback en cas d'échec du log
- Gestion des mutex poisonés mais pas de stratégie de récupération claire

### 4. Performances et Concurrence
- Verrouillage potentiellement bloquant dans les hooks critiques
- Pas de gestion des timeouts pour les opérations de log
- Impact potentiel sur les performances des opérations SSL

### 5. Configuration et Flexibilité
- Configuration de log hardcodée (niveau, fichier de sortie)
- Pas de support pour la rotation de logs
- Pas de support pour plusieurs destinations de log (fichier + console)

### 6. Débogage et Production
- Pas de séparation claire entre les logs de debug et de production
- Logs de debug trop verbeux en production
- Pas de filtrage efficace des logs sensibles

## Objectifs de Refactoring

### 1. Centralisation et Réutilisation
- Un seul système de log partagé entre tous les modules
- Élimination de la duplication de code
- Interface unifiée pour le logging

### 2. Configuration Flexible
- Niveaux de log configurables par environnement (DEBUG vs RELEASE)
- Support pour la rotation de logs
- Multiple destinations (fichier, console, système)

### 3. Performances et Fiabilité
- Gestion des timeouts pour les opérations de log
- Stratégie de fallback en cas d'échec
- Minimisation de l'impact sur les opérations critiques

### 4. Sécurité et Conformité
- Filtrage des données sensibles
- Gestion des erreurs de log sans crash
- Protection contre les attaques par déni de service via les logs

### 5. Maintenabilité
- Documentation complète
- Tests unitaires et d'intégration
- Interface claire et intuitive

## Architecture Proposée

### 1. Module Central de Logging

```rust
pub mod logging {
    // Configuration centralisée
    pub struct LogConfig {
        level: LevelFilter,
        file_path: PathBuf,
        max_file_size: u64,
        max_files: usize,
        console_output: bool,
    }

    // Logger unifié
    pub struct UnifiedLogger {
        config: LogConfig,
        file_writer: Arc<Mutex<FileWriter>>,
        console_writer: ConsoleWriter,
    }

    // Interface de log
    pub trait Logger: log::Log + Send + Sync {
        fn log_with_context(&self, record: &log::Record, context: &LogContext);
        fn flush_with_timeout(&self, timeout: Duration) -> Result<(), LogError>;
    }
}
```

### 2. Gestion des Niveaux de Log

```rust
#[cfg(debug_assertions)]
const DEFAULT_LOG_LEVEL: LevelFilter = LevelFilter::Debug;

#[cfg(not(debug_assertions))]
const DEFAULT_LOG_LEVEL: LevelFilter = LevelFilter::Info;
```

### 3. Contexte de Log Structuré

```rust
pub struct LogContext {
    module: &'static str,
    function: &'static str,
    trace_id: String,
    timestamp: DateTime<Local>,
    is_debug_build: bool,
}
```

### 4. Macros de Log Améliorées

```rust
#[macro_export]
macro_rules! log_debug {
    ($ctx:expr, $($arg:tt)*) => {
        if cfg!(debug_assertions) && crate::logging::is_initialized() {
            crate::logging::log_with_context(
                log::Level::Debug,
                $ctx,
                format_args!($($arg)*)
            );
        }
    };
}
```

## Plan de Migration Étape par Étape

### Phase 1: Analyse et Préparation
1. **Audit complet** des appels de log existants
2. **Documentation** des besoins spécifiques par module
3. **Création de tests** pour valider le comportement actuel
4. **Benchmark** des performances actuelles

### Phase 2: Implémentation du Nouveau Système
1. **Créer le module central** `logging` avec l'architecture proposée
2. **Implémenter les writers** (fichier, console, système)
3. **Créer les macros unifiées** avec support de contexte
4. **Ajouter la gestion des erreurs** et des timeouts
5. **Implémenter la rotation de logs** et la configuration

### Phase 3: Migration des Modules Existants
1. **fish_11_dll** : Migrer vers le nouveau système
2. **fish_11_inject** : Migrer vers le nouveau système
3. **SSL Hooks** : Adapter les logs détaillés
4. **DLL Functions** : Utiliser le contexte structuré

### Phase 4: Tests et Validation
1. **Tests unitaires** pour chaque composant
2. **Tests d'intégration** pour les scénarios complexes
3. **Tests de performance** pour valider l'impact
4. **Tests de stress** pour la concurrence

### Phase 5: Documentation et Déploiement
1. **Documentation complète** du nouveau système
2. **Exemples d'utilisation** pour les développeurs
3. **Guide de migration** pour les contributeurs
4. **Mise à jour des CI/CD** pour les tests de log

## Code Robuste et Partagé

### 1. Élimination de la Duplication

**Avant:**
```rust
// Dans logging.rs
pub struct FileLogger {
    level: LevelFilter,
    file: Arc<Mutex<std::fs::File>>,
}

// Dans helpers_inject.rs  
pub struct TimestampLogger {
    file: std::sync::Mutex<std::fs::File>,
    level: LevelFilter,
}
```

**Après:**
```rust
// Dans logging.rs
pub struct UnifiedFileWriter {
    file: Arc<Mutex<std::fs::File>>,
    rotation_config: LogRotationConfig,
}

impl UnifiedFileWriter {
    pub fn write_with_timeout(&self, data: &[u8], timeout: Duration) -> Result<(), LogError> {
        // Logique unifiée avec gestion des erreurs
    }
}
```

### 2. Gestion des Erreurs Centralisée

```rust
pub enum LogError {
    FileWriteError(io::Error),
    LockTimeout,
    MutexPoisoned,
    ConfigurationError(String),
}

impl From<io::Error> for LogError {
    fn from(err: io::Error) -> Self {
        LogError::FileWriteError(err)
    }
}
```

### 3. Configuration Centralisée

```rust
pub fn configure_logging(config: LogConfig) -> Result<(), LogError> {
    // Initialisation thread-safe
    LOGGER_INIT.call_once(|| {
        let logger = UnifiedLogger::new(config);
        log::set_boxed_logger(Box::new(logger))?;
        log::set_max_level(config.level);
    });
    Ok(())
}
```

### 4. Macros avec Contexte

```rust
#[macro_export]
macro_rules! log_function_entry {
    ($ctx:expr) => {
        crate::logging::log_with_context(
            log::Level::Debug,
            $ctx,
            format_args!("ENTER: {}", $ctx.function)
        );
    };
}
```

## Fonctionnalités de Recherche

### 1. Filtrage par Contexte

```rust
pub fn filter_logs_by_module(module: &str) -> Vec<LogRecord> {
    // Implémentation de filtrage efficace
}
```

### 2. Recherche par Trace ID

```rust
pub fn find_logs_by_trace_id(trace_id: &str) -> Vec<LogRecord> {
    // Recherche dans les logs structurés
}
```

### 3. Analyse des Performances

```rust
pub fn analyze_log_performance() -> LogPerformanceReport {
    // Statistiques sur les temps de log et les goulots
}
```

## Implémentation Technique

### 1. Structure des Fichiers

```
fish_11_core/
└── src/
    └── logging/
        ├── mod.rs          # Module principal
        ├── config.rs       # Configuration
        ├── writers.rs      # FileWriter, ConsoleWriter
        ├── macros.rs       # Macros de log
        ├── context.rs      # LogContext
        └── errors.rs       # Gestion des erreurs
```

### 2. Dépendances

```toml
[dependencies]
log = "0.4"
chrono = "0.4"
lazy_static = "1.4"
parking_lot = "0.12"  # Pour les mutex performants
```

### 3. Exemple d'Utilisation

```rust
// Initialisation
let config = LogConfig {
    level: LevelFilter::Debug,
    file_path: "fish_11.log".into(),
    max_file_size: 10 * 1024 * 1024,  // 10MB
    max_files: 5,
    console_output: cfg!(debug_assertions),
};

logging::configure_logging(config)?;

// Utilisation dans une fonction
let ctx = LogContext::new("SSL", "hooked_ssl_read", generate_trace_id());
log_debug!(&ctx, "SSL_read called with {} bytes", num);
```

## Tests et Validation

### 1. Tests Unitaires

```rust
#[test]
fn test_file_writer_rotation() {
    let temp_dir = tempfile::tempdir().unwrap();
    let config = LogRotationConfig {
        max_size: 1024,
        max_files: 3,
        path: temp_dir.path().join("test.log"),
    };
    
    let writer = FileWriter::new(config);
    // Test de rotation
}
```

### 2. Tests de Concurrence

```rust
#[test]
fn test_concurrent_logging() {
    let logger = Arc::new(UnifiedLogger::new(test_config()));
    let mut handles = vec![];
    
    for i in 0..10 {
        let logger_clone = Arc::clone(&logger);
        handles.push(thread::spawn(move || {
            for j in 0..100 {
                logger_clone.log(&log::Record::builder()
                    .args(format!("Thread {} - Message {}", i, j))
                    .level(log::Level::Info)
                    .build())
                    .unwrap();
            }
        }));
    }
    
    for handle in handles {
        handle.join().unwrap();
    }
}
```

### 3. Tests de Performance

```rust
#[bench]
fn bench_log_performance(b: &mut Bencher) {
    let logger = UnifiedLogger::new(test_config());
    let record = log::Record::builder()
        .args("Test message")
        .level(log::Level::Info)
        .build();
    
    b.iter(|| {
        logger.log(&record).unwrap();
    });
}
```

## Documentation et Maintenance

### 1. Documentation des APIs

```rust
/// Logger unifié pour FiSH_11
///
/// Ce logger gère l'écriture dans des fichiers avec rotation,
/// la sortie console conditionnelle, et la gestion des erreurs.
///
/// # Exemples
///
/// ```no_run
/// use fish_11_logging::{UnifiedLogger, LogConfig};
///
/// let config = LogConfig::default();
/// let logger = UnifiedLogger::new(config);
/// logger.init().expect("Failed to initialize logger");
/// ```
```

### 2. Guide de Contribution

```markdown
## Ajouter des Logs à un Nouveau Module

1. Importer le module de logging:
   ```rust
   use fish_11_logging::{log_debug, log_info, LogContext};
   ```

2. Créer un contexte de log:
   ```rust
   let ctx = LogContext::new("MON_MODULE", "ma_fonction");
   ```

3. Utiliser les macros de log:
   ```rust
   log_debug!(&ctx, "Début du traitement");
   // ... code ...
   log_info!(&ctx, "Traitement terminé avec succès");
   ```
```

### 3. Maintenance Continue

- **Revue de code** pour les nouveaux logs
- **Audit régulier** des niveaux de log
- **Nettoyage** des logs obsolètes
- **Amélioration** des performances

## Éléments de Sécurité et Confidentialité

### 1. Masquage des Données Sensibles
```rust
pub fn mask_sensitive_data(input: &str) -> String {
    // Exemples de données sensibles à masquer
    lazy_static! {
        static ref KEY_PATTERN: Regex = Regex::new(r"[A-Za-z0-9+/]{43}=").unwrap();
        static ref IP_PATTERN: Regex = Regex::new(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b").unwrap();
        static ref NICKNAME_PATTERN: Regex = Regex::new(r"\b\w{1,32}\b").unwrap();
    }

    let mut result = input.to_string();

    // Masquer les clés X25519
    result = KEY_PATTERN.replace_all(&result, "X25519_KEY_REDACTED").to_string();

    // Masquer les adresses IP
    result = IP_PATTERN.replace_all(&result, "IP_REDACTED").to_string();

    result
}
```

### 2. Contrôle d'Accès aux Logs
```rust
pub enum LogSecurityLevel {
    Public,      // Informations non sensibles
    Internal,    // Détails internes mais non critiques
    Sensitive,   // Données potentiellement sensibles
    Confidential // Données critiques (clés, etc.)
}

pub fn should_log_at_security_level(level: LogSecurityLevel) -> bool {
    match level {
        LogSecurityLevel::Public => true,
        LogSecurityLevel::Internal => cfg!(debug_assertions),
        LogSecurityLevel::Sensitive => false, // Jamais en production
        LogSecurityLevel::Confidential => false,
    }
}
```

## Intégration avec les Systèmes Externes

### 1. Support des Standards de Log
- **RFC 5424 (Syslog)** pour l'interopérabilité
- **Structured Logging** avec format JSON
- **Corrélation des traces** avec les systèmes de monitoring

### 2. Interface avec les Systèmes de Monitoring
```rust
pub trait MonitoringAdapter {
    fn emit_metric(&self, name: &str, value: f64, tags: &[(&str, &str)]);
    fn emit_event(&self, event_type: &str, properties: &[(&str, &str)]);
    fn set_context(&self, key: &str, value: &str);
}
```

## Traitement et Analyse des Logs

### 1. Agrégation des Logs
```rust
pub struct LogAggregator {
    buffer: Vec<LogRecord>,
    aggregation_rules: Vec<LogAggregationRule>,
    output_handlers: Vec<Box<dyn LogOutput>>,
}

impl LogAggregator {
    pub fn add_aggregation_rule(&mut self, rule: LogAggregationRule) {
        self.aggregation_rules.push(rule);
    }

    pub fn process_batch(&mut self) -> Result<(), LogError> {
        // Agrégation et traitement par lots pour meilleure performance
        Ok(())
    }
}
```

### 2. Analyse en Temps Réel
```rust
pub struct RealTimeLogAnalyzer {
    pattern_matchers: Vec<PatternMatcher>,
    alert_handlers: Vec<AlertHandler>,
    performance_counters: LogPerformanceCounters,
}

impl RealTimeLogAnalyzer {
    pub fn register_pattern(&mut self, pattern: &str, callback: Box<dyn Fn(&LogRecord)>) {
        self.pattern_matchers.push(PatternMatcher::new(pattern, callback));
    }

    pub fn check_for_anomalies(&mut self, record: &LogRecord) -> Vec<Alert> {
        // Détection d'anomalies en temps réel
        vec![]
    }
}
```

## Tests Complets et Validation

### 1. Tests de Performance des Logs
```rust
#[cfg(test)]
mod performance_tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn test_log_performance_under_load() {
        let logger = create_test_logger();
        let iterations = 100_000;

        let start = Instant::now();
        for i in 0..iterations {
            log_debug!(logger, "Test message {}", i);
        }

        let duration = start.elapsed();
        let avg_time_per_log = duration / iterations;

        assert!(avg_time_per_log.as_micros() < 100, // < 100µs par log
                "Logging too slow: {}µs per log", avg_time_per_log.as_micros());
    }
}
```

### 2. Tests de Concurrence et Sûreté des Threads
```rust
#[cfg(test)]
mod concurrency_tests {
    use super::*;
    use std::thread;
    use std::sync::Arc;

    #[test]
    fn test_concurrent_loggers() {
        let logger = Arc::new(UnifiedLogger::new(test_config()));
        let mut handles = vec![];

        for i in 0..10 {
            let logger_clone = Arc::clone(&logger);
            handles.push(thread::spawn(move || {
                for j in 0..1000 {
                    log_info!(logger_clone, "Thread {} - Message {}", i, j);
                }
            }));
        }

        for handle in handles {
            handle.join().unwrap();
        }
    }
}
```

## Monitoring et Observabilité

### 1. Métriques de Performance
- **Temps de log moyen** et **percentiles**
- **Taux de logs par seconde**
- **Utilisation des ressources** (CPU, mémoire, disque)
- **Erreurs de log** et **taux de succès**

### 2. Tableau de Bord de Surveillance
```rust
pub struct LogMetrics {
    pub log_count: AtomicU64,
    pub error_count: AtomicU64,
    pub avg_duration: AtomicU64, // en nanosecondes
    pub current_loggers: AtomicUsize,
    pub disk_usage: AtomicU64,
}
```

## Plan de Migration Détaillé

### Phase 1: Préparation et Tests
1. **Audit complet** du code existant pour identifier tous les appels de log
2. **Création d'un wrapper** temporaire pour faciliter la migration
3. **Tests de référence** pour valider le comportement actuel
4. **Mise en place des outils** de validation

### Phase 2: Développement de l'Architecture
1. **Implémentation du module central** `UnifiedLogger`
2. **Tests unitaires** pour chaque composant
3. **Benchmarks** pour valider les performances
4. **Tests de sécurité** de base

### Phase 3: Migration Progressive
1. **Migration des modules les moins critiques** d'abord
2. **Tests d'intégration** à chaque étape
3. **Validation des performances** après chaque migration
4. **Documentation** des changements

### Phase 4: Migration Critique
1. **Migration des modules de cryptographie et de sécurité**
2. **Tests de sécurité approfondis**
3. **Tests de performance sous charge**
4. **Validation finale**

### Phase 5: Finalisation
1. **Retrait du code ancien** de logging
2. **Optimisation finale** des performances
3. **Documentation complète** du système
4. **Documentation de migration** pour les contributeurs

## Dépendances et Compatibilité

### 1. Dépendances Recommandées
```toml
[dependencies]
log = "0.4"           # Interface de logging standard
env_logger = "0.10"   # Pour le support d'env_logger
chrono = "0.4"        # Gestion des timestamps
parking_lot = "0.12"  # Mutex performants
serde = { version = "1.0", features = ["derive"] }  # Pour les logs structurés
thiserror = "1.0"     # Pour les erreurs de logging
regex = "1.0"         # Pour le masquage de données sensibles
```

### 2. Compatibilité
- **API Stable** pour les macros publiques
- **Rétrocompatibilité** avec les anciens appels de log (via adaptateurs)
- **Support des versions** Rust actuelle et N-1
- **Intégration** avec les systèmes de logging externes

## Conclusion

Ce plan de refactoring du système de logging pour FiSH-11 propose une approche complète qui améliore non seulement la structure du code mais aussi:

1. **La sécurité** avec le masquage des données sensibles
2. **La performance** avec des mécanismes d'optimisation
3. **La fiabilité** avec une gestion robuste des erreurs
4. **L'observabilité** avec des métriques et surveillance
5. **La maintenance** avec une documentation complète

L'approche progressive permet de minimiser les risques tout en apportant des améliorations significatives à la fois pour les développeurs et les utilisateurs du système. La nouvelle architecture permettra de mieux diagnostiquer et résoudre les problèmes tout en maintenant des performances optimales dans les opérations critiques comme les hooks SSL.

## Structure Détaillée pour le Refactoring - Spécifications Techniques

Ce document fournit une structure détaillée complète pour un agent LLM chargé d'implémenter le système de logging refactoré selon les spécifications ci-dessus.

### 1. Architecture du Nouveau Système de Logging

#### 1.1 Structure des Fichiers à Créer

```
fish_11_core/src/
└── logging/
    ├── mod.rs              # Module racine et gestion de l'initialisation
    ├── config.rs           # Configuration du logger (niveaux, fichiers, etc.)
    ├── unified_logger.rs   # Logger principal et gestion des destinations
    ├── writers/            # Gestion des sorties de logs
    │   ├── file_writer.rs  # Écriture dans des fichiers avec rotation
    │   ├── console_writer.rs # Sortie console conditionnelle
    │   └── null_writer.rs  # Writer muet pour les tests
    ├── macros.rs           # Macros de logging améliorées
    ├── context.rs          # Contexte de log (module, fonction, trace_id)
    ├── security.rs         # Masquage des données sensibles
    ├── errors.rs           # Gestion des erreurs de logging
    ├── filters.rs          # Filtres de log (niveaux, modules, etc.)
    └── metrics.rs          # Métriques de performance
```

#### 1.2 Dépendances Requises

```toml
[dependencies]
log = "0.4"           # Interface de logging standard
chrono = { version = "0.4", features = ["serde"] }  # Gestion des timestamps
parking_lot = "0.12"  # Mutex performants
lazy_static = "1.4"   # Pour les expressions regex statiques
serde = { version = "1.0", features = ["derive"] }  # Pour les logs structurés
thiserror = "1.0"     # Pour les erreurs de logging
regex = "1.0"         # Pour le masquage de données sensibles
cfg-if = "1.0"        # Pour les configurations conditionnelles

[target.'cfg(windows)'.dependencies]
windows = { version = "0.52", features = ["Win32-System-Console"] }
```

### 2. Implémentation Détailée

#### 2.1 Module Principal (`mod.rs`)

```rust
use log::Log;
use std::sync::{Arc, Mutex};

pub mod config;
pub mod unified_logger;
pub mod writers;
pub mod context;
pub mod security;
pub mod errors;
pub mod filters;
pub mod metrics;

use unified_logger::UnifiedLogger;
use config::LogConfig;

// Global logger instance
static mut LOGGER: Option<UnifiedLogger> = None;
static LOGGER_INIT: std::sync::Once = std::sync::Once::new();

pub fn init_logging(config: LogConfig) -> Result<(), errors::LogError> {
    let result = std::panic::catch_unwind(|| {
        LOGGER_INIT.call_once(|| {
            unsafe {
                LOGGER = Some(UnifiedLogger::new(config));
                log::set_logger(&LOGGER.as_ref().unwrap())
                    .map(|()| log::set_max_level(LOGGER.as_ref().unwrap().max_level()))
                    .expect("Failed to initialize logger");
            }
        });
    });

    match result {
        Ok(()) => Ok(()),
        Err(_) => Err(errors::LogError::InitializationFailed),
    }
}

pub fn is_initialized() -> bool {
    unsafe { LOGGER.is_some() }
}
```

#### 2.2 Configuration (`config.rs`)

```rust
use std::path::PathBuf;
use log::LevelFilter;

#[derive(Clone, Debug)]
pub struct LogConfig {
    pub level: LevelFilter,
    pub file_path: PathBuf,
    pub max_file_size: u64,
    pub max_files: usize,
    pub console_output: bool,
    pub console_level: LevelFilter,
    pub enable_context: bool,     // Ajouter des contextes (module, fonction, etc.)
    pub mask_sensitive: bool,     // Masquer les données sensibles
    pub structured_logs: bool,    // Format JSON pour les logs structurés
    pub enable_metrics: bool,     // Activer le suivi des métriques
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: default_log_level(),
            file_path: PathBuf::from("fish_11.log"),
            max_file_size: 10 * 1024 * 1024, // 10MB
            max_files: 5,
            console_output: cfg!(debug_assertions),
            console_level: default_console_level(),
            enable_context: true,
            mask_sensitive: true,
            structured_logs: false,
            enable_metrics: true,
        }
    }
}

#[cfg(debug_assertions)]
fn default_log_level() -> LevelFilter {
    LevelFilter::Debug
}

#[cfg(not(debug_assertions))]
fn default_log_level() -> LevelFilter {
    LevelFilter::Info
}

#[cfg(debug_assertions)]
fn default_console_level() -> LevelFilter {
    LevelFilter::Debug
}

#[cfg(not(debug_assertions))]
fn default_console_level() -> LevelFilter {
    LevelFilter::Warn
}
```

#### 2.3 Logger Unifié (`unified_logger.rs`)

```rust
use log::{Log, LevelFilter, Metadata, Record};
use std::sync::Arc;
use std::time::Duration;

use crate::logging::writers::{FileWriter, ConsoleWriter};
use crate::logging::context::LogContext;
use crate::logging::security;
use crate::logging::errors::LogError;
use crate::logging::config::LogConfig;

pub struct UnifiedLogger {
    file_writer: Arc<FileWriter>,
    console_writer: Option<ConsoleWriter>,
    config: LogConfig,
    context_enabled: bool,
    mask_sensitive: bool,
}

impl UnifiedLogger {
    pub fn new(config: LogConfig) -> Self {
        let file_writer = Arc::new(FileWriter::new(&config.file_path, config.max_file_size, config.max_files));
        let console_writer = if config.console_output {
            Some(ConsoleWriter::new(config.console_level))
        } else {
            None
        };

        Self {
            file_writer,
            console_writer,
            config,
            context_enabled: config.enable_context,
            mask_sensitive: config.mask_sensitive,
        }
    }

    pub fn log_with_context(&self, record: &Record, context: &LogContext) -> Result<(), LogError> {
        let mut formatted_record = record.clone();

        // Apply security filtering if enabled
        if self.mask_sensitive {
            formatted_record = self.apply_security_filter(formatted_record);
        }

        // Add context if enabled
        if self.context_enabled {
            formatted_record = self.add_context(formatted_record, context);
        }

        // Write to file
        self.file_writer.write_record(&formatted_record)?;

        // Write to console if enabled
        if let Some(ref console_writer) = self.console_writer {
            if record.level() <= self.config.console_level {
                console_writer.write_record(&formatted_record)?;
            }
        }

        Ok(())
    }

    fn apply_security_filter(&self, mut record: Record) -> Record {
        // This is a simplified version - in practice, you'd need to clone the record properly
        // which requires some more complex implementation for the Record type
        // For now, we'll just use the log function to apply the mask
        let args = format!("{}", record.args());
        let masked_args = security::mask_sensitive_data(&args);
        // Note: In full implementation, would need to properly recreate the Record with masked args
        record
    }

    fn add_context(&self, mut record: Record, context: &LogContext) -> Record {
        // In a full implementation, this would add context information to the record
        // For now, placeholder implementation
        record
    }

    pub fn flush_with_timeout(&self, timeout: Duration) -> Result<(), LogError> {
        // Attempt to flush with a timeout
        let start = std::time::Instant::now();

        // We'll implement a timeout mechanism for flushing
        while start.elapsed() < timeout {
            if self.file_writer.flush().is_ok() {
                if let Some(ref console_writer) = self.console_writer {
                    let _ = console_writer.flush(); // Ignore console flush errors
                }
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(1));
        }

        Err(LogError::FlushTimeout)
    }
}

impl Log for UnifiedLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= self.config.level
    }

    fn log(&self, record: &Record) {
        if self.enabled(record.metadata()) {
            // Create a default context for logs without explicit context
            let default_context = crate::logging::context::LogContext::default();
            if let Err(e) = self.log_with_context(record, &default_context) {
                eprintln!("Failed to log record: {:?}", e);
            }
        }
    }

    fn flush(&self) {
        let _ = self.flush_with_timeout(Duration::from_millis(100)); // 100ms timeout
    }
}
```

#### 2.4 Gestion des Fichiers (`writers/file_writer.rs`)

```rust
use std::fs::{File, OpenOptions};
use std::io::{Write, BufWriter};
use std::path::Path;
use std::sync::{Arc, Mutex};
use log::Record;
use std::time::Duration;
use crate::logging::errors::LogError;

pub struct FileWriter {
    file: Arc<Mutex<BufWriter<File>>>,
    path: std::path::PathBuf,
    max_size: u64,
    max_files: usize,
    current_size: std::sync::atomic::AtomicU64,
}

impl FileWriter {
    pub fn new(path: &Path, max_size: u64, max_files: usize) -> Self {
        let file = Self::open_file(path);
        let initial_size = file.metadata().map(|m| m.len()).unwrap_or(0);

        Self {
            file: Arc::new(Mutex::new(BufWriter::new(file))),
            path: path.to_path_buf(),
            max_size,
            max_files,
            current_size: std::sync::atomic::AtomicU64::new(initial_size),
        }
    }

    fn open_file(path: &Path) -> File {
        OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .expect("Failed to open log file")
    }

    pub fn write_record(&self, record: &Record) -> Result<(), LogError> {
        // Create a timeout mechanism for write operations
        let start_time = std::time::Instant::now();
        let timeout = Duration::from_millis(100); // 100ms timeout

        // Attempt to acquire lock with timeout-like behavior
        loop {
            if start_time.elapsed() > timeout {
                return Err(LogError::WriteTimeout);
            }

            match self.file.try_lock() {
                Ok(mut guard) => {
                    // Format the log record
                    let formatted = self.format_record(record);

                    // Check size before writing
                    let current_size = self.current_size.load(std::sync::atomic::Ordering::Relaxed);
                    if formatted.len() as u64 + current_size > self.max_size {
                        drop(guard); // Release lock before rotation
                        self.rotate_files()?;
                        guard = self.file.lock().map_err(|_| LogError::MutexPoisoned)?; // Re-acquire lock
                    }

                    // Write the record
                    guard.write_all(formatted.as_bytes())
                        .map_err(|e| LogError::WriteError(e))?;

                    // Update size counter
                    self.current_size.fetch_add(formatted.len() as u64,
                                               std::sync::atomic::Ordering::Relaxed);

                    // Attempt to flush but don't fail if flush fails
                    let _ = guard.flush();

                    return Ok(());
                }
                Err(_) => {
                    // Brief pause before trying again
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        }
    }

    fn format_record(&self, record: &Record) -> String {
        use chrono::Local;

        let timestamp = Local::now().format("%Y-%m-%d %H:%M:%S%.3f").to_string();
        let level = record.level();
        let target = record.target();
        let args = record.args();

        format!("[{}] {} [{}] {}\n", timestamp, level, target, args)
    }

    fn rotate_files(&self) -> Result<(), LogError> {
        use std::fs;
        use std::path::Path;

        // Close the current file
        let mut current_file = self.file.lock().map_err(|_| LogError::MutexPoisoned)?;

        // Flush and close the current file
        current_file.flush().map_err(|e| LogError::WriteError(e))?;

        // Check if we need to rotate
        let metadata = fs::metadata(&self.path).map_err(|e| LogError::IoError(e))?;
        if metadata.len() <= self.max_size {
            return Ok(()); // No need to rotate
        }

        drop(current_file); // Release the lock before file operations

        // Perform rotation: log.4 -> log.5, log.3 -> log.4, etc.
        for i in (1..=self.max_files).rev() {
            let old_path = self.path.with_extension(format!("{}.{}", self.path.extension().unwrap_or_default(), i));
            let new_path = self.path.with_extension(format!("{}.{}", self.path.extension().unwrap_or_default(), i + 1));

            if Path::exists(&old_path) {
                let _ = fs::rename(&old_path, &new_path); // Ignore errors for non-existent files
            }
        }

        // Move current log to .1 extension
        let backup_path = self.path.with_extension(format!("{}.1", self.path.extension().unwrap_or_default()));
        let _ = fs::rename(&self.path, &backup_path); // Ignore errors

        // Reopen the file
        let new_file = Self::open_file(&self.path);
        let mut new_writer = BufWriter::new(new_file);

        // Update our internal state
        let mut guard = self.file.lock().map_err(|_| LogError::MutexPoisoned)?;
        *guard = new_writer;
        self.current_size.store(0, std::sync::atomic::Ordering::Relaxed);

        Ok(())
    }

    pub fn flush(&self) -> Result<(), LogError> {
        let mut guard = self.file.lock().map_err(|_| LogError::MutexPoisoned)?;
        guard.flush().map_err(|e| LogError::WriteError(e))
    }
}
```

#### 2.5 Contexte de Log (`context.rs`)

```rust
use chrono::{DateTime, Local};
use std::sync::atomic::{AtomicU64, Ordering};
use std::fmt;

// Global counter for unique trace IDs
static TRACE_ID_COUNTER: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Debug)]
pub struct LogContext {
    pub module: &'static str,
    pub function: &'static str,
    pub trace_id: String,
    pub timestamp: DateTime<Local>,
    pub thread_id: u64,
    pub file: Option<&'static str>,
    pub line: Option<u32>,
}

impl LogContext {
    pub fn new(module: &'static str, function: &'static str) -> Self {
        Self {
            module,
            function,
            trace_id: generate_trace_id(),
            timestamp: Local::now(),
            thread_id: get_thread_id(),
            file: None,
            line: None,
        }
    }

    pub fn with_location(mut self, file: &'static str, line: u32) -> Self {
        self.file = Some(file);
        self.line = Some(line);
        self
    }

    pub fn with_trace_id(mut self, trace_id: String) -> Self {
        self.trace_id = trace_id;
        self
    }
}

impl Default for LogContext {
    fn default() -> Self {
        Self {
            module: "unknown",
            function: "unknown",
            trace_id: generate_trace_id(),
            timestamp: Local::now(),
            thread_id: get_thread_id(),
            file: None,
            line: None,
        }
    }
}

fn generate_trace_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let counter = TRACE_ID_COUNTER.fetch_add(1, Ordering::SeqCst);

    format!("{:016x}{:016x}", now, counter)
}

fn get_thread_id() -> u64 {
    use std::thread;
    // A simple hash of the thread id for consistent identification
    let id = format!("{:?}", thread::current().id());
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    id.hash(&mut hasher);
    hasher.finish()
}

impl fmt::Display for LogContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}::{}[{}]",
            self.module, self.function, self.trace_id
        )
    }
}
```

#### 2.6 Sécurité - Masquage des Données (`security.rs`)

```rust
use regex::Regex;
use lazy_static::lazy_static;

/// Masks sensitive information in log messages
pub fn mask_sensitive_data(input: &str) -> String {
    let mut result = input.to_string();

    // Mask X25519 public key patterns (43-44 chars, typically ending with = or ==)
    result = mask_x25519_keys(&result);

    // Mask IP addresses
    result = mask_ip_addresses(&result);

    // Mask potential keys that look like base64
    result = mask_potential_keys(&result);

    result
}

fn mask_x25519_keys(input: &str) -> String {
    lazy_static! {
        // Pattern for X25519 public keys (43-44 base64 chars with padding)
        static ref X25519_PATTERN: Regex = Regex::new(r"[A-Za-z0-9+/]{42,44}={0,2}").unwrap();
    }

    X25519_PATTERN
        .replace_all(input, "X25519_KEY_REDACTED")
        .to_string()
}

fn mask_ip_addresses(input: &str) -> String {
    lazy_static! {
        static ref IP_PATTERN: Regex = Regex::new(r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap();
    }

    IP_PATTERN
        .replace_all(input, "IP_REDACTED")
        .to_string()
}

fn mask_potential_keys(input: &str) -> String {
    lazy_static! {
        // Pattern for potential key-like strings (longer base64 patterns)
        static ref KEY_PATTERN: Regex = Regex::new(r"(?i)(key|token|secret|password)\s*[:=]\s*[A-Za-z0-9+/]{20,}={0,2}").unwrap();
    }

    KEY_PATTERN
        .replace_all(input, |caps: &regex::Captures| {
            let prefix = &caps[0..caps.get(1).unwrap().start()];
            format!("{}REDACTED_VALUE", prefix)
        })
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_x25519_keys() {
        let input = "Key: 3R6TSmBAdNS7Ek2NtfmjL2ocxntj5KlZsceiKjDeGZU=";
        let result = mask_x25519_keys(input);
        assert!(result.contains("X25519_KEY_REDACTED"));
    }

    #[test]
    fn test_mask_ip_addresses() {
        let input = "Connection from 192.168.1.1";
        let result = mask_ip_addresses(input);
        assert!(result.contains("IP_REDACTED"));
    }
}
```

#### 2.7 Macros de Logging Améliorées (`macros.rs`)

```rust
/// Macro de log avec contexte - la plus importante
#[macro_export]
macro_rules! log_with_context {
    ($level:expr, $ctx:expr, $($arg:tt)+) => {
        if log::log_enabled!($level) {
            let record = log::Record::builder()
                .level($level)
                .target(module_path!())
                .args(format_args!($($arg)+))
                .file(file!())
                .line(line!())
                .build();

            $crate::logging::log_with_context(&record, $ctx);
        }
    };
}

/// Version simplifiée pour les logs sans contexte explicite
#[macro_export]
macro_rules! log_simple {
    ($level:expr, $($arg:tt)+) => {
        if log::log_enabled!($level) {
            log::log!(
                target: module_path!(),
                $level,
                $($arg)+
            );
        }
    };
}

/// Macros spécifiques avec contexte
#[macro_export]
macro_rules! log_debug_with_context {
    ($ctx:expr, $($arg:tt)+) => {
        $crate::log_with_context!(log::Level::Debug, $ctx, $($arg)+);
    };
}

#[macro_export]
macro_rules! log_info_with_context {
    ($ctx:expr, $($arg:tt)+) => {
        $crate::log_with_context!(log::Level::Info, $ctx, $($arg)+);
    };
}

#[macro_export]
macro_rules! log_warn_with_context {
    ($ctx:expr, $($arg:tt)+) => {
        $crate::log_with_context!(log::Level::Warn, $ctx, $($arg)+);
    };
}

#[macro_export]
macro_rules! log_error_with_context {
    ($ctx:expr, $($arg:tt)+) => {
        $crate::log_with_context!(log::Level::Error, $ctx, $($arg)+);
    };
}

/// Macros conditionnelles pour les builds de debug
#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)+) => {
        #[cfg(debug_assertions)]
        {
            $crate::log_simple!(log::Level::Debug, $($arg)+);
        }
    };
}

#[macro_export]
macro_rules! log_trace {
    ($($arg:tt)+) => {
        #[cfg(debug_assertions)]
        {
            $crate::log_simple!(log::Level::Trace, $($arg)+);
        }
    };
}

// Fonction d'aide pour log_with_context (à implémenter dans le module principal)
pub fn log_with_context(record: &log::Record, _context: &crate::logging::context::LogContext) {
    log::logger().log(record);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::logging::context::LogContext;

    #[test]
    fn test_log_with_context_macro() {
        let ctx = LogContext::new("TEST_MODULE", "test_function");
        log_with_context!(log::Level::Info, &ctx, "Test message with context");
    }
}
```

### 3. Plan de Migration Détaillé pour l'Agent LLM

#### 3.1 Étape 1: Création de la Structure de Base
1. Créer le répertoire `fish_11_core/src/logging/`
2. Implémenter les modules dans l'ordre: `errors.rs`, `config.rs`, `context.rs`, `security.rs`, `writers/file_writer.rs`, `writers/console_writer.rs`, `writers/null_writer.rs`, `unified_logger.rs`, `metrics.rs`, `filters.rs`, `macros.rs`, `mod.rs`
3. Tester l'initialisation du logger

#### 3.2 Étape 2: Migration des Modules Existant
1. **fish_11_dll/src/logging.rs** → Remplacer par le nouveau système
2. **fish_11_inject/src/helpers_inject.rs** → Remplacer le TimestampLogger
3. Mettre à jour tous les appels de `log_debug!`, `log_info!`, etc.
4. Mettre en place les contextes appropriés

#### 3.3 Étape 3: Adaptation des Macros Existantes
1. Remplacer les macros conditionnelles existantes
2. Mettre en place la rétrocompatibilité avec les anciens appels
3. Adapter les appels dans `dll_interface`, `engine_registration`, etc.

#### 3.4 Étape 4: Tests et Validation
1. Implémenter les tests de performance
2. Valider la sécurité des logs
3. Vérifier la non-régression fonctionnelle
4. Tester la concurrence et la performance

#### 3.5 Étape 5: Optimisation et Finalisation
1. Optimiser les performances
2. Finaliser la documentation
3. Nettoyer les anciens modules de logging
4. Mettre à jour les CI/CD

### 4. Considérations Techniques Spécifiques

#### 4.1 Gestion des Erreurs
- Ne jamais planter en cas d'erreur de logging
- Mettre en place des mécanismes de fallback
- Journaliser les erreurs de logging dans un canal secondaire si possible

#### 4.2 Sécurité
- Masquage automatique des données sensibles
- Contrôle des niveaux de log par environnement
- Pas de logs sensibles en production

#### 4.3 Performance
- Utiliser des mutex non bloquants autant que possible
- Mettre en place des timeouts pour les opérations critiques
- Éviter les opérations de I/O dans les chemins critiques

### 5. Exemples d'Utilisation du Nouveau Système

```rust
// Initialisation dans le point d'entrée
use fish_11_core::logging::{init_logging, config::LogConfig};

fn main() {
    let config = LogConfig {
        level: log::LevelFilter::Debug,
        file_path: std::path::PathBuf::from("fish_11.log"),
        max_file_size: 10 * 1024 * 1024, // 10MB
        max_files: 5,
        console_output: cfg!(debug_assertions),
        ..LogConfig::default()
    };

    init_logging(config).expect("Failed to initialize logger");

    // Utilisation avec contexte
    let ctx = LogContext::new("MyModule", "my_function");
    log_info_with_context!(&ctx, "Starting operation with parameter: {}", "value");

    // Utilisation simple (pour rétrocompatibilité)
    log_info!("Simple log message");
}

// Dans une fonction avec gestion d'erreur
use fish_11_core::logging::{LogContext, log_error_with_context};

fn cryptographic_operation() -> Result<(), Box<dyn std::error::Error>> {
    let ctx = LogContext::new("Crypto", "cryptographic_operation");

    log_info_with_context!(&ctx, "Starting cryptographic operation");

    // Si une erreur se produit
    if let Err(e) = perform_operation() {
        log_error_with_context!(&ctx, "Cryptographic operation failed: {}", e);
        return Err(e.into());
    }

    log_info_with_context!(&ctx, "Operation completed successfully");
    Ok(())
}
```

Cette structure fournit une spécification technique complète pour implémenter le système de logging refactoré pour FiSH-11. L'agent LLM devrait implémenter chaque composant dans l'ordre spécifié, en suivant les interfaces et en respectant les considérations de sécurité, performance et fiabilité.
