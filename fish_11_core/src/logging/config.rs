use log::LevelFilter;
use std::path::PathBuf;

#[derive(Clone, Debug)]
pub struct LogConfig {
    pub level: LevelFilter,
    pub file_path: PathBuf,
    pub max_file_size: u64,
    pub max_files: usize,
    pub console_output: bool,
    pub console_level: LevelFilter,
    pub enable_context: bool, // Ajouter des contextes (module, fonction, etc.)
    pub mask_sensitive: bool, // Masquer les données sensibles
    pub structured_logs: bool, // Format JSON pour les logs structurés
    pub enable_metrics: bool, // Activer le suivi des métriques
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
