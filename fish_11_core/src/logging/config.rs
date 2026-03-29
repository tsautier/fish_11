use log::LevelFilter;
use std::path::PathBuf;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LoggingProfile {
    Core,
    Inject,
    Dll,
}

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
    pub include_target: bool,
    pub include_source_location: bool,
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
            include_target: true,
            include_source_location: false,
        }
    }
}

impl LogConfig {
    pub fn for_profile(profile: LoggingProfile) -> Self {
        match profile {
            LoggingProfile::Core => Self::default(),
            LoggingProfile::Inject => Self::for_inject(),
            LoggingProfile::Dll => Self::for_dll(),
        }
    }

    pub fn for_inject() -> Self {
        Self {
            level: LevelFilter::Trace,
            file_path: PathBuf::from("fish11_inject.log"),
            max_file_size: 10 * 1024 * 1024,
            max_files: 3,
            console_output: false,
            console_level: LevelFilter::Off,
            enable_context: false,
            mask_sensitive: false,
            structured_logs: false,
            enable_metrics: false,
            include_target: false,
            include_source_location: true,
        }
    }

    pub fn for_dll() -> Self {
        Self {
            level: LevelFilter::Debug,
            file_path: PathBuf::from("fish_11_dll.log"),
            max_file_size: 10 * 1024 * 1024,
            max_files: 5,
            console_output: false,
            console_level: LevelFilter::Off,
            enable_context: false,
            mask_sensitive: false,
            structured_logs: false,
            enable_metrics: false,
            include_target: false,
            include_source_location: true,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn inject_profile_preserves_file_style_logging() {
        let config = LogConfig::for_inject();

        assert_eq!(config.level, LevelFilter::Trace);
        assert_eq!(config.file_path, PathBuf::from("fish11_inject.log"));
        assert!(!config.console_output);
        assert!(!config.enable_context);
        assert!(!config.mask_sensitive);
        assert!(config.include_source_location);
        assert!(!config.include_target);
    }

    #[test]
    fn dll_profile_preserves_legacy_file_style_logging() {
        let config = LogConfig::for_dll();

        assert_eq!(config.level, LevelFilter::Debug);
        assert_eq!(config.file_path, PathBuf::from("fish_11_dll.log"));
        assert!(!config.console_output);
        assert!(!config.enable_context);
        assert!(!config.mask_sensitive);
        assert!(config.include_source_location);
        assert!(!config.include_target);
    }
}
