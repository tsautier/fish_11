use log::{LevelFilter, Record};

pub struct LogFilter {
    pub min_level: LevelFilter,
    pub modules: Vec<String>,
    pub exclude_modules: Vec<String>,
}

impl LogFilter {
    pub fn new(min_level: LevelFilter) -> Self {
        Self { min_level, modules: vec![], exclude_modules: vec![] }
    }

    pub fn include_module(mut self, module: &str) -> Self {
        self.modules.push(module.to_string());
        self
    }

    pub fn exclude_module(mut self, module: &str) -> Self {
        self.exclude_modules.push(module.to_string());
        self
    }

    pub fn should_log(&self, record: &Record) -> bool {
        // Check level
        if record.level() < self.min_level {
            return false;
        }

        let target = record.target();

        // Check exclusions first
        for excluded in &self.exclude_modules {
            if target.starts_with(excluded) {
                return false;
            }
        }

        // If specific modules are included, check if target is in them
        if !self.modules.is_empty() {
            for included in &self.modules {
                if target.starts_with(included) {
                    return true;
                }
            }
            // If we have includes but this target doesn't match, return false
            return false;
        }

        // If no includes specified, and it's not excluded, return true
        true
    }
}
