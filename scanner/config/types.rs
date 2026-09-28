#![allow(dead_code)]

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConfigFormat {
    Env,
    Yaml,
    Json,
    Toml,
    Ini,
    ApplicationConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigEntry {
    pub key: String,
    pub value: String,
    pub raw_line: String,
    pub line: usize,
    pub section: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigModel {
    pub file_path: String,
    pub format: ConfigFormat,
    pub entries: Vec<ConfigEntry>,
}

impl ConfigModel {
    pub fn new(file_path: &str, format: ConfigFormat) -> Self {
        Self {
            file_path: file_path.to_string(),
            format,
            entries: Vec::new(),
        }
    }

    pub fn get_value(&self, key: &str) -> Option<&str> {
        let lower = key.to_lowercase();
        self.entries
            .iter()
            .find(|e| e.key.to_lowercase() == lower)
            .map(|e| e.value.as_str())
    }
}
