//! Application configuration for kubecontrol

use crate::error::{KcError, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Application configuration stored in ~/.kc/config.toml
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppConfig {
    /// Default output format
    #[serde(default)]
    pub default_output: OutputFormat,

    /// Whether to use colors
    #[serde(default = "default_true")]
    pub colors: bool,

    /// Cache TTL in seconds
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: u64,

    /// Enable caching
    #[serde(default = "default_true")]
    pub cache_enabled: bool,
}

fn default_true() -> bool {
    true
}

fn default_cache_ttl() -> u64 {
    30
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum OutputFormat {
    #[default]
    Table,
    Json,
    Yaml,
    Wide,
    Name,
}

/// Application state stored in ~/.kc/state.json
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AppState {
    /// Last used context
    pub last_context: Option<String>,

    /// Last used namespace per context
    #[serde(default)]
    pub namespaces: std::collections::HashMap<String, String>,
}

impl AppState {
    /// Get the last namespace used for a context
    pub fn namespace_for_context(&self, context: &str) -> Option<&str> {
        self.namespaces.get(context).map(String::as_str)
    }

    /// Set the namespace for a context
    pub fn set_namespace(&mut self, context: &str, namespace: &str) {
        self.namespaces
            .insert(context.to_string(), namespace.to_string());
    }
}

/// Get the kc config directory (~/.kc)
pub fn config_dir() -> Result<PathBuf> {
    dirs::home_dir()
        .map(|h| h.join(".kc"))
        .ok_or_else(|| KcError::Config("Could not determine home directory".to_string()))
}

/// Get the cache directory (~/.kc/cache)
pub fn cache_dir() -> Result<PathBuf> {
    config_dir().map(|d| d.join("cache"))
}

/// Load application config from ~/.kc/config.toml
pub fn load_config() -> Result<AppConfig> {
    let path = config_dir()?.join("config.toml");
    if path.exists() {
        let content = std::fs::read_to_string(&path)?;
        toml::from_str(&content).map_err(|e| KcError::Config(e.to_string()))
    } else {
        Ok(AppConfig::default())
    }
}

/// Load application state from ~/.kc/state.json
pub fn load_state() -> Result<AppState> {
    let path = config_dir()?.join("state.json");
    if path.exists() {
        let content = std::fs::read_to_string(&path)?;
        serde_json::from_str(&content).map_err(|e| KcError::Config(e.to_string()))
    } else {
        Ok(AppState::default())
    }
}

/// Save application state to ~/.kc/state.json
pub fn save_state(state: &AppState) -> Result<()> {
    let dir = config_dir()?;
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("state.json");
    let content = serde_json::to_string_pretty(state)?;
    std::fs::write(path, content)?;
    Ok(())
}
