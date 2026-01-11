//! Error types for kubecontrol

use thiserror::Error;

/// Main error type for kubecontrol
#[derive(Debug, Error)]
pub enum KcError {
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),

    #[error("Resource not found: {kind}/{name}")]
    NotFound { kind: String, name: String },

    #[error("Multiple matches for '{pattern}': {}", matches.join(", "))]
    AmbiguousMatch { pattern: String, matches: Vec<String> },

    #[error("No context specified and no current context in kubeconfig")]
    NoContext,

    #[error("Context not found: {0}")]
    ContextNotFound(String),

    #[error("Namespace not found: {0}")]
    NamespaceNotFound(String),

    #[error("Invalid resource type: {0}")]
    InvalidResourceType(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Cache error: {0}")]
    Cache(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid argument: {0}")]
    InvalidArgument(String),

    #[error("Operation cancelled")]
    Cancelled,

    #[error("Timeout waiting for {0}")]
    Timeout(String),
}

impl From<serde_json::Error> for KcError {
    fn from(e: serde_json::Error) -> Self {
        KcError::Serialization(e.to_string())
    }
}

impl From<serde_yaml::Error> for KcError {
    fn from(e: serde_yaml::Error) -> Self {
        KcError::Serialization(e.to_string())
    }
}

/// Result type alias for kubecontrol
pub type Result<T> = std::result::Result<T, KcError>;
