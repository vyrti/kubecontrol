//! Kubernetes client abstraction

use crate::error::{KcError, Result};
use kube::{config::KubeConfigOptions, Client, Config};

/// Create a Kubernetes client for the specified context
pub async fn create_client(context: Option<&str>) -> Result<Client> {
    let config = load_config(context).await?;
    Client::try_from(config).map_err(KcError::from)
}

/// Load Kubernetes configuration
async fn load_config(context: Option<&str>) -> Result<Config> {
    let options = KubeConfigOptions {
        context: context.map(String::from),
        ..Default::default()
    };

    Config::from_kubeconfig(&options)
        .await
        .map_err(|e| KcError::Config(format!("Failed to load kubeconfig: {e}")))
}

/// Get all available contexts from kubeconfig
pub fn list_contexts() -> Result<Vec<ContextInfo>> {
    let kubeconfig = kube::config::Kubeconfig::read().map_err(|e| {
        KcError::Config(format!("Failed to read kubeconfig: {e}"))
    })?;

    let current = kubeconfig.current_context.as_deref();

    let contexts = kubeconfig
        .contexts
        .into_iter()
        .map(|ctx| {
            let name = ctx.name.clone();
            let cluster = ctx.context.as_ref().map(|c| c.cluster.clone());
            let namespace = ctx.context.as_ref().and_then(|c| c.namespace.clone());
            let is_current = current == Some(name.as_str());

            ContextInfo {
                name,
                cluster,
                namespace,
                is_current,
            }
        })
        .collect();

    Ok(contexts)
}

/// Get the current context name
pub fn current_context() -> Result<String> {
    let kubeconfig = kube::config::Kubeconfig::read()
        .map_err(|e| KcError::Config(format!("Failed to read kubeconfig: {e}")))?;

    kubeconfig
        .current_context
        .ok_or(KcError::NoContext)
}

/// Context information
#[derive(Debug, Clone)]
pub struct ContextInfo {
    pub name: String,
    pub cluster: Option<String>,
    pub namespace: Option<String>,
    pub is_current: bool,
}
