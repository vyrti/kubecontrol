//! Azure AKS-specific diagnostics
//!
//! Checks for common issues specific to Azure Kubernetes Service clusters.

pub mod config;
pub mod identity;
pub mod network;
pub mod nodes;
pub mod observability;
pub mod registry;
pub mod storage;
pub mod workloads;

// Re-export all check functions
pub use config::*;
pub use identity::*;
pub use network::*;
pub use nodes::*;
pub use observability::*;
pub use registry::*;
pub use storage::*;
pub use workloads::*;

use crate::debug::types::{DebugIssue, DebugReport};
use crate::error::KcError;
use k8s_openapi::api::core::v1::Node;
use kube::Client;

/// Run all AKS-specific diagnostics
pub async fn debug_aks(client: &Client, namespace: Option<&str>) -> Result<DebugReport, KcError> {
    let mut issues = Vec::new();

    // Run checks in 5 parallel batches

    // Batch 1: Core K8s checks
    let (pod_issues, deploy_issues, svc_issues, config_issues, rbac_issues) = tokio::join!(
        check_pod_issues(client, namespace),
        check_deployment_issues(client, namespace),
        check_service_issues(client, namespace),
        check_config_issues(client, namespace),
        check_rbac_issues(client, namespace),
    );

    // Batch 2: More K8s checks
    let (scheduling_issues, sts_issues, job_issues, ingress_issues, webhook_issues) = tokio::join!(
        check_scheduling_issues(client, namespace),
        check_statefulset_issues(client, namespace),
        check_job_issues(client, namespace),
        check_ingress_issues(client, namespace),
        check_webhook_issues(client),
    );

    // Batch 3: Resource and quota checks
    let quota_issues = check_quota_issues(client, namespace).await;

    // Batch 4: AKS-specific provider checks
    let (identity_issues, cni_issues, component_issues, virtual_node_issues) = tokio::join!(
        check_azure_identity(client, namespace),
        check_azure_cni(client),
        check_aks_components(client),
        check_virtual_nodes(client, namespace),
    );

    // Batch 5: More AKS-specific checks
    let (lb_issues, storage_issues, node_pool_issues, acr_issues, obs_issues) = tokio::join!(
        check_aks_load_balancers(client, namespace),
        check_aks_storage(client, namespace),
        check_aks_node_pools(client),
        check_acr_access(client, namespace),
        check_aks_observability(client),
    );

    // Collect all issues
    if let Ok(i) = pod_issues { issues.extend(i); }
    if let Ok(i) = deploy_issues { issues.extend(i); }
    if let Ok(i) = svc_issues { issues.extend(i); }
    if let Ok(i) = config_issues { issues.extend(i); }
    if let Ok(i) = rbac_issues { issues.extend(i); }
    if let Ok(i) = scheduling_issues { issues.extend(i); }
    if let Ok(i) = sts_issues { issues.extend(i); }
    if let Ok(i) = job_issues { issues.extend(i); }
    if let Ok(i) = ingress_issues { issues.extend(i); }
    if let Ok(i) = webhook_issues { issues.extend(i); }
    if let Ok(i) = quota_issues { issues.extend(i); }
    if let Ok(i) = identity_issues { issues.extend(i); }
    if let Ok(i) = cni_issues { issues.extend(i); }
    if let Ok(i) = component_issues { issues.extend(i); }
    if let Ok(i) = virtual_node_issues { issues.extend(i); }
    if let Ok(i) = lb_issues { issues.extend(i); }
    if let Ok(i) = storage_issues { issues.extend(i); }
    if let Ok(i) = node_pool_issues { issues.extend(i); }
    if let Ok(i) = acr_issues { issues.extend(i); }
    if let Ok(i) = obs_issues { issues.extend(i); }

    // Add Azure SDK cluster checks if feature enabled
    #[cfg(feature = "azure")]
    {
        if let Ok(i) = check_aks_cluster_config().await {
            issues.extend(i);
        }
    }

    Ok(DebugReport::new("aks", issues))
}

// =============================================================================
// AKS Detection
// =============================================================================

/// Detect if the cluster is running on AKS
pub fn is_aks(nodes: &[Node]) -> bool {
    nodes.iter().any(|node| {
        let labels = node.metadata.labels.as_ref();
        let provider_id = node
            .spec
            .as_ref()
            .and_then(|s| s.provider_id.as_ref());

        // Check for AKS-specific labels
        let has_aks_labels = labels
            .map(|l| {
                l.contains_key("kubernetes.azure.com/agentpool")
                    || l.contains_key("kubernetes.azure.com/cluster")
                    || l.contains_key("kubernetes.azure.com/mode")
                    || l.contains_key("agentpool")
            })
            .unwrap_or(false);

        // Check for Azure provider ID
        let has_azure_provider = provider_id
            .map(|p| p.starts_with("azure://"))
            .unwrap_or(false);

        has_aks_labels || has_azure_provider
    })
}

/// Detect if the cluster has virtual nodes (ACI virtual kubelet)
pub fn has_virtual_nodes(nodes: &[Node]) -> bool {
    nodes.iter().any(|node| {
        let labels = node.metadata.labels.as_ref();

        // Check for virtual-kubelet type label
        labels
            .map(|l| {
                l.get("type")
                    .map(|v| v == "virtual-kubelet")
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    })
}
