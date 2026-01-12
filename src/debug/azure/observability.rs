//! AKS observability checks
//!
//! Checks for Azure Monitor, Container Insights, and cluster configuration.

use crate::debug::types::{DebugCategory, DebugIssue, Severity};
use crate::error::KcError;
use k8s_openapi::api::apps::v1::DaemonSet;
use k8s_openapi::api::core::v1::Pod;
use kube::{api::ListParams, Api, Client};

#[cfg(feature = "azure")]
use azure_identity::ManagedIdentityCredential;

pub async fn check_aks_observability(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let pods: Api<Pod> = Api::namespaced(client.clone(), "kube-system");

    // Check Azure Monitor Agent (Container Insights)
    if let Ok(omsagent_pods) = pods
        .list(&ListParams::default().labels("component=oms-agent"))
        .await
    {
        if omsagent_pods.items.is_empty() {
            issues.push(
                DebugIssue::new(
                    Severity::Info,
                    DebugCategory::Cluster,
                    "DaemonSet",
                    "omsagent",
                    "Container Insights Not Found",
                    "Azure Monitor Agent (omsagent) not detected",
                )
                .with_namespace("kube-system")
                .with_remediation("Enable Container Insights on the cluster for monitoring"),
            );
        } else {
            let unhealthy: Vec<_> = omsagent_pods.items.iter()
                .filter(|p| {
                    p.status.as_ref()
                        .and_then(|s| s.phase.as_ref())
                        .map(|ph| ph != "Running")
                        .unwrap_or(true)
                })
                .collect();

            if !unhealthy.is_empty() {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Cluster,
                        "DaemonSet",
                        "omsagent",
                        "Container Insights Agent Issues",
                        format!("{} omsagent pods are not healthy", unhealthy.len()),
                    )
                    .with_namespace("kube-system")
                    .with_remediation("Check omsagent pod logs for errors"),
                );
            }
        }
    }

    // Check Azure Managed Prometheus
    if let Ok(prom_pods) = pods
        .list(&ListParams::default().labels("app=prometheus-operator"))
        .await
    {
        if !prom_pods.items.is_empty() {
            let unhealthy: Vec<_> = prom_pods.items.iter()
                .filter(|p| {
                    p.status.as_ref()
                        .and_then(|s| s.phase.as_ref())
                        .map(|ph| ph != "Running")
                        .unwrap_or(true)
                })
                .collect();

            if !unhealthy.is_empty() {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Cluster,
                        "Deployment",
                        "prometheus-operator",
                        "Azure Managed Prometheus Issues",
                        format!("{} prometheus pods are not healthy", unhealthy.len()),
                    )
                    .with_namespace("kube-system")
                    .with_remediation("Check prometheus pod logs"),
                );
            }
        }
    }

    Ok(issues)
}

// =============================================================================
// Azure SDK Integration (optional, requires azure feature)
// =============================================================================

#[cfg(feature = "azure")]
pub async fn check_aks_cluster_config() -> Result<Vec<DebugIssue>, KcError> {
    // Azure SDK cluster config checks would go here
    // This is a placeholder for Azure-specific API calls
    Ok(Vec::new())
}

// =============================================================================
// AKS Detection
// =============================================================================
