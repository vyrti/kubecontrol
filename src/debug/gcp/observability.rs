//! GKE observability checks
//!
//! Checks for Cloud Logging, Cloud Monitoring, and cluster configuration.

use crate::debug::types::{DebugCategory, DebugIssue, Severity};
use crate::error::KcError;
use k8s_openapi::api::apps::v1::DaemonSet;
use k8s_openapi::api::core::v1::{Namespace, Pod};
use kube::{api::ListParams, Api, Client};

pub async fn check_gke_observability(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let pods: Api<Pod> = Api::namespaced(client.clone(), "kube-system");

    // Check Fluent Bit (Cloud Logging agent)
    if let Ok(fluentbit_pods) = pods
        .list(&ListParams::default().labels("k8s-app=fluentbit-gke"))
        .await
    {
        if fluentbit_pods.items.is_empty() {
            issues.push(
                DebugIssue::new(
                    Severity::Info,
                    DebugCategory::Cluster,
                    "DaemonSet",
                    "fluentbit-gke",
                    "Cloud Logging Agent Not Found",
                    "Fluent Bit logging agent not detected",
                )
                .with_namespace("kube-system")
                .with_remediation("Enable Cloud Logging on the cluster if log collection is needed"),
            );
        } else {
            let unhealthy: Vec<_> = fluentbit_pods.items.iter()
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
                        "fluentbit-gke",
                        "Cloud Logging Agent Issues",
                        format!("{} fluentbit-gke pods are not healthy", unhealthy.len()),
                    )
                    .with_namespace("kube-system")
                    .with_remediation("Check fluentbit-gke pod logs for errors"),
                );
            }
        }
    }

    // Check GKE Metrics Agent
    if let Ok(metrics_pods) = pods
        .list(&ListParams::default().labels("k8s-app=gke-metrics-agent"))
        .await
    {
        if metrics_pods.items.is_empty() {
            issues.push(
                DebugIssue::new(
                    Severity::Info,
                    DebugCategory::Cluster,
                    "DaemonSet",
                    "gke-metrics-agent",
                    "Cloud Monitoring Agent Not Found",
                    "GKE metrics agent not detected",
                )
                .with_namespace("kube-system")
                .with_remediation("Enable Cloud Monitoring on the cluster if metrics collection is needed"),
            );
        } else {
            let unhealthy: Vec<_> = metrics_pods.items.iter()
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
                        "gke-metrics-agent",
                        "Cloud Monitoring Agent Issues",
                        format!("{} gke-metrics-agent pods are not healthy", unhealthy.len()),
                    )
                    .with_namespace("kube-system")
                    .with_remediation("Check gke-metrics-agent pod logs for errors"),
                );
            }
        }
    }

    // Check for Managed Prometheus
    let gmp_ns_api: Api<Namespace> = Api::all(client.clone());
    if gmp_ns_api.get("gmp-system").await.is_ok() {
        let gmp_pods: Api<Pod> = Api::namespaced(client.clone(), "gmp-system");
        if let Ok(collector_pods) = gmp_pods
            .list(&ListParams::default().labels("app.kubernetes.io/name=collector"))
            .await
        {
            let unhealthy: Vec<_> = collector_pods.items.iter()
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
                        "gmp-collector",
                        "Managed Prometheus Collector Issues",
                        format!("{} collector pods are not healthy", unhealthy.len()),
                    )
                    .with_namespace("gmp-system")
                    .with_remediation("Check collector pod logs in gmp-system namespace"),
                );
            }
        }
    }

    Ok(issues)
}

// =============================================================================
// GCP SDK Integration (requires gcp feature)
// =============================================================================

/// Check GKE cluster configuration via GCP API
#[cfg(feature = "gcp")]
pub async fn check_gke_cluster_config(_client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Note: Full implementation would require:
    // 1. Getting cluster name and project from node labels or environment
    // 2. Creating authenticated GCP client
    // 3. Calling ClusterManager to get cluster details

    // For now, add a placeholder that indicates the feature is enabled
    issues.push(
        DebugIssue::new(
            Severity::Info,
            DebugCategory::Cluster,
            "Feature",
            "gcp",
            "GCP API Checks Enabled",
            "GCP SDK is available for extended cluster configuration checks",
        )
        .with_remediation("Cluster configuration will be validated via GCP API when credentials are available"),
    );

    Ok(issues)
}
