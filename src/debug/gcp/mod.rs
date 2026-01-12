//! GCP GKE-specific diagnostics
//!
//! Checks for common issues specific to Google Kubernetes Engine clusters.
//! Includes 200+ checks covering GKE provider-specific issues and Kubernetes issues on GKE.

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

use crate::debug::types::{DebugCategory, DebugIssue, DebugReport, Severity};
use crate::error::KcError;
use k8s_openapi::api::core::v1::Node;
use kube::Client;

/// Run all GKE-specific diagnostics
pub async fn debug_gke(client: &Client, namespace: Option<&str>) -> Result<DebugReport, KcError> {
    let mut issues = Vec::new();

    // Run core GKE checks in parallel (batch 1)
    let (wi_issues, autopilot_issues, component_issues, networking_issues) = tokio::join!(
        check_workload_identity(client, namespace),
        check_autopilot_constraints(client, namespace),
        check_gke_components(client),
        check_vpc_native_networking(client),
    );

    if let Ok(wi) = wi_issues {
        issues.extend(wi);
    }
    if let Ok(ap) = autopilot_issues {
        issues.extend(ap);
    }
    if let Ok(comp) = component_issues {
        issues.extend(comp);
    }
    if let Ok(net) = networking_issues {
        issues.extend(net);
    }

    // Run Kubernetes workload checks in parallel (batch 2)
    let (pod_issues, deployment_issues, service_issues, config_issues) = tokio::join!(
        check_pod_issues(client, namespace),
        check_deployment_issues(client, namespace),
        check_service_issues(client, namespace),
        check_config_issues(client, namespace),
    );

    if let Ok(p) = pod_issues {
        issues.extend(p);
    }
    if let Ok(d) = deployment_issues {
        issues.extend(d);
    }
    if let Ok(s) = service_issues {
        issues.extend(s);
    }
    if let Ok(c) = config_issues {
        issues.extend(c);
    }

    // Run additional workload checks in parallel (batch 3)
    let (rbac_issues, scheduling_issues, statefulset_issues, job_issues) = tokio::join!(
        check_rbac_issues(client, namespace),
        check_scheduling_issues(client, namespace),
        check_statefulset_issues(client, namespace),
        check_job_issues(client, namespace),
    );

    if let Ok(r) = rbac_issues {
        issues.extend(r);
    }
    if let Ok(s) = scheduling_issues {
        issues.extend(s);
    }
    if let Ok(ss) = statefulset_issues {
        issues.extend(ss);
    }
    if let Ok(j) = job_issues {
        issues.extend(j);
    }

    // Run infrastructure checks in parallel (batch 4)
    let (ingress_issues, webhook_issues, quota_issues) = tokio::join!(
        check_ingress_issues(client, namespace),
        check_webhook_issues(client),
        check_quota_issues(client, namespace),
    );

    if let Ok(i) = ingress_issues {
        issues.extend(i);
    }
    if let Ok(w) = webhook_issues {
        issues.extend(w);
    }
    if let Ok(q) = quota_issues {
        issues.extend(q);
    }

    // Run GKE-specific checks in parallel (batch 5)
    let (lb_issues, storage_issues, node_pool_issues, gcr_issues, observability_issues) = tokio::join!(
        check_gke_load_balancers(client, namespace),
        check_gke_storage(client, namespace),
        check_gke_node_pools(client),
        check_gcr_access(client, namespace),
        check_gke_observability(client),
    );

    if let Ok(lb) = lb_issues {
        issues.extend(lb);
    }
    if let Ok(st) = storage_issues {
        issues.extend(st);
    }
    if let Ok(np) = node_pool_issues {
        issues.extend(np);
    }
    if let Ok(gcr) = gcr_issues {
        issues.extend(gcr);
    }
    if let Ok(obs) = observability_issues {
        issues.extend(obs);
    }

    // GCP API checks (requires gcp feature)
    #[cfg(feature = "gcp")]
    {
        if let Ok(cluster_issues) = check_gke_cluster_config(client).await {
            issues.extend(cluster_issues);
        }
    }

    #[cfg(not(feature = "gcp"))]
    {
        issues.push(
            DebugIssue::new(
                Severity::Info,
                DebugCategory::Cluster,
                "Feature",
                "gcp",
                "GCP API Checks Disabled",
                "Build with --features gcp for full GKE cluster configuration checks via GCP API",
            )
            .with_remediation("Run: cargo build --features gcp"),
        );
    }

    Ok(DebugReport::new("gke", issues))
}

// =============================================================================
// Detection functions
// =============================================================================

/// Check if cluster is running on GKE
pub fn is_gke(nodes: &[Node]) -> bool {
    nodes.iter().any(|node| {
        node.metadata
            .labels
            .as_ref()
            .map(|labels| {
                labels.contains_key("cloud.google.com/gke-nodepool")
                    || labels.contains_key("cloud.google.com/gke-os-distribution")
            })
            .unwrap_or(false)
    })
}

/// Check if cluster is GKE Autopilot
pub fn is_gke_autopilot(nodes: &[Node]) -> bool {
    nodes.iter().any(|node| {
        node.metadata
            .labels
            .as_ref()
            .map(|labels| labels.contains_key("cloud.google.com/gke-autopilot"))
            .unwrap_or(false)
    })
}
