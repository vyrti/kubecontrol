//! Kubernetes Debugging Suite
//!
//! Comprehensive debugging capabilities for diagnosing Kubernetes cluster issues.
//! Available via `kc debug` CLI command and Web API.

pub mod types;
pub mod pod;
pub mod events;
pub mod dns;
pub mod network;
pub mod node;
pub mod deployment;
pub mod service;
pub mod storage;
pub mod security;
pub mod resources;
pub mod ingress;
pub mod cluster;
pub mod report;

pub use types::*;
pub use report::*;

use kube::Client;
use crate::error::KcError;

/// Run all debug checks
pub async fn debug_all(
    client: &Client,
    namespace: Option<&str>,
) -> Result<DebugReport, KcError> {
    let mut all_issues = Vec::new();

    // Run all category checks in parallel
    let (pod_result, event_result, dns_result, node_result,
         deploy_result, svc_result, storage_result, security_result,
         resource_result, cluster_result) = tokio::join!(
        pod::debug_pods(client, namespace),
        events::debug_events(client, namespace),
        dns::debug_dns(client),
        node::debug_nodes(client),
        deployment::debug_deployments(client, namespace),
        service::debug_services(client, namespace),
        storage::debug_storage(client, namespace),
        security::debug_security(client, namespace),
        resources::debug_resources(client, namespace),
        cluster::debug_cluster(client),
    );

    // Collect all issues
    if let Ok(report) = pod_result {
        all_issues.extend(report.issues);
    }
    if let Ok(report) = event_result {
        all_issues.extend(report.issues);
    }
    if let Ok(report) = dns_result {
        all_issues.extend(report.issues);
    }
    if let Ok(report) = node_result {
        all_issues.extend(report.issues);
    }
    if let Ok(report) = deploy_result {
        all_issues.extend(report.issues);
    }
    if let Ok(report) = svc_result {
        all_issues.extend(report.issues);
    }
    if let Ok(report) = storage_result {
        all_issues.extend(report.issues);
    }
    if let Ok(report) = security_result {
        all_issues.extend(report.issues);
    }
    if let Ok(report) = resource_result {
        all_issues.extend(report.issues);
    }
    if let Ok(report) = cluster_result {
        all_issues.extend(report.issues);
    }

    Ok(DebugReport::new("all", all_issues))
}
