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
pub mod cloud;
pub mod gcp;
pub mod azure;
pub mod eks;

pub use types::*;
pub use report::*;

use k8s_openapi::api::core::v1::Node;
use kube::{api::ListParams, Api, Client};
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

    // Run cloud-specific checks based on detected platform
    let nodes: Api<Node> = Api::all(client.clone());
    if let Ok(node_list) = nodes.list(&ListParams::default()).await {
        let node_items = node_list.items;

        // EKS-specific checks
        if eks::is_eks(&node_items) {
            if let Ok(report) = eks::debug_eks(client, namespace).await {
                all_issues.extend(report.issues);
            }
        }

        // GKE-specific checks
        if gcp::is_gke(&node_items) {
            if let Ok(report) = gcp::debug_gke(client, namespace).await {
                all_issues.extend(report.issues);
            }
        }

        // AKS-specific checks
        if azure::is_aks(&node_items) {
            if let Ok(report) = azure::debug_aks(client, namespace).await {
                all_issues.extend(report.issues);
            }
        }
    }

    Ok(DebugReport::new("all", all_issues))
}
