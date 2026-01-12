//! Azure CNI and load balancer checks for AKS
//!
//! Checks for Azure CNI, AGIC, and load balancer issues.

use crate::debug::types::{DebugCategory, DebugIssue, Severity};
use crate::error::KcError;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment};
use k8s_openapi::api::core::v1::{Node, Pod, Service};
use kube::{api::ListParams, Api, Client};

pub async fn check_azure_cni(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let nodes: Api<Node> = Api::all(client.clone());
    if let Ok(node_list) = nodes.list(&ListParams::default()).await {
        for node in node_list {
            let node_name = node.metadata.name.clone().unwrap_or_default();

            if let Some(status) = &node.status {
                if let Some(conditions) = &status.conditions {
                    for condition in conditions {
                        if condition.type_ == "NetworkUnavailable" && condition.status == "True" {
                            if let Some(message) = &condition.message {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Network,
                                        "Node",
                                        &node_name,
                                        "Azure CNI Network Issue",
                                        format!("Node network unavailable: {}", message),
                                    )
                                    .with_remediation(
                                        "Check Azure CNI pod health and subnet IP availability",
                                    ),
                                );
                            }
                        }
                    }
                }

                if let Some(allocatable) = &status.allocatable {
                    if let Some(pods) = allocatable.get("pods") {
                        let max_pods: i32 = pods.0.parse().unwrap_or(0);
                        if max_pods < 30 {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Info,
                                    DebugCategory::Network,
                                    "Node",
                                    &node_name,
                                    "Low Pod Capacity",
                                    format!("Node has max {} pods. Consider using larger nodes or Azure CNI Overlay.", max_pods),
                                )
                                .with_remediation(
                                    "Increase node size or switch to Azure CNI Overlay for higher pod density",
                                ),
                            );
                        }
                    }
                }
            }
        }
    }

    // Check for Azure NPM (Network Policy Manager)
    let pods: Api<Pod> = Api::namespaced(client.clone(), "kube-system");
    if let Ok(npm_pods) = pods
        .list(&ListParams::default().labels("k8s-app=azure-npm"))
        .await
    {
        if !npm_pods.items.is_empty() {
            let unhealthy: Vec<_> = npm_pods.items
                .iter()
                .filter(|pod| {
                    pod.status
                        .as_ref()
                        .and_then(|s| s.phase.as_ref())
                        .map(|p| p != "Running")
                        .unwrap_or(true)
                })
                .collect();

            if !unhealthy.is_empty() {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Network,
                        "DaemonSet",
                        "azure-npm",
                        "Azure Network Policy Manager Issues",
                        format!("{} Azure NPM pods are not running. NetworkPolicies may not be enforced.", unhealthy.len()),
                    )
                    .with_namespace("kube-system")
                    .with_remediation("Check azure-npm pod logs for errors"),
                );
            }
        }
    }

    Ok(issues)
}

/// Check AKS-specific system components
pub async fn check_aks_load_balancers(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Check AGIC (Application Gateway Ingress Controller)
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), "default");
    if let Ok(agic) = deployments.get("ingress-appgw-deployment").await {
        if let Some(status) = &agic.status {
            let ready = status.ready_replicas.unwrap_or(0);
            if ready == 0 {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Network,
                        "Deployment",
                        "ingress-appgw-deployment",
                        "AGIC Not Ready",
                        "Application Gateway Ingress Controller has no ready replicas",
                    )
                    .with_namespace("default")
                    .with_remediation("Check AGIC pod logs and Application Gateway health"),
                );
            }
        }
    }

    // Check services for LoadBalancer issues
    let services: Api<Service> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(svc_list) = services.list(&ListParams::default()).await {
        for svc in svc_list {
            let svc_name = svc.metadata.name.clone().unwrap_or_default();
            let svc_ns = svc.metadata.namespace.clone().unwrap_or_default();
            let annotations = svc.metadata.annotations.clone().unwrap_or_default();

            if let Some(spec) = &svc.spec {
                // Check for internal load balancer
                if annotations.get("service.beta.kubernetes.io/azure-load-balancer-internal") == Some(&"true".to_string()) {
                    if let Some(status) = &svc.status {
                        let has_ip = status.load_balancer.as_ref()
                            .and_then(|lb| lb.ingress.as_ref())
                            .map(|i| !i.is_empty())
                            .unwrap_or(false);

                        if !has_ip {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Critical,
                                    DebugCategory::Network,
                                    "Service",
                                    &svc_name,
                                    "Internal LB Pending",
                                    "Internal LoadBalancer has no IP assigned",
                                )
                                .with_namespace(&svc_ns)
                                .with_remediation("Check subnet configuration and Azure ILB quotas"),
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(issues)
}
