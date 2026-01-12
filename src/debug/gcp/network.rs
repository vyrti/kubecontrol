//! GKE network and load balancer checks
//!
//! Checks for VPC-native networking and GKE load balancer issues.

use crate::debug::types::{DebugCategory, DebugIssue, Severity};
use crate::error::KcError;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Node, Pod, Service};
use kube::{api::ListParams, Api, Client};

pub async fn check_vpc_native_networking(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let nodes: Api<Node> = Api::all(client.clone());
    let node_list = nodes
        .list(&ListParams::default())
        .await
        .map_err(|e| KcError::Config(e.to_string()))?;

    for node in node_list {
        let node_name = node.metadata.name.clone().unwrap_or_default();

        // Check for pod CIDR allocation
        if let Some(spec) = &node.spec {
            if spec.pod_cidr.is_none() && spec.pod_cidrs.as_ref().map(|c| c.is_empty()).unwrap_or(true) {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Network,
                        "Node",
                        &node_name,
                        "No Pod CIDR Allocated",
                        "Node has no pod CIDR allocated. This may indicate IP exhaustion in the pod IP range.",
                    )
                    .with_remediation(
                        "Check the secondary IP range for pods in your VPC subnet",
                    ),
                );
            }
        }

        // Check for alias IP issues in conditions
        if let Some(status) = &node.status {
            if let Some(conditions) = &status.conditions {
                for condition in conditions {
                    if condition.type_ == "NetworkUnavailable" && condition.status == "True" {
                        if let Some(message) = &condition.message {
                            if message.contains("alias IP") || message.contains("IP range") {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Network,
                                        "Node",
                                        &node_name,
                                        "Alias IP Range Issue",
                                        format!("Node has alias IP issues: {}", message),
                                    )
                                    .with_remediation(
                                        "Check VPC subnet secondary ranges and GKE IP allocation mode",
                                    ),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Check for IP utilization warnings in events
    // This would require events API access which we could add

    Ok(issues)
}

/// Check if cluster is running on GKE
pub async fn check_gke_load_balancers(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Check for GKE Ingress controller (l7-default-backend)
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), "kube-system");

    // Check l7-default-backend for GCE Ingress
    if let Ok(backend) = deployments.get("l7-default-backend").await {
        if let Some(status) = &backend.status {
            let ready = status.ready_replicas.unwrap_or(0);
            let desired = backend.spec.as_ref().and_then(|s| s.replicas).unwrap_or(1);

            if ready < desired {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Network,
                        "Deployment",
                        "l7-default-backend",
                        "GCE Ingress Backend Unhealthy",
                        format!("l7-default-backend has {}/{} replicas ready", ready, desired),
                    )
                    .with_namespace("kube-system")
                    .with_remediation("Check l7-default-backend pod status"),
                );
            }
        }
    }

    // Check services for NEG issues
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

            // Check for NEG annotations
            if let Some(neg_status) = annotations.get("cloud.google.com/neg-status") {
                if neg_status.contains("error") || neg_status.contains("Error") {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Network,
                            "Service",
                            &svc_name,
                            "NEG Error",
                            "Network Endpoint Group has errors",
                        )
                        .with_namespace(&svc_ns)
                        .with_remediation("Check NEG status annotation and GCP console for details"),
                    );
                }
            }

            // Check for internal load balancer issues
            if annotations.get("cloud.google.com/load-balancer-type") == Some(&"Internal".to_string()) {
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
                            .with_remediation("Check subnet configuration and GCP ILB quotas"),
                        );
                    }
                }
            }
        }
    }

    Ok(issues)
}
