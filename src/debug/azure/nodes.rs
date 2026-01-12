//! AKS node and node pool checks
//!
//! Checks for AKS components, virtual nodes, and node pool issues.

use crate::debug::types::{DebugCategory, DebugIssue, Severity};
use crate::error::KcError;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment};
use k8s_openapi::api::core::v1::{Node, Pod};
use kube::{api::ListParams, Api, Client};

pub async fn check_aks_components(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let pods: Api<Pod> = Api::namespaced(client.clone(), "kube-system");

    // Check coredns-autoscaler
    if let Ok(autoscaler_pods) = pods
        .list(&ListParams::default().labels("k8s-app=coredns-autoscaler"))
        .await
    {
        if !autoscaler_pods.items.is_empty() {
            let unhealthy: Vec<_> = autoscaler_pods.items
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
                        DebugCategory::Cluster,
                        "Deployment",
                        "coredns-autoscaler",
                        "CoreDNS Autoscaler Issues",
                        format!("{} coredns-autoscaler pods are not running", unhealthy.len()),
                    )
                    .with_namespace("kube-system")
                    .with_remediation("Check coredns-autoscaler logs. DNS scaling may not work properly."),
                );
            }
        }
    }

    // Check Azure Policy pods
    if let Ok(policy_pods) = pods
        .list(&ListParams::default().labels("app=azure-policy"))
        .await
    {
        if !policy_pods.items.is_empty() {
            let unhealthy: Vec<_> = policy_pods.items
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
                        DebugCategory::Security,
                        "Deployment",
                        "azure-policy",
                        "Azure Policy Add-on Issues",
                        format!("{} Azure Policy pods are not running. Policy enforcement may fail.", unhealthy.len()),
                    )
                    .with_namespace("kube-system")
                    .with_remediation("Check Azure Policy pod logs and Azure portal for policy status"),
                );
            }
        }
    }

    // Check metrics-server (AKS managed)
    if let Ok(metrics_pods) = pods
        .list(&ListParams::default().labels("k8s-app=metrics-server"))
        .await
    {
        if metrics_pods.items.is_empty() {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Cluster,
                    "Deployment",
                    "metrics-server",
                    "Metrics Server Not Found",
                    "No metrics-server pods found. HPA and kubectl top will not work.",
                )
                .with_namespace("kube-system")
                .with_remediation("Check if AKS metrics-server add-on is enabled"),
            );
        } else {
            let unhealthy: Vec<_> = metrics_pods.items
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
                        DebugCategory::Cluster,
                        "Deployment",
                        "metrics-server",
                        "Metrics Server Unhealthy",
                        format!("{} metrics-server pods are not running", unhealthy.len()),
                    )
                    .with_namespace("kube-system")
                    .with_remediation("Check metrics-server pod logs"),
                );
            }
        }
    }

    // Check Key Vault provider for Secrets Store CSI
    if let Ok(kv_pods) = pods
        .list(&ListParams::default().labels("app=secrets-store-csi-driver-provider-azure"))
        .await
    {
        if !kv_pods.items.is_empty() {
            let unhealthy: Vec<_> = kv_pods.items
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
                        DebugCategory::Security,
                        "DaemonSet",
                        "secrets-store-csi-driver-provider-azure",
                        "Key Vault Provider Issues",
                        format!("{} Key Vault provider pods are not running", unhealthy.len()),
                    )
                    .with_namespace("kube-system")
                    .with_remediation("Check secrets-store-csi-driver-provider-azure logs"),
                );
            }
        }
    }

    Ok(issues)
}

/// Check for virtual node (ACI) issues
pub async fn check_virtual_nodes(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let nodes: Api<Node> = Api::all(client.clone());
    if let Ok(node_list) = nodes.list(&ListParams::default()).await {
        let virtual_nodes: Vec<_> = node_list
            .iter()
            .filter(|n| {
                n.metadata
                    .labels
                    .as_ref()
                    .map(|l| l.get("type").map(|v| v == "virtual-kubelet").unwrap_or(false))
                    .unwrap_or(false)
            })
            .collect();

        for vn in &virtual_nodes {
            let node_name = vn.metadata.name.clone().unwrap_or_default();

            if let Some(status) = &vn.status {
                if let Some(conditions) = &status.conditions {
                    for condition in conditions {
                        if condition.type_ == "Ready" && condition.status != "True" {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Critical,
                                    DebugCategory::Cluster,
                                    "Node",
                                    &node_name,
                                    "Virtual Node Not Ready",
                                    condition
                                        .message
                                        .clone()
                                        .unwrap_or_else(|| "Virtual node is not ready".to_string()),
                                )
                                .with_remediation("Check virtual-kubelet pod logs in kube-system namespace"),
                            );
                        }
                    }
                }
            }
        }

        if !virtual_nodes.is_empty() {
            let pods: Api<Pod> = Api::namespaced(client.clone(), "kube-system");
            if let Ok(vk_pods) = pods
                .list(&ListParams::default().labels("app=virtual-kubelet-linux-aci"))
                .await
            {
                let unhealthy: Vec<_> = vk_pods.items
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
                            Severity::Critical,
                            DebugCategory::Cluster,
                            "Deployment",
                            "virtual-kubelet",
                            "Virtual Kubelet Unhealthy",
                            format!("{} virtual-kubelet pods are not running", unhealthy.len()),
                        )
                        .with_namespace("kube-system")
                        .with_remediation("Check virtual-kubelet pod logs"),
                    );
                }
            }
        }
    }

    Ok(issues)
}

/// Check AKS load balancer issues
pub async fn check_aks_node_pools(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let nodes: Api<Node> = Api::all(client.clone());
    if let Ok(node_list) = nodes.list(&ListParams::default()).await {
        for node in node_list {
            let node_name = node.metadata.name.clone().unwrap_or_default();
            let labels = node.metadata.labels.clone().unwrap_or_default();

            if let Some(status) = &node.status {
                if let Some(conditions) = &status.conditions {
                    for condition in conditions {
                        match condition.type_.as_str() {
                            "Ready" if condition.status != "True" => {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Cluster,
                                        "Node",
                                        &node_name,
                                        "Node Not Ready",
                                        condition.message.clone().unwrap_or_else(|| "Node is not ready".to_string()),
                                    )
                                    .with_remediation("Check node status and kubelet logs"),
                                );
                            }
                            "MemoryPressure" if condition.status == "True" => {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Warning,
                                        DebugCategory::Resources,
                                        "Node",
                                        &node_name,
                                        "Node Memory Pressure",
                                        "Node is experiencing memory pressure",
                                    )
                                    .with_remediation("Consider scaling the node pool or optimizing workload memory usage"),
                                );
                            }
                            "DiskPressure" if condition.status == "True" => {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Warning,
                                        DebugCategory::Resources,
                                        "Node",
                                        &node_name,
                                        "Node Disk Pressure",
                                        "Node is experiencing disk pressure",
                                    )
                                    .with_remediation("Clean up unused images/containers or increase disk size"),
                                );
                            }
                            "PIDPressure" if condition.status == "True" => {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Warning,
                                        DebugCategory::Resources,
                                        "Node",
                                        &node_name,
                                        "Node PID Pressure",
                                        "Node is running low on process IDs",
                                    )
                                    .with_remediation("Check for runaway processes or increase PID limits"),
                                );
                            }
                            "NetworkUnavailable" if condition.status == "True" => {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Network,
                                        "Node",
                                        &node_name,
                                        "Node Network Unavailable",
                                        condition.message.clone().unwrap_or_else(|| "Node network is unavailable".to_string()),
                                    )
                                    .with_remediation("Check Azure CNI configuration and node networking"),
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }

            // Check for spot node issues
            if labels.get("kubernetes.azure.com/scalesetpriority") == Some(&"spot".to_string()) {
                if let Some(status) = &node.status {
                    if let Some(conditions) = &status.conditions {
                        for condition in conditions {
                            if condition.type_ == "Ready" && condition.status != "True" {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Info,
                                        DebugCategory::Cluster,
                                        "Node",
                                        &node_name,
                                        "Spot Node Issue",
                                        "Spot VM node may have been evicted",
                                    )
                                    .with_remediation("This is expected behavior for spot nodes"),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Check Cluster Autoscaler
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), "kube-system");
    if let Ok(ca) = deployments.get("cluster-autoscaler").await {
        if let Some(status) = &ca.status {
            let ready = status.ready_replicas.unwrap_or(0);
            if ready == 0 {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Cluster,
                        "Deployment",
                        "cluster-autoscaler",
                        "Cluster Autoscaler Not Ready",
                        "Cluster Autoscaler has no ready replicas",
                    )
                    .with_namespace("kube-system")
                    .with_remediation("Check cluster autoscaler pod logs"),
                );
            }
        }
    }

    Ok(issues)
}
