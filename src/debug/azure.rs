//! Azure AKS-specific diagnostics
//!
//! Checks for common issues specific to Azure Kubernetes Service clusters.

use k8s_openapi::api::core::v1::{Node, Pod, ServiceAccount};
use kube::{api::ListParams, Api, Client};
use crate::debug::types::{DebugCategory, DebugIssue, DebugReport, Severity};
use crate::error::KcError;

/// Run all AKS-specific diagnostics
pub async fn debug_aks(client: &Client, namespace: Option<&str>) -> Result<DebugReport, KcError> {
    let mut issues = Vec::new();

    // Run checks in parallel
    let (identity_issues, cni_issues, component_issues, virtual_node_issues) = tokio::join!(
        check_azure_identity(client, namespace),
        check_azure_cni(client),
        check_aks_components(client),
        check_virtual_nodes(client, namespace),
    );

    if let Ok(id) = identity_issues {
        issues.extend(id);
    }
    if let Ok(cni) = cni_issues {
        issues.extend(cni);
    }
    if let Ok(comp) = component_issues {
        issues.extend(comp);
    }
    if let Ok(vn) = virtual_node_issues {
        issues.extend(vn);
    }

    Ok(DebugReport::new("aks", issues))
}

/// Check for Azure AD/Entra and Managed Identity issues
pub async fn check_azure_identity(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Check for Azure AD Pod Identity (legacy) or Workload Identity pods
    let kube_system_pods: Api<Pod> = Api::namespaced(client.clone(), "kube-system");

    // Check for AAD Pod Identity components (legacy)
    let aad_pods = kube_system_pods
        .list(&ListParams::default().labels("app=aad-pod-identity"))
        .await
        .map(|list| list.items)
        .unwrap_or_default();

    if !aad_pods.is_empty() {
        // Check if aad-pod-identity pods are healthy
        let unhealthy: Vec<_> = aad_pods
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
                    DebugCategory::Security,
                    "DaemonSet",
                    "aad-pod-identity",
                    "AAD Pod Identity Unhealthy",
                    format!("{} AAD Pod Identity pods are not running", unhealthy.len()),
                )
                .with_namespace("kube-system")
                .with_remediation(
                    "Check aad-pod-identity pod logs. Consider migrating to Workload Identity.",
                ),
            );
        }

        // Recommend migration to Workload Identity
        issues.push(
            DebugIssue::new(
                Severity::Info,
                DebugCategory::Security,
                "Cluster",
                "identity-system",
                "Legacy AAD Pod Identity Detected",
                "Cluster uses AAD Pod Identity which is deprecated. Consider migrating to Workload Identity.",
            )
            .with_remediation(
                "Plan migration to Azure Workload Identity for improved security and reliability",
            ),
        );
    }

    // Check for Workload Identity webhook
    let wi_webhook = kube_system_pods
        .list(&ListParams::default().labels("azure-workload-identity.io/system=true"))
        .await
        .map(|list| list.items)
        .unwrap_or_default();

    if !wi_webhook.is_empty() {
        let unhealthy: Vec<_> = wi_webhook
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
                    DebugCategory::Security,
                    "Deployment",
                    "azure-wi-webhook",
                    "Workload Identity Webhook Unhealthy",
                    format!("{} Workload Identity webhook pods are not running", unhealthy.len()),
                )
                .with_namespace("kube-system")
                .with_remediation(
                    "Check azure-wi-webhook pod logs. Workload identity token injection will fail.",
                ),
            );
        }
    }

    // Check ServiceAccounts for Workload Identity annotations
    let service_accounts: Api<ServiceAccount> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    let sa_list = service_accounts
        .list(&ListParams::default())
        .await
        .map(|list| list.items)
        .unwrap_or_default();

    for sa in sa_list {
        let sa_name = sa.metadata.name.clone().unwrap_or_default();
        let sa_ns = sa.metadata.namespace.clone().unwrap_or_default();
        let annotations = sa.metadata.annotations.clone().unwrap_or_default();

        // Check for Azure Workload Identity annotation
        let client_id = annotations.get("azure.workload.identity/client-id");
        let tenant_id = annotations.get("azure.workload.identity/tenant-id");

        // If client-id is set but tenant-id is not, warn
        if client_id.is_some() && tenant_id.is_none() {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Security,
                    "ServiceAccount",
                    &sa_name,
                    "Incomplete Workload Identity Config",
                    "ServiceAccount has client-id but missing tenant-id annotation",
                )
                .with_namespace(&sa_ns)
                .with_remediation(
                    "Add azure.workload.identity/tenant-id annotation to complete Workload Identity setup",
                ),
            );
        }
    }

    Ok(issues)
}

/// Check Azure CNI health and IP allocation
pub async fn check_azure_cni(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let nodes: Api<Node> = Api::all(client.clone());
    let node_list = nodes
        .list(&ListParams::default())
        .await
        .map_err(|e| KcError::Config(e.to_string()))?;

    for node in node_list {
        let node_name = node.metadata.name.clone().unwrap_or_default();

        // Check for Azure-specific network conditions
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

            // Check pod capacity for Azure CNI (max pods based on node size)
            if let Some(allocatable) = &status.allocatable {
                if let Some(pods) = allocatable.get("pods") {
                    let max_pods: i32 = pods.0.parse().unwrap_or(0);
                    // Azure CNI default is 30 pods per node for most node sizes
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

    // Check for Azure NPM (Network Policy Manager)
    let pods: Api<Pod> = Api::namespaced(client.clone(), "kube-system");
    let npm_pods = pods
        .list(&ListParams::default().labels("k8s-app=azure-npm"))
        .await
        .map(|list| list.items)
        .unwrap_or_default();

    if !npm_pods.is_empty() {
        let unhealthy: Vec<_> = npm_pods
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

    Ok(issues)
}

/// Check AKS-specific system components
pub async fn check_aks_components(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let pods: Api<Pod> = Api::namespaced(client.clone(), "kube-system");

    // Check coredns-autoscaler
    let autoscaler_pods = pods
        .list(&ListParams::default().labels("k8s-app=coredns-autoscaler"))
        .await
        .map(|list| list.items)
        .unwrap_or_default();

    if !autoscaler_pods.is_empty() {
        let unhealthy: Vec<_> = autoscaler_pods
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

    // Check Azure Policy pods
    let policy_pods = pods
        .list(&ListParams::default().labels("app=azure-policy"))
        .await
        .map(|list| list.items)
        .unwrap_or_default();

    if !policy_pods.is_empty() {
        let unhealthy: Vec<_> = policy_pods
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

    // Check metrics-server (AKS managed)
    let metrics_pods = pods
        .list(&ListParams::default().labels("k8s-app=metrics-server"))
        .await
        .map(|list| list.items)
        .unwrap_or_default();

    if metrics_pods.is_empty() {
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
        let unhealthy: Vec<_> = metrics_pods
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
                .with_remediation("Check metrics-server pod logs. HPA and kubectl top may fail."),
            );
        }
    }

    Ok(issues)
}

/// Check Virtual Nodes (ACI) integration
pub async fn check_virtual_nodes(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Check for virtual-node-aci-linux pods
    let kube_system_pods: Api<Pod> = Api::namespaced(client.clone(), "kube-system");
    let virtual_kubelet_pods = kube_system_pods
        .list(&ListParams::default().labels("app=virtual-kubelet-linux-aci"))
        .await
        .map(|list| list.items)
        .unwrap_or_default();

    if virtual_kubelet_pods.is_empty() {
        // Virtual nodes not enabled, skip checks
        return Ok(issues);
    }

    // Check virtual kubelet health
    let unhealthy: Vec<_> = virtual_kubelet_pods
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
                DebugCategory::Node,
                "Pod",
                "virtual-kubelet-aci",
                "Virtual Kubelet Unhealthy",
                format!("{} Virtual Kubelet pods are not running. ACI scheduling will fail.", unhealthy.len()),
            )
            .with_namespace("kube-system")
            .with_remediation("Check virtual-kubelet pod logs and Azure Container Instances quota"),
        );
    }

    // Check virtual node status
    let nodes: Api<Node> = Api::all(client.clone());
    let node_list = nodes
        .list(&ListParams::default())
        .await
        .map(|list| list.items)
        .unwrap_or_default();

    for node in node_list {
        let node_name = node.metadata.name.clone().unwrap_or_default();

        // Check if it's a virtual node
        if let Some(labels) = &node.metadata.labels {
            if labels.get("type").map(|v| v == "virtual-kubelet").unwrap_or(false)
                || labels.get("kubernetes.io/role").map(|v| v == "agent").unwrap_or(false)
            {
                // Check virtual node conditions
                if let Some(status) = &node.status {
                    if let Some(conditions) = &status.conditions {
                        for condition in conditions {
                            if condition.type_ == "Ready" && condition.status != "True" {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Node,
                                        "Node",
                                        &node_name,
                                        "Virtual Node Not Ready",
                                        format!("Virtual node is not ready: {:?}", condition.message),
                                    )
                                    .with_remediation(
                                        "Check ACI connectivity and quota in your Azure subscription",
                                    ),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Check pods scheduled on virtual nodes
    let pods: Api<Pod> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    let pod_list = pods
        .list(&ListParams::default())
        .await
        .map(|list| list.items)
        .unwrap_or_default();

    for pod in pod_list {
        let pod_name = pod.metadata.name.clone().unwrap_or_default();
        let pod_ns = pod.metadata.namespace.clone().unwrap_or_default();

        // Check if pod is scheduled on virtual node
        if let Some(spec) = &pod.spec {
            if let Some(node_name) = &spec.node_name {
                if node_name.contains("virtual-node") || node_name.contains("aci-connector") {
                    // Check for ACI-related issues
                    if let Some(status) = &pod.status {
                        if let Some(phase) = &status.phase {
                            if phase == "Pending" || phase == "Failed" {
                                let message = status.message.clone().unwrap_or_default();
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Warning,
                                        DebugCategory::Pod,
                                        "Pod",
                                        &pod_name,
                                        "ACI Pod Issue",
                                        format!("Pod on virtual node has status {}: {}", phase, message),
                                    )
                                    .with_namespace(&pod_ns)
                                    .with_remediation(
                                        "Check ACI quota, resource limits, and supported features",
                                    ),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(issues)
}

/// Check if cluster is running on AKS
pub fn is_aks(nodes: &[Node]) -> bool {
    nodes.iter().any(|node| {
        node.metadata
            .labels
            .as_ref()
            .map(|labels| {
                labels.contains_key("kubernetes.azure.com/agentpool")
                    || labels.contains_key("kubernetes.azure.com/cluster")
            })
            .unwrap_or(false)
    })
}

/// Check if virtual nodes are enabled
pub fn has_virtual_nodes(nodes: &[Node]) -> bool {
    nodes.iter().any(|node| {
        node.metadata
            .labels
            .as_ref()
            .map(|labels| {
                labels.get("type").map(|v| v == "virtual-kubelet").unwrap_or(false)
            })
            .unwrap_or(false)
    })
}
