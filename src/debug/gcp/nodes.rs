//! GKE node and node pool checks
//!
//! Checks for Autopilot constraints, GKE components, and node pool issues.

use crate::debug::types::{DebugCategory, DebugIssue, Severity};
use crate::error::KcError;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment};
use k8s_openapi::api::core::v1::{Node, Pod};
use kube::{api::ListParams, Api, Client};

pub async fn check_autopilot_constraints(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Check if cluster is Autopilot by looking at node labels
    let nodes: Api<Node> = Api::all(client.clone());
    let node_list = nodes
        .list(&ListParams::default())
        .await
        .map_err(|e| KcError::Config(e.to_string()))?;

    let is_autopilot = node_list.iter().any(|node| {
        node.metadata
            .labels
            .as_ref()
            .map(|l: &std::collections::BTreeMap<String, String>| l.contains_key("cloud.google.com/gke-autopilot"))
            .unwrap_or(false)
    });

    if !is_autopilot {
        return Ok(issues);
    }

    // Autopilot constraints check
    let pods: Api<Pod> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    let pod_list = pods
        .list(&ListParams::default())
        .await
        .map_err(|e| KcError::Config(e.to_string()))?;

    for pod in pod_list {
        let pod_name = pod.metadata.name.clone().unwrap_or_default();
        let pod_ns = pod.metadata.namespace.clone().unwrap_or_default();

        if let Some(spec) = &pod.spec {
            // Check for privileged containers (not allowed in Autopilot)
            for container in &spec.containers {
                if let Some(security_context) = &container.security_context {
                    if security_context.privileged == Some(true) {
                        issues.push(
                            DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Security,
                                "Pod",
                                &pod_name,
                                "Privileged Container in Autopilot",
                                format!("Container '{}' is privileged, which is not allowed in GKE Autopilot", container.name),
                            )
                            .with_namespace(&pod_ns)
                            .with_remediation(
                                "Remove privileged: true from the container's securityContext",
                            ),
                        );
                    }
                }
            }

            // Check for hostNetwork (not allowed in Autopilot)
            if spec.host_network == Some(true) {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Network,
                        "Pod",
                        &pod_name,
                        "HostNetwork in Autopilot",
                        "Pod uses hostNetwork, which is not allowed in GKE Autopilot",
                    )
                    .with_namespace(&pod_ns)
                    .with_remediation(
                        "Remove hostNetwork: true from pod spec",
                    ),
                );
            }

            // Check for hostPID (not allowed in Autopilot)
            if spec.host_pid == Some(true) {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Security,
                        "Pod",
                        &pod_name,
                        "HostPID in Autopilot",
                        "Pod uses hostPID, which is not allowed in GKE Autopilot",
                    )
                    .with_namespace(&pod_ns)
                    .with_remediation(
                        "Remove hostPID: true from pod spec",
                    ),
                );
            }

            // Check for missing resource requests (required in Autopilot)
            for container in &spec.containers {
                let has_resources = container.resources.as_ref()
                    .map(|r| r.requests.is_some())
                    .unwrap_or(false);

                if !has_resources {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Resources,
                            "Pod",
                            &pod_name,
                            "Missing Resource Requests in Autopilot",
                            format!("Container '{}' has no resource requests. Autopilot will use defaults which may not be optimal.", container.name),
                        )
                        .with_namespace(&pod_ns)
                        .with_remediation(
                            "Specify resource requests for optimal Autopilot node selection",
                        ),
                    );
                }
            }
        }
    }

    Ok(issues)
}

/// Check GKE-specific system components
pub async fn check_gke_components(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let pods: Api<Pod> = Api::namespaced(client.clone(), "kube-system");

    // Check gke-metadata-server
    let metadata_server_pods = pods
        .list(&ListParams::default().labels("k8s-app=gke-metadata-server"))
        .await
        .map(|list| list.items)
        .unwrap_or_default();

    let metadata_server_healthy = metadata_server_pods.iter().all(|pod| {
        pod.status
            .as_ref()
            .and_then(|s| s.phase.as_ref())
            .map(|p| p == "Running")
            .unwrap_or(false)
    });

    if !metadata_server_pods.is_empty() && !metadata_server_healthy {
        issues.push(
            DebugIssue::new(
                Severity::Critical,
                DebugCategory::Cluster,
                "DaemonSet",
                "gke-metadata-server",
                "GKE Metadata Server Unhealthy",
                "gke-metadata-server pods are not all running. This affects Workload Identity.",
            )
            .with_namespace("kube-system")
            .with_remediation("Check gke-metadata-server pod logs and events"),
        );
    }

    // Check fluentbit-gke (logging agent)
    let fluentbit_pods = pods
        .list(&ListParams::default().labels("k8s-app=fluentbit-gke"))
        .await
        .map(|list| list.items)
        .unwrap_or_default();

    let fluentbit_unhealthy: Vec<_> = fluentbit_pods
        .iter()
        .filter(|pod| {
            pod.status
                .as_ref()
                .and_then(|s| s.phase.as_ref())
                .map(|p| p != "Running")
                .unwrap_or(true)
        })
        .collect();

    if !fluentbit_unhealthy.is_empty() {
        issues.push(
            DebugIssue::new(
                Severity::Warning,
                DebugCategory::Cluster,
                "DaemonSet",
                "fluentbit-gke",
                "GKE Logging Agent Issues",
                format!("{} fluentbit-gke pods are not running properly", fluentbit_unhealthy.len()),
            )
            .with_namespace("kube-system")
            .with_remediation("Check fluentbit-gke pod logs for errors. Logs may not be forwarded to Cloud Logging."),
        );
    }

    // Check gke-metrics-agent
    let metrics_agent_pods = pods
        .list(&ListParams::default().labels("k8s-app=gke-metrics-agent"))
        .await
        .map(|list| list.items)
        .unwrap_or_default();

    let metrics_agent_unhealthy: Vec<_> = metrics_agent_pods
        .iter()
        .filter(|pod| {
            pod.status
                .as_ref()
                .and_then(|s| s.phase.as_ref())
                .map(|p| p != "Running")
                .unwrap_or(true)
        })
        .collect();

    if !metrics_agent_unhealthy.is_empty() {
        issues.push(
            DebugIssue::new(
                Severity::Warning,
                DebugCategory::Cluster,
                "DaemonSet",
                "gke-metrics-agent",
                "GKE Metrics Agent Issues",
                format!("{} gke-metrics-agent pods are not running properly", metrics_agent_unhealthy.len()),
            )
            .with_namespace("kube-system")
            .with_remediation("Check gke-metrics-agent pod logs. Metrics may not be forwarded to Cloud Monitoring."),
        );
    }

    Ok(issues)
}

/// Check VPC-native networking issues
pub async fn check_gke_node_pools(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let nodes: Api<Node> = Api::all(client.clone());
    if let Ok(node_list) = nodes.list(&ListParams::default()).await {
        for node in node_list {
            let node_name = node.metadata.name.clone().unwrap_or_default();
            let labels = node.metadata.labels.clone().unwrap_or_default();

            // Check node conditions
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
                                    .with_remediation("Check VPC CNI configuration and node networking"),
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }

            // Check for preemptible/spot node termination warnings
            if labels.get("cloud.google.com/gke-preemptible") == Some(&"true".to_string())
                || labels.get("cloud.google.com/gke-spot") == Some(&"true".to_string()) {
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
                                        "Preemptible/Spot Node Issue",
                                        "Preemptible or Spot VM node may have been preempted",
                                    )
                                    .with_remediation("This is expected behavior for preemptible/spot nodes"),
                                );
                            }
                        }
                    }
                }
            }

            // Check for GPU nodes
            if labels.contains_key("cloud.google.com/gke-accelerator") {
                // Check for NVIDIA driver daemonset
                let daemonsets: Api<DaemonSet> = Api::namespaced(client.clone(), "kube-system");
                if daemonsets.get("nvidia-driver-installer").await.is_err()
                    && daemonsets.get("nvidia-gpu-device-plugin").await.is_err() {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Cluster,
                            "Node",
                            &node_name,
                            "GPU Driver Not Installed",
                            "GPU node detected but NVIDIA driver installer not found",
                        )
                        .with_remediation("Ensure GPU drivers are installed. GKE usually auto-installs them."),
                    );
                }
            }
        }
    }

    // Check Cluster Autoscaler
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), "kube-system");
    if let Ok(ca) = deployments.get("cluster-autoscaler-gke").await {
        if let Some(status) = &ca.status {
            let ready = status.ready_replicas.unwrap_or(0);
            if ready == 0 {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Cluster,
                        "Deployment",
                        "cluster-autoscaler-gke",
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
