//! Node diagnostics
//!
//! Checks for node issues including:
//! - Node conditions (Ready, MemoryPressure, DiskPressure, PIDPressure)
//! - Resource capacity and allocation
//! - Taints and their effects
//! - System pods health

use super::types::*;
use crate::error::KcError;
use k8s_openapi::api::core::v1::{Node, Pod};
use kube::{Api, Client, api::ListParams};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;

/// Debug all nodes
pub async fn debug_nodes(client: &Client) -> Result<DebugReport, KcError> {
    let api: Api<Node> = Api::all(client.clone());
    let nodes = api.list(&ListParams::default()).await?;

    let mut issues = Vec::new();
    let mut total_checks = 0;

    for node in &nodes.items {
        total_checks += 1;
        let node_issues = analyze_node(client, node).await?;
        issues.extend(node_issues);
    }

    Ok(DebugReport::with_check_count("node", issues, total_checks))
}

/// Debug a specific node
pub async fn debug_node(
    client: &Client,
    name: &str,
) -> Result<DebugReport, KcError> {
    let api: Api<Node> = Api::all(client.clone());
    let node = api.get(name).await?;

    let issues = analyze_node(client, &node).await?;
    Ok(DebugReport::new("node", issues))
}

/// Analyze a single node
async fn analyze_node(client: &Client, node: &Node) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let name = node.metadata.name.as_deref().unwrap_or("unknown");

    // Check node conditions
    if let Some(status) = &node.status {
        if let Some(conditions) = &status.conditions {
            for condition in conditions {
                let issue = match condition.type_.as_str() {
                    "Ready" => {
                        if condition.status != "True" {
                            Some(DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Node,
                                "Node",
                                name,
                                "Node not ready",
                                format!(
                                    "Node {} is not ready. Reason: {}. Message: {}",
                                    name,
                                    condition.reason.as_deref().unwrap_or("Unknown"),
                                    condition.message.as_deref().unwrap_or("")
                                ),
                            )
                            .with_remediation("Check kubelet status and logs"))
                        } else {
                            None
                        }
                    }
                    "MemoryPressure" => {
                        if condition.status == "True" {
                            Some(DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Node,
                                "Node",
                                name,
                                "Memory pressure detected",
                                format!("Node {} is experiencing memory pressure. Pods may be evicted.", name),
                            )
                            .with_remediation("Free up memory, add more memory, or reduce pod memory requests"))
                        } else {
                            None
                        }
                    }
                    "DiskPressure" => {
                        if condition.status == "True" {
                            Some(DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Node,
                                "Node",
                                name,
                                "Disk pressure detected",
                                format!("Node {} is experiencing disk pressure. Pods may be evicted.", name),
                            )
                            .with_remediation("Clean up disk space, expand volume, or reduce image/log sizes"))
                        } else {
                            None
                        }
                    }
                    "PIDPressure" => {
                        if condition.status == "True" {
                            Some(DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Node,
                                "Node",
                                name,
                                "PID pressure detected",
                                format!("Node {} is running low on process IDs.", name),
                            )
                            .with_remediation("Increase pid.max or reduce number of pods/processes"))
                        } else {
                            None
                        }
                    }
                    "NetworkUnavailable" => {
                        if condition.status == "True" {
                            Some(DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Node,
                                "Node",
                                name,
                                "Network unavailable",
                                format!("Node {} network is not configured correctly.", name),
                            )
                            .with_remediation("Check CNI plugin and network configuration"))
                        } else {
                            None
                        }
                    }
                    _ => None,
                };

                if let Some(issue) = issue {
                    issues.push(issue);
                }
            }
        }

        // Check resource utilization
        let capacity_issues = check_resource_utilization(client, node, name).await?;
        issues.extend(capacity_issues);

        // Check node info
        if let Some(node_info) = &status.node_info {
            // Check kubelet version
            let version = &node_info.kubelet_version;
            if version.contains("alpha") || version.contains("beta") {
                issues.push(
                    DebugIssue::new(
                        Severity::Info,
                        DebugCategory::Node,
                        "Node",
                        name,
                        "Pre-release Kubernetes version",
                        format!("Node {} is running {} (pre-release)", name, version),
                    )
                );
            }

            // Check container runtime
            let runtime = &node_info.container_runtime_version;
            if runtime.contains("docker://1.") || runtime.contains("docker://17.") || runtime.contains("docker://18.") {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Node,
                        "Node",
                        name,
                        "Outdated container runtime",
                        format!("Node {} has outdated runtime: {}", name, runtime),
                    )
                    .with_remediation("Consider upgrading to containerd or a newer Docker version")
                );
            }
        }
    }

    // Check taints
    if let Some(spec) = &node.spec {
        if let Some(taints) = &spec.taints {
            let mut has_no_schedule = false;
            let mut has_no_execute = false;

            for taint in taints {
                match taint.effect.as_str() {
                    "NoSchedule" => has_no_schedule = true,
                    "NoExecute" => has_no_execute = true,
                    _ => {}
                }
            }

            if has_no_execute {
                issues.push(
                    DebugIssue::new(
                        Severity::Info,
                        DebugCategory::Node,
                        "Node",
                        name,
                        "Node has NoExecute taint",
                        format!(
                            "Node {} has NoExecute taint. Existing pods without matching tolerations will be evicted.",
                            name
                        ),
                    )
                    .with_details(serde_json::json!({
                        "taints": taints.iter().map(|t| {
                            serde_json::json!({
                                "key": t.key,
                                "value": t.value,
                                "effect": t.effect,
                            })
                        }).collect::<Vec<_>>()
                    }))
                );
            }

            if has_no_schedule && !has_no_execute {
                issues.push(
                    DebugIssue::new(
                        Severity::Info,
                        DebugCategory::Node,
                        "Node",
                        name,
                        "Node has NoSchedule taint",
                        format!("Node {} has NoSchedule taint. New pods without matching tolerations cannot be scheduled.", name),
                    )
                );
            }
        }

        // Check if node is unschedulable (cordoned)
        if spec.unschedulable == Some(true) {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Node,
                    "Node",
                    name,
                    "Node is cordoned",
                    format!("Node {} is cordoned (unschedulable). No new pods will be scheduled.", name),
                )
                .with_remediation("Uncordon with 'kubectl uncordon' when ready")
            );
        }
    }

    // Check system pods on this node
    let system_pod_issues = check_system_pods(client, name).await?;
    issues.extend(system_pod_issues);

    Ok(issues)
}

/// Check resource utilization on node
async fn check_resource_utilization(
    client: &Client,
    node: &Node,
    node_name: &str,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let status = match &node.status {
        Some(s) => s,
        None => return Ok(issues),
    };

    let allocatable = match &status.allocatable {
        Some(a) => a,
        None => return Ok(issues),
    };

    // Get pods running on this node
    let pod_api: Api<Pod> = Api::all(client.clone());
    let lp = ListParams::default().fields(&format!("spec.nodeName={}", node_name));
    let pods = pod_api.list(&lp).await?;

    // Calculate requested resources
    let mut requested_cpu: i64 = 0;
    let mut requested_memory: i64 = 0;

    for pod in &pods.items {
        if let Some(spec) = &pod.spec {
            for container in &spec.containers {
                if let Some(resources) = &container.resources {
                    if let Some(requests) = &resources.requests {
                        if let Some(cpu) = requests.get("cpu") {
                            requested_cpu += parse_cpu_quantity(cpu);
                        }
                        if let Some(mem) = requests.get("memory") {
                            requested_memory += parse_memory_quantity(mem);
                        }
                    }
                }
            }
        }
    }

    // Get allocatable resources
    let allocatable_cpu = allocatable.get("cpu").map(|q| parse_cpu_quantity(q)).unwrap_or(0);
    let allocatable_memory = allocatable.get("memory").map(|q| parse_memory_quantity(q)).unwrap_or(0);

    // Check CPU utilization
    if allocatable_cpu > 0 {
        let cpu_percent = (requested_cpu as f64 / allocatable_cpu as f64) * 100.0;

        if cpu_percent > 90.0 {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Node,
                    "Node",
                    node_name,
                    format!("High CPU allocation ({:.1}%)", cpu_percent),
                    format!(
                        "Node {} has {:.1}% of CPU allocated. May not be able to schedule more pods.",
                        node_name, cpu_percent
                    ),
                )
                .with_details(serde_json::json!({
                    "requested_cpu_millicores": requested_cpu,
                    "allocatable_cpu_millicores": allocatable_cpu,
                    "utilization_percent": cpu_percent,
                }))
            );
        } else if cpu_percent > 100.0 {
            issues.push(
                DebugIssue::new(
                    Severity::Critical,
                    DebugCategory::Node,
                    "Node",
                    node_name,
                    format!("CPU overcommitted ({:.1}%)", cpu_percent),
                    format!("Node {} is overcommitted on CPU by {:.1}%", node_name, cpu_percent - 100.0),
                )
            );
        }
    }

    // Check memory utilization
    if allocatable_memory > 0 {
        let mem_percent = (requested_memory as f64 / allocatable_memory as f64) * 100.0;

        if mem_percent > 90.0 {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Node,
                    "Node",
                    node_name,
                    format!("High memory allocation ({:.1}%)", mem_percent),
                    format!(
                        "Node {} has {:.1}% of memory allocated. May experience OOM issues.",
                        node_name, mem_percent
                    ),
                )
                .with_details(serde_json::json!({
                    "requested_memory_bytes": requested_memory,
                    "allocatable_memory_bytes": allocatable_memory,
                    "utilization_percent": mem_percent,
                }))
            );
        } else if mem_percent > 100.0 {
            issues.push(
                DebugIssue::new(
                    Severity::Critical,
                    DebugCategory::Node,
                    "Node",
                    node_name,
                    format!("Memory overcommitted ({:.1}%)", mem_percent),
                    format!("Node {} is overcommitted on memory by {:.1}%", node_name, mem_percent - 100.0),
                )
            );
        }
    }

    Ok(issues)
}

/// Check system pods on a node
async fn check_system_pods(client: &Client, node_name: &str) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let pod_api: Api<Pod> = Api::namespaced(client.clone(), "kube-system");
    let lp = ListParams::default().fields(&format!("spec.nodeName={}", node_name));
    let pods = pod_api.list(&lp).await?;

    for pod in &pods.items {
        let pod_name = pod.metadata.name.as_deref().unwrap_or("unknown");

        if let Some(status) = &pod.status {
            let phase = status.phase.as_deref().unwrap_or("Unknown");

            if phase != "Running" && phase != "Succeeded" {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Node,
                        "Pod",
                        pod_name,
                        format!("System pod not running ({})", phase),
                        format!("System pod {} on node {} is in {} state", pod_name, node_name, phase),
                    )
                    .with_namespace("kube-system")
                );
            }

            // Check for restarts
            if let Some(container_statuses) = &status.container_statuses {
                for cs in container_statuses {
                    if cs.restart_count > 5 {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Node,
                                "Pod",
                                pod_name,
                                format!("System pod high restarts ({})", cs.restart_count),
                                format!(
                                    "System pod {} on node {} has restarted {} times",
                                    pod_name, node_name, cs.restart_count
                                ),
                            )
                            .with_namespace("kube-system")
                        );
                    }
                }
            }
        }
    }

    Ok(issues)
}

/// Parse CPU quantity to millicores
fn parse_cpu_quantity(quantity: &Quantity) -> i64 {
    let s = quantity.0.as_str();

    if s.ends_with('m') {
        // Already in millicores
        s.trim_end_matches('m').parse().unwrap_or(0)
    } else if s.ends_with('n') {
        // Nanocores
        s.trim_end_matches('n').parse::<i64>().unwrap_or(0) / 1_000_000
    } else {
        // Cores - convert to millicores
        s.parse::<f64>().unwrap_or(0.0) as i64 * 1000
    }
}

/// Parse memory quantity to bytes
fn parse_memory_quantity(quantity: &Quantity) -> i64 {
    let s = quantity.0.as_str();

    if s.ends_with("Ki") {
        s.trim_end_matches("Ki").parse::<i64>().unwrap_or(0) * 1024
    } else if s.ends_with("Mi") {
        s.trim_end_matches("Mi").parse::<i64>().unwrap_or(0) * 1024 * 1024
    } else if s.ends_with("Gi") {
        s.trim_end_matches("Gi").parse::<i64>().unwrap_or(0) * 1024 * 1024 * 1024
    } else if s.ends_with("Ti") {
        s.trim_end_matches("Ti").parse::<i64>().unwrap_or(0) * 1024 * 1024 * 1024 * 1024
    } else if s.ends_with('K') || s.ends_with('k') {
        s.trim_end_matches(['K', 'k']).parse::<i64>().unwrap_or(0) * 1000
    } else if s.ends_with('M') {
        s.trim_end_matches('M').parse::<i64>().unwrap_or(0) * 1000 * 1000
    } else if s.ends_with('G') {
        s.trim_end_matches('G').parse::<i64>().unwrap_or(0) * 1000 * 1000 * 1000
    } else if s.ends_with('T') {
        s.trim_end_matches('T').parse::<i64>().unwrap_or(0) * 1000 * 1000 * 1000 * 1000
    } else {
        s.parse().unwrap_or(0)
    }
}
