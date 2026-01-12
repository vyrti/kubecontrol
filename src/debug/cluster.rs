//! Cluster-wide health checks
//!
//! Checks for cluster issues including:
//! - Control plane components
//! - API server health
//! - Certificate expiration
//! - Version compatibility

use super::types::*;
use crate::error::KcError;
use k8s_openapi::api::core::v1::{Pod, Node, ComponentStatus};
use kube::{Api, Client, api::ListParams};

/// Debug cluster health
pub async fn debug_cluster(client: &Client) -> Result<DebugReport, KcError> {
    let mut issues = Vec::new();
    let mut total_checks = 0;

    // Check control plane pods
    total_checks += 1;
    let cp_issues = check_control_plane(client).await?;
    issues.extend(cp_issues);

    // Check component status (deprecated but still available in some clusters)
    total_checks += 1;
    let cs_issues = check_component_status(client).await?;
    issues.extend(cs_issues);

    // Check node health summary
    total_checks += 1;
    let node_issues = check_node_health_summary(client).await?;
    issues.extend(node_issues);

    // Check version skew
    total_checks += 1;
    let version_issues = check_version_skew(client).await?;
    issues.extend(version_issues);

    // Check cluster capacity
    total_checks += 1;
    let capacity_issues = check_cluster_capacity(client).await?;
    issues.extend(capacity_issues);

    Ok(DebugReport::with_check_count("cluster", issues, total_checks))
}

/// Check control plane components
async fn check_control_plane(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let api: Api<Pod> = Api::namespaced(client.clone(), "kube-system");

    // Check critical components
    let components = [
        ("kube-apiserver", "API Server"),
        ("kube-controller-manager", "Controller Manager"),
        ("kube-scheduler", "Scheduler"),
        ("etcd", "etcd"),
    ];

    for (prefix, display_name) in &components {
        let lp = ListParams::default().labels(&format!("component={}", prefix));
        let pods = api.list(&lp).await?;

        if pods.items.is_empty() {
            // Try tier=control-plane label
            let lp2 = ListParams::default().labels(&format!("tier=control-plane,component={}", prefix));
            let pods2 = api.list(&lp2).await?;

            if pods2.items.is_empty() {
                // This might be a managed cluster where control plane is not visible
                continue;
            }
        }

        let running_pods: Vec<_> = pods.items.iter()
            .filter(|p| {
                p.status.as_ref()
                    .and_then(|s| s.phase.as_deref())
                    == Some("Running")
            })
            .collect();

        let not_ready: Vec<_> = pods.items.iter()
            .filter(|p| {
                p.status.as_ref()
                    .and_then(|s| s.conditions.as_ref())
                    .map(|c| !c.iter().any(|cond| cond.type_ == "Ready" && cond.status == "True"))
                    .unwrap_or(true)
            })
            .collect();

        if running_pods.is_empty() {
            issues.push(
                DebugIssue::new(
                    Severity::Critical,
                    DebugCategory::Cluster,
                    "ControlPlane",
                    *prefix,
                    format!("{} not running", display_name),
                    format!("No {} pods are in Running state. Cluster may be non-functional.", display_name),
                )
                .with_namespace("kube-system")
            );
        } else if !not_ready.is_empty() {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Cluster,
                    "ControlPlane",
                    *prefix,
                    format!("{} has not-ready pods", display_name),
                    format!(
                        "{} has {} pod(s) not ready out of {}",
                        display_name, not_ready.len(), pods.items.len()
                    ),
                )
                .with_namespace("kube-system")
            );
        }

        // Check for restarts
        for pod in &pods.items {
            let name = pod.metadata.name.as_deref().unwrap_or("unknown");
            if let Some(status) = &pod.status {
                if let Some(container_statuses) = &status.container_statuses {
                    for cs in container_statuses {
                        if cs.restart_count > 3 {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Warning,
                                    DebugCategory::Cluster,
                                    "ControlPlane",
                                    name,
                                    format!("{} pod restarted {} times", display_name, cs.restart_count),
                                    format!("Control plane component {} has high restart count", display_name),
                                )
                                .with_namespace("kube-system")
                                .with_remediation("Check control plane logs for errors")
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(issues)
}

/// Check component status (legacy API)
async fn check_component_status(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let api: Api<ComponentStatus> = Api::all(client.clone());

    match api.list(&ListParams::default()).await {
        Ok(components) => {
            for cs in &components.items {
                let name = cs.metadata.name.as_deref().unwrap_or("unknown");

                if let Some(conditions) = &cs.conditions {
                    for condition in conditions {
                        if condition.type_ == "Healthy" && condition.status != "True" {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Critical,
                                    DebugCategory::Cluster,
                                    "Component",
                                    name,
                                    format!("Component {} is unhealthy", name),
                                    condition.message.clone().unwrap_or_else(|| "Unknown error".to_string()),
                                )
                                .with_remediation("Check component logs and status")
                            );
                        }
                    }
                }
            }
        }
        Err(_) => {
            // ComponentStatus API may be disabled in newer clusters
        }
    }

    Ok(issues)
}

/// Check node health summary
async fn check_node_health_summary(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let api: Api<Node> = Api::all(client.clone());
    let nodes = api.list(&ListParams::default()).await?;

    let total_nodes = nodes.items.len();
    let mut ready_nodes = 0;
    let mut not_ready_nodes = 0;
    let mut pressure_nodes = 0;

    for node in &nodes.items {
        if let Some(status) = &node.status {
            if let Some(conditions) = &status.conditions {
                let is_ready = conditions.iter()
                    .any(|c| c.type_ == "Ready" && c.status == "True");

                if is_ready {
                    ready_nodes += 1;
                } else {
                    not_ready_nodes += 1;
                }

                let has_pressure = conditions.iter()
                    .any(|c| {
                        (c.type_ == "MemoryPressure" || c.type_ == "DiskPressure" || c.type_ == "PIDPressure")
                            && c.status == "True"
                    });

                if has_pressure {
                    pressure_nodes += 1;
                }
            }
        }
    }

    if not_ready_nodes > 0 {
        let severity = if not_ready_nodes == total_nodes {
            Severity::Critical
        } else if not_ready_nodes > total_nodes / 2 {
            Severity::Critical
        } else {
            Severity::Warning
        };

        issues.push(
            DebugIssue::new(
                severity,
                DebugCategory::Cluster,
                "Cluster",
                "nodes",
                format!("{}/{} nodes not ready", not_ready_nodes, total_nodes),
                format!(
                    "Cluster has {} nodes not ready out of {} total",
                    not_ready_nodes, total_nodes
                ),
            )
            .with_remediation("Investigate NotReady nodes with 'kubectl describe node'")
        );
    }

    if pressure_nodes > 0 {
        issues.push(
            DebugIssue::new(
                Severity::Warning,
                DebugCategory::Cluster,
                "Cluster",
                "nodes",
                format!("{} nodes under pressure", pressure_nodes),
                format!(
                    "{} nodes are experiencing memory, disk, or PID pressure",
                    pressure_nodes
                ),
            )
            .with_remediation("Check node resources and consider scaling")
        );
    }

    if total_nodes == 1 {
        issues.push(
            DebugIssue::new(
                Severity::Info,
                DebugCategory::Cluster,
                "Cluster",
                "nodes",
                "Single node cluster",
                "Cluster has only 1 node. No fault tolerance for node failures.",
            )
            .with_remediation("Add more nodes for high availability")
        );
    }

    Ok(issues)
}

/// Check version skew between nodes
async fn check_version_skew(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let api: Api<Node> = Api::all(client.clone());
    let nodes = api.list(&ListParams::default()).await?;

    let mut versions: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();

    for node in &nodes.items {
        let name = node.metadata.name.as_deref().unwrap_or("unknown");
        if let Some(status) = &node.status {
            if let Some(info) = &status.node_info {
                let version = info.kubelet_version.clone();
                versions.entry(version).or_default().push(name.to_string());
            }
        }
    }

    if versions.len() > 1 {
        let version_list: Vec<_> = versions.keys().cloned().collect();
        issues.push(
            DebugIssue::new(
                Severity::Warning,
                DebugCategory::Cluster,
                "Cluster",
                "version-skew",
                format!("Multiple kubelet versions detected ({})", versions.len()),
                format!(
                    "Nodes are running different Kubernetes versions: {}",
                    version_list.join(", ")
                ),
            )
            .with_remediation("Upgrade nodes to a consistent version")
            .with_details(serde_json::json!({
                "versions": versions,
            }))
        );
    }

    Ok(issues)
}

/// Check cluster capacity
async fn check_cluster_capacity(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let node_api: Api<Node> = Api::all(client.clone());
    let nodes = node_api.list(&ListParams::default()).await?;

    let pod_api: Api<Pod> = Api::all(client.clone());
    let pods = pod_api.list(&ListParams::default()).await?;

    // Calculate totals
    let mut total_cpu_capacity: i64 = 0;
    let mut total_memory_capacity: i64 = 0;
    let mut total_cpu_allocatable: i64 = 0;
    let mut total_memory_allocatable: i64 = 0;

    for node in &nodes.items {
        if let Some(status) = &node.status {
            if let Some(capacity) = &status.capacity {
                if let Some(cpu) = capacity.get("cpu") {
                    total_cpu_capacity += parse_cpu(&cpu.0);
                }
                if let Some(mem) = capacity.get("memory") {
                    total_memory_capacity += parse_memory(&mem.0);
                }
            }
            if let Some(allocatable) = &status.allocatable {
                if let Some(cpu) = allocatable.get("cpu") {
                    total_cpu_allocatable += parse_cpu(&cpu.0);
                }
                if let Some(mem) = allocatable.get("memory") {
                    total_memory_allocatable += parse_memory(&mem.0);
                }
            }
        }
    }

    // Calculate requested resources
    let mut total_cpu_requested: i64 = 0;
    let mut total_memory_requested: i64 = 0;

    for pod in &pods.items {
        // Skip completed/failed pods
        if pod.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Succeeded")
            || pod.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Failed") {
            continue;
        }

        if let Some(spec) = &pod.spec {
            for container in &spec.containers {
                if let Some(resources) = &container.resources {
                    if let Some(requests) = &resources.requests {
                        if let Some(cpu) = requests.get("cpu") {
                            total_cpu_requested += parse_cpu(&cpu.0);
                        }
                        if let Some(mem) = requests.get("memory") {
                            total_memory_requested += parse_memory(&mem.0);
                        }
                    }
                }
            }
        }
    }

    // Check CPU utilization
    if total_cpu_allocatable > 0 {
        let cpu_percent = (total_cpu_requested as f64 / total_cpu_allocatable as f64) * 100.0;

        if cpu_percent > 90.0 {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Cluster,
                    "Cluster",
                    "capacity",
                    format!("Cluster CPU at {:.1}% capacity", cpu_percent),
                    format!(
                        "Cluster has {:.1}% of allocatable CPU requested. May have scheduling issues.",
                        cpu_percent
                    ),
                )
                .with_remediation("Add more nodes or reduce CPU requests")
            );
        } else if cpu_percent > 100.0 {
            issues.push(
                DebugIssue::new(
                    Severity::Critical,
                    DebugCategory::Cluster,
                    "Cluster",
                    "capacity",
                    format!("Cluster CPU overcommitted ({:.1}%)", cpu_percent),
                    format!("Cluster has more CPU requested than available."),
                )
            );
        }
    }

    // Check memory utilization
    if total_memory_allocatable > 0 {
        let mem_percent = (total_memory_requested as f64 / total_memory_allocatable as f64) * 100.0;

        if mem_percent > 90.0 {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Cluster,
                    "Cluster",
                    "capacity",
                    format!("Cluster memory at {:.1}% capacity", mem_percent),
                    format!(
                        "Cluster has {:.1}% of allocatable memory requested. May experience OOM issues.",
                        mem_percent
                    ),
                )
                .with_remediation("Add more nodes or reduce memory requests")
            );
        } else if mem_percent > 100.0 {
            issues.push(
                DebugIssue::new(
                    Severity::Critical,
                    DebugCategory::Cluster,
                    "Cluster",
                    "capacity",
                    format!("Cluster memory overcommitted ({:.1}%)", mem_percent),
                    format!("Cluster has more memory requested than available."),
                )
            );
        }
    }

    Ok(issues)
}

/// Parse CPU to millicores
fn parse_cpu(s: &str) -> i64 {
    if s.ends_with('m') {
        s.trim_end_matches('m').parse().unwrap_or(0)
    } else if s.ends_with('n') {
        s.trim_end_matches('n').parse::<i64>().unwrap_or(0) / 1_000_000
    } else {
        (s.parse::<f64>().unwrap_or(0.0) * 1000.0) as i64
    }
}

/// Parse memory to bytes
fn parse_memory(s: &str) -> i64 {
    if s.ends_with("Ki") {
        s.trim_end_matches("Ki").parse::<i64>().unwrap_or(0) * 1024
    } else if s.ends_with("Mi") {
        s.trim_end_matches("Mi").parse::<i64>().unwrap_or(0) * 1024 * 1024
    } else if s.ends_with("Gi") {
        s.trim_end_matches("Gi").parse::<i64>().unwrap_or(0) * 1024 * 1024 * 1024
    } else if s.ends_with("Ti") {
        s.trim_end_matches("Ti").parse::<i64>().unwrap_or(0) * 1024 * 1024 * 1024 * 1024
    } else {
        s.parse().unwrap_or(0)
    }
}
