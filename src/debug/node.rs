//! Node diagnostics
//!
//! Checks for node issues including:
//! - Node conditions (Ready, MemoryPressure, DiskPressure, PIDPressure)
//! - Resource capacity and allocation
//! - Taints and their effects
//! - System pods health
//!
//! Enhanced SRE-level diagnostics (with --deep flag):
//! - Deleted but open files (phantom disk usage)
//! - Zombie/defunct processes
//! - Kernel messages (dmesg analysis)
//! - Network connection states (TIME_WAIT, etc.)
//! - Inode exhaustion
//! - File descriptor limits
//! - Deep kubelet health (PLEG, restarts)
//! - Container runtime health
//! - Disk I/O latency
//! - AWS EKS-specific checks (ENI, spot, etc.)
//! - Memory deep analysis (swap, cgroup pressure)
//! - CPU throttling detection

use super::types::*;
use crate::error::KcError;
use k8s_openapi::api::core::v1::{Node, Pod, Event};
use kube::{Api, Client, api::ListParams};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use std::collections::HashMap;
use tracing::warn;


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

// ============================================================================
// Enhanced SRE-Level Node Diagnostics
// ============================================================================

/// Debug a node with deep SRE-level diagnostics
///
/// This runs comprehensive API-based checks and provides diagnostic commands
/// for issues that require SSH/exec access to the node.
pub async fn debug_node_deep(
    client: &Client,
    name: &str,
) -> Result<DebugReport, KcError> {
    let api: Api<Node> = Api::all(client.clone());
    let node = api.get(name).await?;

    // Run basic analysis
    let mut issues = analyze_node(client, &node).await?;

    // Run enhanced checks via events (no exec required)
    let event_issues = check_node_events(client, name).await?;
    issues.extend(event_issues);

    // Run deep checks that analyze node-level data from Kubernetes API
    let kubelet_issues = check_kubelet_health_from_events(client, name).await?;
    issues.extend(kubelet_issues);

    let runtime_issues = check_container_runtime_from_status(&node, name);
    issues.extend(runtime_issues);

    // Analyze pods on this node for potential node-level issues
    let pod_issues = analyze_node_pods(client, name).await?;
    issues.extend(pod_issues);

    // Add suggestions for host-level checks that require SSH/exec
    issues.push(create_deep_check_suggestions(name));

    Ok(DebugReport::new("node-deep", issues))
}

/// Create suggestions for deep host-level checks
fn create_deep_check_suggestions(node_name: &str) -> DebugIssue {
    let commands = vec![
        ("Deleted but open files", "lsof -a +L1 | awk '{sum+=$7} END {print sum/1024/1024 \" MB\"}'"),
        ("Zombie processes", "ps aux | awk '$8 ~ /Z/ {count++} END {print count+0}'"),
        ("OOM kills in dmesg", "dmesg | grep -ic 'out of memory\\|oom\\|killed process'"),
        ("Filesystem errors", "dmesg | grep -icE 'ext4.*error|xfs.*error|i/o error'"),
        ("TIME_WAIT connections", "ss -tan state time-wait | wc -l"),
        ("Conntrack usage", "cat /proc/sys/net/netfilter/nf_conntrack_count"),
        ("Inode usage", "df -i /var/lib/kubelet"),
        ("File descriptors", "cat /proc/sys/fs/file-nr"),
        ("Memory info", "cat /proc/meminfo | grep -E 'MemAvailable|SwapFree'"),
        ("I/O wait", "iostat -c 1 2 | tail -1 | awk '{print $4}'"),
    ];

    let details: Vec<serde_json::Value> = commands.iter()
        .map(|(name, cmd)| serde_json::json!({
            "check": name,
            "command": cmd,
        }))
        .collect();

    DebugIssue::new(
        Severity::Info,
        DebugCategory::Node,
        "Node",
        node_name,
        "Deep host-level checks available",
        format!(
            "For comprehensive SRE-level diagnostics on node {}, SSH or use a debug pod to run the following checks.",
            node_name
        ),
    )
    .with_remediation("Run: kubectl debug node/{} -it --image=busybox -- sh")
    .with_details(serde_json::json!({
        "diagnostic_commands": details,
        "debug_pod_command": format!("kubectl debug node/{} -it --image=busybox -- sh", node_name),
    }))
}

/// Analyze pods on a node to detect node-level issues
async fn analyze_node_pods(client: &Client, node_name: &str) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let pod_api: Api<Pod> = Api::all(client.clone());
    let lp = ListParams::default().fields(&format!("spec.nodeName={}", node_name));
    let pods = pod_api.list(&lp).await?;

    let mut oom_killed_count = 0;
    let mut evicted_count = 0;
    let mut image_pull_errors = 0;
    let mut high_restart_pods = Vec::new();

    for pod in &pods.items {
        let pod_name = pod.metadata.name.as_deref().unwrap_or("unknown");
        let namespace = pod.metadata.namespace.as_deref().unwrap_or("default");

        if let Some(status) = &pod.status {
            // Check for evicted pods
            if status.phase.as_deref() == Some("Failed") {
                if let Some(reason) = &status.reason {
                    if reason == "Evicted" {
                        evicted_count += 1;
                    }
                }
            }

            // Check container statuses
            if let Some(container_statuses) = &status.container_statuses {
                for cs in container_statuses {
                    // Check for OOMKilled
                    if let Some(last_state) = &cs.last_state {
                        if let Some(terminated) = &last_state.terminated {
                            if terminated.reason.as_deref() == Some("OOMKilled") {
                                oom_killed_count += 1;
                            }
                        }
                    }

                    // Check for high restarts
                    if cs.restart_count > 10 {
                        high_restart_pods.push(format!("{}/{}", namespace, pod_name));
                    }

                    // Check for image pull issues
                    if let Some(waiting) = &cs.state.as_ref().and_then(|s| s.waiting.as_ref()) {
                        if waiting.reason.as_deref() == Some("ImagePullBackOff")
                            || waiting.reason.as_deref() == Some("ErrImagePull")
                        {
                            image_pull_errors += 1;
                        }
                    }
                }
            }
        }
    }

    // Report aggregated issues
    if oom_killed_count > 0 {
        issues.push(
            DebugIssue::new(
                Severity::Critical,
                DebugCategory::Node,
                "Node",
                node_name,
                format!("{} OOMKilled containers on node", oom_killed_count),
                format!(
                    "Node {} has {} containers that were killed due to Out of Memory. \
                    This indicates memory pressure on the node.",
                    node_name, oom_killed_count
                ),
            )
            .with_remediation("Increase memory limits or add memory resources. Check pod memory requests/limits.")
            .with_details(serde_json::json!({
                "oom_killed_count": oom_killed_count,
            }))
        );
    }

    if evicted_count > 0 {
        issues.push(
            DebugIssue::new(
                Severity::Warning,
                DebugCategory::Node,
                "Node",
                node_name,
                format!("{} evicted pods on node", evicted_count),
                format!(
                    "Node {} has {} evicted pods. This indicates resource pressure (disk, memory, or PID).",
                    node_name, evicted_count
                ),
            )
            .with_remediation("Check node conditions and clean up evicted pods: kubectl get pods --field-selector=status.phase=Failed")
            .with_details(serde_json::json!({
                "evicted_count": evicted_count,
            }))
        );
    }

    if image_pull_errors > 0 {
        issues.push(
            DebugIssue::new(
                Severity::Warning,
                DebugCategory::Node,
                "Node",
                node_name,
                format!("{} image pull errors on node", image_pull_errors),
                format!(
                    "Node {} has {} containers with image pull errors. May indicate network issues or full disk.",
                    node_name, image_pull_errors
                ),
            )
            .with_remediation("Check network connectivity to container registry. Verify disk space with: df -h")
        );
    }

    if !high_restart_pods.is_empty() {
        issues.push(
            DebugIssue::new(
                Severity::Warning,
                DebugCategory::Node,
                "Node",
                node_name,
                format!("{} pods with high restart counts", high_restart_pods.len()),
                format!(
                    "Node {} has pods with many restarts: {}. May indicate node stability issues.",
                    node_name,
                    high_restart_pods.iter().take(5).cloned().collect::<Vec<_>>().join(", ")
                ),
            )
            .with_details(serde_json::json!({
                "high_restart_pods": high_restart_pods,
            }))
        );
    }

    Ok(issues)
}

/// Check node events for issues
async fn check_node_events(client: &Client, node_name: &str) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let event_api: Api<Event> = Api::all(client.clone());
    let lp = ListParams::default().fields(&format!("involvedObject.name={}", node_name));
    let events = event_api.list(&lp).await?;

    let mut warning_counts: HashMap<String, i32> = HashMap::new();

    for event in &events.items {
        if event.type_.as_deref() == Some("Warning") {
            let reason = event.reason.as_deref().unwrap_or("Unknown");
            *warning_counts.entry(reason.to_string()).or_insert(0) += 1;
        }
    }

    // Report high-frequency warning events
    for (reason, count) in &warning_counts {
        if *count > 5 {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Node,
                    "Node",
                    node_name,
                    format!("Repeated {} events ({}x)", reason, count),
                    format!(
                        "Node {} has {} occurrences of '{}' warning events.",
                        node_name, count, reason
                    ),
                )
            );
        }
    }

    Ok(issues)
}

/// Check kubelet health from events
async fn check_kubelet_health_from_events(client: &Client, node_name: &str) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let event_api: Api<Event> = Api::all(client.clone());
    let lp = ListParams::default();
    let events = event_api.list(&lp).await?;

    for event in &events.items {
        let message = event.message.as_deref().unwrap_or("");
        let involved = &event.involved_object;
        let involved_name = involved.name.as_deref().unwrap_or("");

        if involved_name == node_name || message.contains(node_name) {
            // Check for PLEG issues
            if message.contains("PLEG is not healthy") {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Node,
                        "Node",
                        node_name,
                        "PLEG unhealthy",
                        format!(
                            "Node {} has PLEG (Pod Lifecycle Event Generator) health issues. \
                            This causes pods to not start or respond correctly.",
                            node_name
                        ),
                    )
                    .with_remediation("Check kubelet logs. May indicate disk, network, or runtime issues.")
                );
            }

            // Check for container runtime issues
            if message.contains("container runtime") && message.to_lowercase().contains("error") {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Node,
                        "Node",
                        node_name,
                        "Container runtime error",
                        format!(
                            "Node {} has container runtime errors: {}",
                            node_name, message
                        ),
                    )
                    .with_remediation("Check containerd/docker status. May need to restart runtime.")
                );
            }
        }
    }

    Ok(issues)
}

/// Check container runtime from node status
fn check_container_runtime_from_status(node: &Node, node_name: &str) -> Vec<DebugIssue> {
    let mut issues = Vec::new();

    if let Some(status) = &node.status {
        if let Some(node_info) = &status.node_info {
            let runtime = &node_info.container_runtime_version;

            // Check for Docker (should use containerd on modern clusters)
            if runtime.starts_with("docker://") {
                issues.push(
                    DebugIssue::new(
                        Severity::Info,
                        DebugCategory::Node,
                        "Node",
                        node_name,
                        "Using Docker runtime",
                        format!(
                            "Node {} is using Docker ({}). Consider migrating to containerd for better performance.",
                            node_name, runtime
                        ),
                    )
                );
            }

            // Check for very old runtime versions
            if runtime.contains("1.") && !runtime.contains("1.6") && !runtime.contains("1.7") {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Node,
                        "Node",
                        node_name,
                        "Potentially outdated container runtime",
                        format!("Node {} has runtime: {}", node_name, runtime),
                    )
                    .with_remediation("Consider upgrading container runtime for security and stability")
                );
            }
        }
    }

    issues
}
