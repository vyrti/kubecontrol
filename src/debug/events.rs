//! Event correlation and pattern detection
//!
//! Analyzes Kubernetes events to:
//! - Detect patterns (repeated failures)
//! - Correlate events across resources
//! - Build event chains for root cause analysis
//! - Identify warning event clusters

use super::types::*;
use crate::error::KcError;
use k8s_openapi::api::core::v1::Event;
use kube::{Api, Client, api::ListParams};
use std::collections::HashMap;

/// Debug events and find patterns
pub async fn debug_events(
    client: &Client,
    namespace: Option<&str>,
) -> Result<DebugReport, KcError> {
    let events: Vec<Event> = if let Some(ns) = namespace {
        let api: Api<Event> = Api::namespaced(client.clone(), ns);
        api.list(&ListParams::default()).await?.items
    } else {
        let api: Api<Event> = Api::all(client.clone());
        api.list(&ListParams::default()).await?.items
    };

    let issues = analyze_events(&events);
    Ok(DebugReport::new("events", issues))
}

/// Analyze events for patterns and issues
fn analyze_events(events: &[Event]) -> Vec<DebugIssue> {
    let mut issues = Vec::new();

    // Filter to warning events
    let warning_events: Vec<_> = events
        .iter()
        .filter(|e| e.type_.as_deref() == Some("Warning"))
        .collect();

    // Group by involved object
    let mut by_object: HashMap<String, Vec<&Event>> = HashMap::new();
    for event in &warning_events {
        let involved = &event.involved_object;
        let key = format!(
            "{}/{}/{}",
            involved.namespace.as_deref().unwrap_or(""),
            involved.kind.as_deref().unwrap_or(""),
            involved.name.as_deref().unwrap_or("")
        );
        by_object.entry(key).or_default().push(event);
    }

    // Detect repeated events (same reason, high count)
    for event in &warning_events {
        let count = event.count.unwrap_or(1);
        let reason = event.reason.as_deref().unwrap_or("Unknown");
        let message = event.message.as_deref().unwrap_or("");

        if count >= 5 {
            let involved = &event.involved_object;
            let resource_type = involved.kind.as_deref().unwrap_or("Unknown");
            let resource_name = involved.name.as_deref().unwrap_or("unknown");
            let namespace = involved.namespace.as_deref();

            let severity = match count {
                5..=10 => Severity::Warning,
                _ => Severity::Critical,
            };

            let mut issue = DebugIssue::new(
                severity,
                DebugCategory::Events,
                resource_type,
                resource_name,
                format!("Repeated event: {} ({} times)", reason, count),
                format!("Event '{}' occurred {} times: {}", reason, count, message),
            )
            .with_remediation(get_event_remediation(reason));

            if let Some(ns) = namespace {
                issue = issue.with_namespace(ns);
            }

            issue = issue.with_details(serde_json::json!({
                "reason": reason,
                "count": count,
                "message": message,
            }));

            issues.push(issue);
        }
    }

    // Detect event patterns for objects
    for (object_key, object_events) in &by_object {
        let patterns = detect_event_patterns(object_events);

        for pattern in patterns {
            let parts: Vec<&str> = object_key.split('/').collect();
            let namespace = if parts.len() > 0 && !parts[0].is_empty() { Some(parts[0]) } else { None };
            let resource_type = if parts.len() > 1 { parts[1] } else { "Unknown" };
            let resource_name = if parts.len() > 2 { parts[2] } else { "unknown" };

            let mut issue = DebugIssue::new(
                pattern.severity,
                DebugCategory::Events,
                resource_type,
                resource_name,
                pattern.title,
                pattern.description,
            );

            if let Some(ns) = namespace {
                issue = issue.with_namespace(ns);
            }

            if let Some(remediation) = pattern.remediation {
                issue = issue.with_remediation(remediation);
            }

            issue = issue.with_details(pattern.details);
            issues.push(issue);
        }
    }

    // Detect cluster-wide patterns
    let cluster_patterns = detect_cluster_patterns(&warning_events);
    for pattern in cluster_patterns {
        issues.push(
            DebugIssue::new(
                pattern.severity,
                DebugCategory::Events,
                "Cluster",
                "cluster-wide",
                pattern.title,
                pattern.description,
            )
            .with_details(pattern.details)
        );
    }

    issues
}

/// Event pattern detection result
struct EventPattern {
    severity: Severity,
    title: String,
    description: String,
    remediation: Option<String>,
    details: serde_json::Value,
}

/// Detect patterns in events for a single object
fn detect_event_patterns(events: &[&Event]) -> Vec<EventPattern> {
    let mut patterns = Vec::new();

    // Group by reason
    let mut by_reason: HashMap<&str, Vec<&Event>> = HashMap::new();
    for event in events {
        let reason = event.reason.as_deref().unwrap_or("Unknown");
        by_reason.entry(reason).or_default().push(event);
    }

    // Detect CrashLoop pattern
    let backoff_count = by_reason.get("BackOff").map(|e| e.len()).unwrap_or(0);
    let failed_count = by_reason.get("Failed").map(|e| e.len()).unwrap_or(0);

    if backoff_count > 0 && failed_count > 0 {
        patterns.push(EventPattern {
            severity: Severity::Critical,
            title: "CrashLoop pattern detected".to_string(),
            description: format!(
                "BackOff ({}) and Failed ({}) events indicate a crash loop.",
                backoff_count, failed_count
            ),
            remediation: Some("Check container logs for the root cause of failures".to_string()),
            details: serde_json::json!({
                "backoff_events": backoff_count,
                "failed_events": failed_count,
                "pattern": "crash_loop",
            }),
        });
    }

    // Detect scheduling issues pattern
    let scheduling_issues = by_reason.get("FailedScheduling").map(|e| e.len()).unwrap_or(0);
    if scheduling_issues > 3 {
        patterns.push(EventPattern {
            severity: Severity::Critical,
            title: "Persistent scheduling failures".to_string(),
            description: format!("{} scheduling failures detected", scheduling_issues),
            remediation: Some("Check node resources, taints, and pod requirements".to_string()),
            details: serde_json::json!({
                "scheduling_failures": scheduling_issues,
                "pattern": "scheduling_issues",
            }),
        });
    }

    // Detect image pull issues
    let image_pull_errors = by_reason.get("Failed").map(|events| {
        events.iter().filter(|e| {
            e.message.as_deref().map(|m| m.contains("ImagePull") || m.contains("image")).unwrap_or(false)
        }).count()
    }).unwrap_or(0);

    if image_pull_errors > 0 {
        patterns.push(EventPattern {
            severity: Severity::Critical,
            title: "Image pull failures".to_string(),
            description: format!("{} image pull failures detected", image_pull_errors),
            remediation: Some("Verify image name, tag, and registry authentication".to_string()),
            details: serde_json::json!({
                "image_pull_errors": image_pull_errors,
                "pattern": "image_pull_issues",
            }),
        });
    }

    // Detect probe failures
    let probe_failures = by_reason.get("Unhealthy").map(|e| e.len()).unwrap_or(0);
    if probe_failures > 5 {
        patterns.push(EventPattern {
            severity: Severity::Warning,
            title: "Frequent probe failures".to_string(),
            description: format!("{} health probe failures detected", probe_failures),
            remediation: Some("Review probe configuration and application health endpoint".to_string()),
            details: serde_json::json!({
                "probe_failures": probe_failures,
                "pattern": "probe_issues",
            }),
        });
    }

    // Detect volume mount issues
    let mount_failures = by_reason.get("FailedMount").map(|e| e.len()).unwrap_or(0)
        + by_reason.get("FailedAttachVolume").map(|e| e.len()).unwrap_or(0);

    if mount_failures > 0 {
        patterns.push(EventPattern {
            severity: Severity::Critical,
            title: "Volume mount failures".to_string(),
            description: format!("{} volume mount/attach failures detected", mount_failures),
            remediation: Some("Check PVC status, storage class, and node storage capacity".to_string()),
            details: serde_json::json!({
                "mount_failures": mount_failures,
                "pattern": "volume_issues",
            }),
        });
    }

    patterns
}

/// Detect cluster-wide patterns
fn detect_cluster_patterns(events: &[&Event]) -> Vec<EventPattern> {
    let mut patterns = Vec::new();

    // Count events by reason
    let mut reason_counts: HashMap<&str, usize> = HashMap::new();
    for event in events {
        let reason = event.reason.as_deref().unwrap_or("Unknown");
        *reason_counts.entry(reason).or_insert(0) += 1;
    }

    // Detect widespread scheduling issues
    if let Some(&count) = reason_counts.get("FailedScheduling") {
        if count > 10 {
            patterns.push(EventPattern {
                severity: Severity::Critical,
                title: "Cluster-wide scheduling issues".to_string(),
                description: format!("{} pods failed to schedule across the cluster", count),
                remediation: Some("Check cluster capacity, add nodes, or reduce resource requests".to_string()),
                details: serde_json::json!({
                    "scheduling_failures": count,
                    "pattern": "cluster_scheduling_issues",
                }),
            });
        }
    }

    // Detect node pressure events
    let node_pressure_reasons = ["NodeNotReady", "NodeMemoryPressure", "NodeDiskPressure", "NodePIDPressure"];
    let node_pressure_count: usize = node_pressure_reasons
        .iter()
        .filter_map(|r| reason_counts.get(*r))
        .sum();

    if node_pressure_count > 5 {
        patterns.push(EventPattern {
            severity: Severity::Critical,
            title: "Node pressure detected".to_string(),
            description: format!("{} node pressure events across the cluster", node_pressure_count),
            remediation: Some("Check node health, resource utilization, and consider scaling".to_string()),
            details: serde_json::json!({
                "pressure_events": node_pressure_count,
                "pattern": "node_pressure",
            }),
        });
    }

    // Count total warnings in last hour (if we had timestamp access)
    let total_warnings = events.len();
    if total_warnings > 50 {
        patterns.push(EventPattern {
            severity: Severity::Warning,
            title: "High warning event volume".to_string(),
            description: format!("{} warning events in the cluster", total_warnings),
            remediation: Some("Review and address underlying issues causing warnings".to_string()),
            details: serde_json::json!({
                "total_warnings": total_warnings,
                "pattern": "high_warning_volume",
            }),
        });
    }

    patterns
}

/// Get remediation suggestion for event reason
fn get_event_remediation(reason: &str) -> String {
    match reason {
        "BackOff" => "Check container logs and fix the underlying issue causing restarts".to_string(),
        "Failed" => "Examine the failure message and container logs for details".to_string(),
        "FailedScheduling" => "Check node resources, taints, tolerations, and affinity rules".to_string(),
        "FailedMount" | "FailedAttachVolume" => "Verify PVC exists, is bound, and storage is available".to_string(),
        "Unhealthy" => "Review health probe configuration and application responsiveness".to_string(),
        "Killing" => "Check if this is expected (rolling update) or unexpected termination".to_string(),
        "NodeNotReady" => "Investigate node health, kubelet status, and network connectivity".to_string(),
        "FailedCreate" => "Check resource quotas, limits, and controller logs".to_string(),
        "FailedSync" => "Check controller logs for sync errors".to_string(),
        "NetworkNotReady" => "Check CNI plugin status and network configuration".to_string(),
        _ => "Check event details and related resource status".to_string(),
    }
}

/// Build event chain for root cause analysis
pub fn build_event_chain(events: &[Event]) -> Vec<EventChain> {
    let mut chains = Vec::new();

    // Group by involved object
    let mut by_object: HashMap<String, Vec<&Event>> = HashMap::new();
    for event in events {
        let involved = &event.involved_object;
        let key = format!(
            "{}/{}",
            involved.namespace.as_deref().unwrap_or(""),
            involved.name.as_deref().unwrap_or("")
        );
        by_object.entry(key).or_default().push(event);
    }

    for (object, object_events) in by_object {
        // Sort by timestamp
        let mut sorted_events = object_events;
        sorted_events.sort_by(|a, b| {
            let a_time = a.last_timestamp.as_ref().or(a.first_timestamp.as_ref());
            let b_time = b.last_timestamp.as_ref().or(b.first_timestamp.as_ref());
            a_time.cmp(&b_time)
        });

        if sorted_events.len() >= 2 {
            let chain_events: Vec<_> = sorted_events
                .iter()
                .filter(|e| e.type_.as_deref() == Some("Warning"))
                .map(|e| ChainEvent {
                    reason: e.reason.clone().unwrap_or_default(),
                    message: e.message.clone().unwrap_or_default(),
                    count: e.count.unwrap_or(1),
                })
                .collect();

            if !chain_events.is_empty() {
                chains.push(EventChain {
                    object: object.clone(),
                    events: chain_events,
                    root_cause: infer_root_cause(&sorted_events),
                });
            }
        }
    }

    chains
}

/// Event chain for visualization
#[derive(Debug, Clone)]
pub struct EventChain {
    pub object: String,
    pub events: Vec<ChainEvent>,
    pub root_cause: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ChainEvent {
    pub reason: String,
    pub message: String,
    pub count: i32,
}

/// Infer root cause from event sequence
fn infer_root_cause(events: &[&Event]) -> Option<String> {
    // Look for the earliest warning event
    for event in events {
        if event.type_.as_deref() == Some("Warning") {
            let reason = event.reason.as_deref().unwrap_or("");
            let message = event.message.as_deref().unwrap_or("");

            // Check for common root causes
            if message.contains("ImagePull") {
                return Some("Image pull failure - check image name and registry access".to_string());
            }
            if message.contains("Insufficient") {
                return Some("Resource constraints - not enough CPU/memory available".to_string());
            }
            if message.contains("taint") || message.contains("toleration") {
                return Some("Node taint/toleration mismatch".to_string());
            }
            if message.contains("affinity") {
                return Some("Pod affinity/anti-affinity constraints not satisfied".to_string());
            }
            if reason == "FailedMount" || reason == "FailedAttachVolume" {
                return Some("Volume mount failure - check PVC and storage".to_string());
            }
            if reason == "OOMKilled" {
                return Some("Out of memory - container exceeded memory limit".to_string());
            }

            // Default to first warning reason
            return Some(format!("{}: {}", reason, message));
        }
    }

    None
}
