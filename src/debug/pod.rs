//! Pod diagnostics
//!
//! Comprehensive pod debugging including:
//! - Container state analysis
//! - Exit code interpretation
//! - OOMKilled detection
//! - CrashLoopBackOff detection
//! - Image pull issues
//! - Volume mount failures
//! - Probe failures
//! - Resource pressure

use super::types::*;
use crate::error::KcError;
use k8s_openapi::api::core::v1::{Pod, Event};
use kube::{Api, Client, api::ListParams};

/// Debug all pods in namespace (or all namespaces)
pub async fn debug_pods(
    client: &Client,
    namespace: Option<&str>,
) -> Result<DebugReport, KcError> {
    let pods: Vec<Pod> = if let Some(ns) = namespace {
        let api: Api<Pod> = Api::namespaced(client.clone(), ns);
        api.list(&ListParams::default()).await?.items
    } else {
        let api: Api<Pod> = Api::all(client.clone());
        api.list(&ListParams::default()).await?.items
    };

    let mut issues = Vec::new();
    let mut total_checks = 0;

    for pod in &pods {
        let pod_issues = analyze_pod(client, pod).await?;
        total_checks += 1;
        issues.extend(pod_issues);
    }

    Ok(DebugReport::with_check_count("pod", issues, total_checks))
}

/// Debug a specific pod
pub async fn debug_pod(
    client: &Client,
    namespace: &str,
    name: &str,
) -> Result<DebugReport, KcError> {
    let api: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let pod = api.get(name).await?;

    let issues = analyze_pod(client, &pod).await?;
    Ok(DebugReport::new("pod", issues))
}

/// Analyze a single pod for issues
async fn analyze_pod(client: &Client, pod: &Pod) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let name = pod.metadata.name.as_deref().unwrap_or("unknown");
    let namespace = pod.metadata.namespace.as_deref().unwrap_or("default");

    let status = match &pod.status {
        Some(s) => s,
        None => return Ok(issues),
    };

    let spec = match &pod.spec {
        Some(s) => s,
        None => return Ok(issues),
    };

    // Check pod phase
    if let Some(phase) = &status.phase {
        match phase.as_str() {
            "Failed" => {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Pod,
                        "Pod",
                        name,
                        "Pod in Failed state",
                        format!("Pod {} is in Failed phase. Check events and container logs.", name),
                    )
                    .with_namespace(namespace)
                    .with_remediation("Check pod events with 'kubectl describe pod' and container logs with 'kubectl logs'")
                );
            }
            "Pending" => {
                // Check why pending
                if let Some(conditions) = &status.conditions {
                    for condition in conditions {
                        if condition.type_ == "PodScheduled" && condition.status == "False" {
                            let reason = condition.reason.as_deref().unwrap_or("Unknown");
                            let message = condition.message.as_deref().unwrap_or("");

                            issues.push(
                                DebugIssue::new(
                                    Severity::Warning,
                                    DebugCategory::Pod,
                                    "Pod",
                                    name,
                                    format!("Pod pending: {}", reason),
                                    format!("Pod cannot be scheduled. Reason: {}. {}", reason, message),
                                )
                                .with_namespace(namespace)
                                .with_remediation(get_scheduling_remediation(reason))
                            );
                        }
                    }
                }
            }
            _ => {}
        }
    }

    // Analyze init containers
    if let Some(init_statuses) = &status.init_container_statuses {
        for init_status in init_statuses {
            if let Some(state) = &init_status.state {
                if let Some(waiting) = &state.waiting {
                    let reason = waiting.reason.as_deref().unwrap_or("Unknown");
                    let message = waiting.message.as_deref();

                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Pod,
                            "InitContainer",
                            &init_status.name,
                            format!("Init container waiting: {}", reason),
                            format!("Init container {} is waiting. {}", init_status.name, message.unwrap_or("")),
                        )
                        .with_namespace(namespace)
                        .with_details(serde_json::json!({
                            "pod": name,
                            "container": init_status.name,
                            "reason": reason,
                        }))
                    );
                }

                if let Some(terminated) = &state.terminated {
                    if terminated.exit_code != 0 {
                        let exit_info = ExitCodeInfo::analyze(terminated.exit_code);

                        issues.push(
                            DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Pod,
                                "InitContainer",
                                &init_status.name,
                                format!("Init container failed with exit code {}", terminated.exit_code),
                                format!(
                                    "Init container {} exited with code {}. {}: {}",
                                    init_status.name,
                                    terminated.exit_code,
                                    exit_info.meaning,
                                    exit_info.common_causes.join(", ")
                                ),
                            )
                            .with_namespace(namespace)
                            .with_remediation("Check init container logs for error details")
                            .with_details(serde_json::json!({
                                "pod": name,
                                "container": init_status.name,
                                "exit_code": terminated.exit_code,
                                "exit_info": exit_info,
                            }))
                        );
                    }
                }
            }
        }
    }

    // Analyze main containers
    if let Some(container_statuses) = &status.container_statuses {
        for cs in container_statuses {
            // Check restart count
            let pattern = RestartPattern::analyze(cs.restart_count);
            if pattern.is_crash_loop {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Pod,
                        "Container",
                        &cs.name,
                        format!("CrashLoopBackOff detected ({} restarts)", cs.restart_count),
                        format!(
                            "Container {} has restarted {} times. This indicates a persistent failure.",
                            cs.name, cs.restart_count
                        ),
                    )
                    .with_namespace(namespace)
                    .with_remediation("Check container logs for root cause. Common issues: exit code errors, OOMKilled, liveness probe failures.")
                    .with_details(serde_json::json!({
                        "pod": name,
                        "container": cs.name,
                        "restart_count": cs.restart_count,
                        "pattern": pattern,
                    }))
                );
            } else if cs.restart_count > 5 {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Pod,
                        "Container",
                        &cs.name,
                        format!("High restart count ({})", cs.restart_count),
                        format!("Container {} has restarted {} times. Investigate stability.", cs.name, cs.restart_count),
                    )
                    .with_namespace(namespace)
                    .with_details(serde_json::json!({
                        "pod": name,
                        "container": cs.name,
                        "restart_count": cs.restart_count,
                    }))
                );
            }

            // Analyze container state
            if let Some(state) = &cs.state {
                // Waiting state
                if let Some(waiting) = &state.waiting {
                    let reason = waiting.reason.as_deref().unwrap_or("Unknown");
                    let message = waiting.message.as_deref();
                    let (is_recoverable, suggested_actions) =
                        ContainerStateAnalysis::analyze_waiting_reason(reason, message);

                    let severity = if is_recoverable { Severity::Warning } else { Severity::Critical };

                    issues.push(
                        DebugIssue::new(
                            severity,
                            DebugCategory::Pod,
                            "Container",
                            &cs.name,
                            format!("Container waiting: {}", reason),
                            format!("Container {} is waiting. {}", cs.name, message.unwrap_or("")),
                        )
                        .with_namespace(namespace)
                        .with_remediation(&suggested_actions.join(". "))
                        .with_details(serde_json::json!({
                            "pod": name,
                            "container": cs.name,
                            "reason": reason,
                            "message": message,
                            "is_recoverable": is_recoverable,
                        }))
                    );
                }

                // Terminated state
                if let Some(terminated) = &state.terminated {
                    // Check for OOMKilled
                    if terminated.reason.as_deref() == Some("OOMKilled") {
                        issues.push(
                            DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Pod,
                                "Container",
                                &cs.name,
                                "OOMKilled - Out of Memory",
                                format!(
                                    "Container {} was killed due to out of memory. The container exceeded its memory limit.",
                                    cs.name
                                ),
                            )
                            .with_namespace(namespace)
                            .with_remediation("Increase memory limits or optimize application memory usage. Check for memory leaks.")
                            .with_details(serde_json::json!({
                                "pod": name,
                                "container": cs.name,
                                "exit_code": terminated.exit_code,
                                "reason": "OOMKilled",
                            }))
                        );
                    } else if terminated.exit_code != 0 {
                        let exit_info = ExitCodeInfo::analyze(terminated.exit_code);

                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Pod,
                                "Container",
                                &cs.name,
                                format!("Container exited with code {}", terminated.exit_code),
                                format!(
                                    "Container {} terminated. {}: {}",
                                    cs.name,
                                    exit_info.meaning,
                                    exit_info.common_causes.join(", ")
                                ),
                            )
                            .with_namespace(namespace)
                            .with_details(serde_json::json!({
                                "pod": name,
                                "container": cs.name,
                                "exit_info": exit_info,
                            }))
                        );
                    }
                }
            }

            // Check last termination state
            if let Some(last_state) = &cs.last_state {
                if let Some(terminated) = &last_state.terminated {
                    if terminated.reason.as_deref() == Some("OOMKilled") {
                        // Already running but was previously OOMKilled
                        if cs.state.as_ref().and_then(|s| s.running.as_ref()).is_some() {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Warning,
                                    DebugCategory::Pod,
                                    "Container",
                                    &cs.name,
                                    "Previously OOMKilled",
                                    format!(
                                        "Container {} was previously killed due to OOM but is now running. Consider increasing memory limits.",
                                        cs.name
                                    ),
                                )
                                .with_namespace(namespace)
                                .with_remediation("Increase memory limits to prevent future OOM kills")
                            );
                        }
                    }
                }
            }
        }
    }

    // Check for missing resource limits
    for container in &spec.containers {
        let has_limits = container.resources.as_ref()
            .and_then(|r| r.limits.as_ref())
            .map(|l| !l.is_empty())
            .unwrap_or(false);

        if !has_limits {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Pod,
                    "Container",
                    &container.name,
                    "No resource limits defined",
                    format!("Container {} has no resource limits. This can lead to resource contention and OOM issues.", container.name),
                )
                .with_namespace(namespace)
                .with_remediation("Define CPU and memory limits for the container")
                .with_details(serde_json::json!({
                    "pod": name,
                    "container": container.name,
                }))
            );
        }

        let has_requests = container.resources.as_ref()
            .and_then(|r| r.requests.as_ref())
            .map(|r| !r.is_empty())
            .unwrap_or(false);

        if !has_requests {
            issues.push(
                DebugIssue::new(
                    Severity::Info,
                    DebugCategory::Pod,
                    "Container",
                    &container.name,
                    "No resource requests defined",
                    format!("Container {} has no resource requests. The scheduler may not allocate appropriate resources.", container.name),
                )
                .with_namespace(namespace)
                .with_remediation("Define CPU and memory requests for better scheduling")
            );
        }

        // Check for missing probes
        if container.liveness_probe.is_none() && container.readiness_probe.is_none() {
            issues.push(
                DebugIssue::new(
                    Severity::Info,
                    DebugCategory::Pod,
                    "Container",
                    &container.name,
                    "No health probes configured",
                    format!("Container {} has no liveness or readiness probes. Kubernetes cannot detect if the container is healthy.", container.name),
                )
                .with_namespace(namespace)
                .with_remediation("Add liveness and/or readiness probes for better health detection")
            );
        }

        // Check for :latest tag
        if let Some(image) = &container.image {
            if image.ends_with(":latest") || !image.contains(':') {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Pod,
                        "Container",
                        &container.name,
                        "Using :latest or untagged image",
                        format!("Container {} uses image '{}'. This can cause unpredictable behavior.", container.name, image),
                    )
                    .with_namespace(namespace)
                    .with_remediation("Use a specific image tag instead of :latest")
                );
            }
        }
    }

    // Check for pod-level security issues
    if let Some(security_context) = &spec.security_context {
        if security_context.run_as_user == Some(0) {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Pod,
                    "Pod",
                    name,
                    "Pod runs as root user",
                    "Running as root user increases security risk. Consider running as non-root.",
                )
                .with_namespace(namespace)
                .with_remediation("Set runAsNonRoot: true and specify a non-root runAsUser")
            );
        }
    }

    // Check host namespaces
    if spec.host_network == Some(true) {
        issues.push(
            DebugIssue::new(
                Severity::Warning,
                DebugCategory::Pod,
                "Pod",
                name,
                "Using host network namespace",
                "Pod shares the host's network namespace. This bypasses network isolation.",
            )
            .with_namespace(namespace)
            .with_remediation("Consider if hostNetwork is truly required")
        );
    }

    if spec.host_pid == Some(true) {
        issues.push(
            DebugIssue::new(
                Severity::Warning,
                DebugCategory::Pod,
                "Pod",
                name,
                "Using host PID namespace",
                "Pod shares the host's PID namespace. Processes can see all host processes.",
            )
            .with_namespace(namespace)
            .with_remediation("Consider if hostPID is truly required")
        );
    }

    // Check events for additional issues
    let event_issues = check_pod_events(client, namespace, name).await?;
    issues.extend(event_issues);

    Ok(issues)
}

/// Check pod events for issues
async fn check_pod_events(
    client: &Client,
    namespace: &str,
    pod_name: &str,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let api: Api<Event> = Api::namespaced(client.clone(), namespace);
    let field_selector = format!("involvedObject.name={},involvedObject.kind=Pod", pod_name);
    let lp = ListParams::default().fields(&field_selector);

    let events = api.list(&lp).await?.items;

    for event in events {
        let event_type = event.type_.as_deref().unwrap_or("Normal");
        let reason = event.reason.as_deref().unwrap_or("Unknown");
        let message = event.message.as_deref().unwrap_or("");

        if event_type == "Warning" {
            let severity = match reason {
                "FailedScheduling" | "FailedMount" | "FailedAttachVolume" => Severity::Critical,
                "Unhealthy" | "BackOff" | "Failed" => Severity::Warning,
                _ => Severity::Info,
            };

            issues.push(
                DebugIssue::new(
                    severity,
                    DebugCategory::Pod,
                    "Event",
                    reason,
                    format!("Event: {}", reason),
                    message.to_string(),
                )
                .with_namespace(namespace)
                .with_details(serde_json::json!({
                    "pod": pod_name,
                    "event_type": event_type,
                    "reason": reason,
                    "count": event.count,
                }))
            );
        }
    }

    Ok(issues)
}

/// Get remediation for scheduling issues
fn get_scheduling_remediation(reason: &str) -> String {
    match reason {
        "Unschedulable" => "Check node capacity and pod resource requests. Consider adding more nodes or reducing resource requests.".to_string(),
        "FailedScheduling" => "Check node affinity, taints, tolerations, and available resources.".to_string(),
        "InsufficientCPU" => "Reduce CPU requests or add nodes with more CPU capacity.".to_string(),
        "InsufficientMemory" => "Reduce memory requests or add nodes with more memory.".to_string(),
        "PodToleratesNodeTaints" => "Add appropriate tolerations to the pod spec.".to_string(),
        _ => "Check pod events and node status for more details.".to_string(),
    }
}
