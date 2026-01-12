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
                    .with_remediation(format!(
                        "Run `kc logs {} --previous` for crash logs. Run `kc describe pod {}` for events.",
                        name, name
                    ))
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

    // Check for stuck terminating pods
    if pod.metadata.deletion_timestamp.is_some() {
        issues.push(
            DebugIssue::new(
                Severity::Warning,
                DebugCategory::Pod,
                "Pod",
                name,
                "Pod stuck in Terminating state",
                format!("Pod {} has a deletion timestamp but has not been fully terminated", name),
            )
            .with_namespace(namespace)
            .with_remediation(format!(
                "Check finalizers: `kc describe pod {}`. Force delete if stuck: `kc delete pod {} --force --grace-period=0`",
                name, name
            ))
        );
    }

    // Check pod conditions for additional issues
    if let Some(conditions) = &status.conditions {
        for condition in conditions {
            match (condition.type_.as_str(), condition.status.as_str()) {
                ("Ready", "False") => {
                    // Only report if pod is not Pending (which is expected to not be ready)
                    if status.phase.as_deref() != Some("Pending") {
                        let reason = condition.reason.as_deref().unwrap_or("Unknown");
                        let message = condition.message.as_deref().unwrap_or("");
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Pod,
                                "Pod",
                                name,
                                format!("Pod not ready: {}", reason),
                                format!("Pod {} is not ready. {}", name, message),
                            )
                            .with_namespace(namespace)
                            .with_remediation(format!(
                                "Run `kc describe pod {}` for status. Check container readiness probes.",
                                name
                            ))
                        );
                    }
                }
                ("ContainersReady", "False") => {
                    if status.phase.as_deref() == Some("Running") {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Pod,
                                "Pod",
                                name,
                                "Containers not ready",
                                format!("Not all containers in pod {} are ready. {}", name,
                                    condition.message.as_deref().unwrap_or("")),
                            )
                            .with_namespace(namespace)
                            .with_remediation(format!(
                                "Run `kc logs {}` to check each container. Verify readiness probes.",
                                name
                            ))
                        );
                    }
                }
                ("Initialized", "False") => {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Pod,
                            "Pod",
                            name,
                            "Pod initialization incomplete",
                            format!("Init containers have not completed for pod {}. {}",
                                name, condition.message.as_deref().unwrap_or("")),
                        )
                        .with_namespace(namespace)
                        .with_remediation(format!(
                            "Check init container status: `kc describe pod {}`. Review init container logs.",
                            name
                        ))
                    );
                }
                ("DisruptionTarget", "True") => {
                    issues.push(
                        DebugIssue::new(
                            Severity::Info,
                            DebugCategory::Pod,
                            "Pod",
                            name,
                            "Pod targeted for disruption",
                            format!("Pod {} is being considered for eviction or disruption", name),
                        )
                        .with_namespace(namespace)
                        .with_remediation("Pod may be evicted due to maintenance or preemption. This is informational.")
                    );
                }
                _ => {}
            }
        }
    }

    // Check QoS class for eviction risk
    if let Some(qos_class) = &status.qos_class {
        if qos_class == "BestEffort" {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Pod,
                    "Pod",
                    name,
                    "BestEffort QoS - first to be evicted",
                    format!("Pod {} has no resource requests/limits. It will be first to evict under memory pressure.", name),
                )
                .with_namespace(namespace)
                .with_remediation("Set resource requests and limits to achieve Burstable or Guaranteed QoS class")
            );
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
                            .with_remediation(format!(
                                "Run `kc logs {} -c {}` for init container logs. Check `kc describe pod {}` for events.",
                                name, init_status.name, name
                            ))
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
                    .with_remediation(format!(
                        "Run `kc logs {} -c {} --previous` for crash logs. Check exit codes in `kc describe pod {}`.",
                        name, cs.name, name
                    ))
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
                            .with_remediation(format!(
                                "Increase memory limits. Check usage: `kc exec {} -- cat /proc/meminfo`. Profile for memory leaks.",
                                name
                            ))
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

            // Check for container running but not ready
            if !cs.ready {
                if let Some(state) = &cs.state {
                    if state.running.is_some() {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Pod,
                                "Container",
                                &cs.name,
                                "Container running but not ready",
                                format!("Container {} is running but not passing readiness probe", cs.name),
                            )
                            .with_namespace(namespace)
                            .with_remediation(format!(
                                "Check readiness probe: `kc describe pod {}`. Test: `kc exec {} -- curl localhost:<port><path>`",
                                name, name
                            ))
                            .with_details(serde_json::json!({
                                "pod": name,
                                "container": cs.name,
                                "running": true,
                                "ready": false,
                            }))
                        );
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
                .with_remediation(format!(
                    "Add CPU/memory limits. Monitor: `kc exec {} -- top` or check metrics.",
                    name
                ))
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
                .with_remediation("Define CPU and memory requests for better scheduling. Run `kc debug resources` to check cluster allocation.")
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
                .with_remediation(format!(
                    "Add liveness/readiness probes. Test: `kc exec {} -- curl localhost:<port>/health`",
                    name
                ))
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

    // Check for hostPath volumes (security concern)
    if let Some(volumes) = &spec.volumes {
        for volume in volumes {
            if let Some(host_path) = &volume.host_path {
                let path = &host_path.path;
                let severity = if path == "/" || path.starts_with("/etc") || path.starts_with("/var/run") || path.starts_with("/proc") {
                    Severity::Warning
                } else {
                    Severity::Info
                };

                issues.push(
                    DebugIssue::new(
                        severity,
                        DebugCategory::Pod,
                        "Volume",
                        &volume.name,
                        format!("hostPath volume: {}", path),
                        format!("Pod {} mounts host path {}. This bypasses container isolation.", name, path),
                    )
                    .with_namespace(namespace)
                    .with_remediation("Consider if hostPath is necessary. Use PVCs or ConfigMaps/Secrets when possible.")
                );
            }

            // Check emptyDir without sizeLimit
            if let Some(empty_dir) = &volume.empty_dir {
                if empty_dir.size_limit.is_none() {
                    issues.push(
                        DebugIssue::new(
                            Severity::Info,
                            DebugCategory::Pod,
                            "Volume",
                            &volume.name,
                            "emptyDir without sizeLimit",
                            format!("Volume {} has no sizeLimit. Pod may be evicted if it uses too much ephemeral storage.", volume.name),
                        )
                        .with_namespace(namespace)
                        .with_remediation("Consider setting sizeLimit on emptyDir to prevent eviction")
                    );
                }
            }
        }
    }

    // Check ephemeral container status
    if let Some(ephemeral_statuses) = &status.ephemeral_container_statuses {
        for es in ephemeral_statuses {
            if let Some(state) = &es.state {
                if let Some(waiting) = &state.waiting {
                    let reason = waiting.reason.as_deref().unwrap_or("Unknown");
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Pod,
                            "EphemeralContainer",
                            &es.name,
                            format!("Ephemeral container waiting: {}", reason),
                            format!("Debug container {} is waiting: {}", es.name, waiting.message.as_deref().unwrap_or("")),
                        )
                        .with_namespace(namespace)
                        .with_remediation(format!("Check ephemeral container status: `kc describe pod {}`", name))
                    );
                }
            }
        }
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

            // Get event-specific remediation
            let remediation = get_event_remediation(reason, pod_name);

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
                .with_remediation(remediation)
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
        "Unschedulable" => "Run `kc nodes` for capacity. Run `kc debug resources` for allocation. Reduce requests or scale.".to_string(),
        "FailedScheduling" => "Run `kc describe pod <name>` for constraints. Check `kc nodes` for taints/resources.".to_string(),
        "InsufficientCPU" => "Check CPU: `kc debug resources`. Reduce CPU requests or add nodes.".to_string(),
        "InsufficientMemory" => "Check memory: `kc debug resources`. Reduce memory requests or add nodes.".to_string(),
        "PodToleratesNodeTaints" => "View taints: `kc describe node <name>`. Add matching tolerations to pod spec.".to_string(),
        "NodeSelectorMismatch" | "NoNodesAvailable" => "Run `kc nodes` for available nodes. Review nodeSelector in pod spec.".to_string(),
        "PodAffinityRulesNotMatch" => "Check affinity rules in spec. Run `kc pods -l <selector>` for matching pods.".to_string(),
        "TaintToleration" => "Node has taints pod doesn't tolerate. View: `kc describe node <name>`. Add tolerations.".to_string(),
        "NodeResourcesFit" => "Node doesn't have enough resources. Check `kc nodes` and `kc debug resources`.".to_string(),
        _ => "Run `kc describe pod <name>` for events. Run `kc debug cluster` for diagnostics.".to_string(),
    }
}

/// Get remediation for pod events
fn get_event_remediation(reason: &str, pod_name: &str) -> String {
    match reason {
        "FailedScheduling" => format!(
            "Run `kc describe pod {}` for scheduling constraints. Check `kc nodes` for resources.",
            pod_name
        ),
        "FailedMount" | "FailedAttachVolume" => format!(
            "Run `kc debug storage` to check PVC/PV status. Verify volume exists: `kc get pvc`."
        ),
        "Unhealthy" => format!(
            "Check probe config: `kc describe pod {}`. Test probe: `kc exec {} -- curl localhost:<port><path>`.",
            pod_name, pod_name
        ),
        "BackOff" => format!(
            "Run `kc logs {} --previous` for crash logs. Check `kc describe pod {}` for exit codes.",
            pod_name, pod_name
        ),
        "Evicted" => format!(
            "Pod was evicted. Run `kc debug node <node>` to check node pressure. Review resource requests."
        ),
        "Preempted" => format!(
            "Pod was preempted by higher priority pod. Review PriorityClass settings."
        ),
        "FailedCreatePodSandbox" => format!(
            "Network/CNI issue. Run `kc debug network` to diagnose CNI health."
        ),
        "FailedKillPod" => format!(
            "Container won't terminate. May need `kc delete pod {} --force --grace-period=0`.",
            pod_name
        ),
        "NodeNotReady" => format!(
            "Node is not ready. Check node status: `kc nodes`. Run `kc debug node <name>`."
        ),
        "NetworkNotReady" => format!(
            "Network plugin not ready. Run `kc debug network` for CNI diagnostics."
        ),
        "FailedSync" => format!(
            "Kubelet failed to sync pod. Check `kc describe pod {}` and node kubelet logs.",
            pod_name
        ),
        "FailedValidation" => format!(
            "Pod spec validation failed. Check `kc describe pod {}` for details.",
            pod_name
        ),
        "FailedPostStartHook" => format!(
            "PostStart hook failed. Run `kc logs {} --previous` to see logs.",
            pod_name
        ),
        "FailedPreStopHook" => format!(
            "PreStop hook failed. Check pod spec for hook definition."
        ),
        "ExceededGracePeriod" => format!(
            "Container exceeded termination grace period. Consider increasing terminationGracePeriodSeconds."
        ),
        _ => format!(
            "Run `kc describe pod {}` for full event details.",
            pod_name
        ),
    }
}
