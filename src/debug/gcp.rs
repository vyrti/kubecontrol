//! GCP GKE-specific diagnostics
//!
//! Checks for common issues specific to Google Kubernetes Engine clusters.

use k8s_openapi::api::core::v1::{Node, Pod, ServiceAccount};
use kube::{api::ListParams, Api, Client};
use crate::debug::types::{DebugCategory, DebugIssue, DebugReport, Severity};
use crate::error::KcError;

/// Run all GKE-specific diagnostics
pub async fn debug_gke(client: &Client, namespace: Option<&str>) -> Result<DebugReport, KcError> {
    let mut issues = Vec::new();

    // Run checks in parallel
    let (wi_issues, autopilot_issues, component_issues, networking_issues) = tokio::join!(
        check_workload_identity(client, namespace),
        check_autopilot_constraints(client, namespace),
        check_gke_components(client),
        check_vpc_native_networking(client),
    );

    if let Ok(wi) = wi_issues {
        issues.extend(wi);
    }
    if let Ok(ap) = autopilot_issues {
        issues.extend(ap);
    }
    if let Ok(comp) = component_issues {
        issues.extend(comp);
    }
    if let Ok(net) = networking_issues {
        issues.extend(net);
    }

    Ok(DebugReport::new("gke", issues))
}

/// Check for Workload Identity issues
pub async fn check_workload_identity(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Get ServiceAccounts to check for Workload Identity annotations
    let service_accounts: Api<ServiceAccount> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    let sa_list = service_accounts
        .list(&ListParams::default())
        .await
        .map_err(|e| KcError::Config(e.to_string()))?;

    for sa in sa_list {
        let sa_name = sa.metadata.name.clone().unwrap_or_default();
        let sa_ns = sa.metadata.namespace.clone().unwrap_or_default();
        let annotations = sa.metadata.annotations.clone().unwrap_or_default();

        // Check for GCP service account annotation
        let gcp_sa = annotations.get("iam.gke.io/gcp-service-account");

        // Skip default ServiceAccounts without workload identity
        if sa_name == "default" && gcp_sa.is_none() {
            continue;
        }

        // Check if pods are using this ServiceAccount with potential WI issues
        let pods: Api<Pod> = Api::namespaced(client.clone(), &sa_ns);
        let pod_list = pods
            .list(&ListParams::default().fields(&format!("spec.serviceAccountName={}", sa_name)))
            .await
            .map(|list| list.items)
            .unwrap_or_default();

        for pod in &pod_list {
            let pod_name = pod.metadata.name.clone().unwrap_or_default();

            // Check for WI-related issues in events
            if let Some(status) = &pod.status {
                if let Some(container_statuses) = &status.container_statuses {
                    for cs in container_statuses {
                        if let Some(state) = &cs.state {
                            if let Some(waiting) = &state.waiting {
                                if let Some(message) = &waiting.message {
                                    if message.contains("workload identity")
                                        || message.contains("metadata.google")
                                        || message.contains("gcp-service-account")
                                    {
                                        issues.push(
                                            DebugIssue::new(
                                                Severity::Critical,
                                                DebugCategory::Security,
                                                "Pod",
                                                &pod_name,
                                                "Workload Identity Issue",
                                                format!("Pod has Workload Identity configuration issues: {}", message),
                                            )
                                            .with_namespace(&sa_ns)
                                            .with_remediation(
                                                "Verify the GCP service account annotation is correct and the IAM binding exists",
                                            ),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check for missing GCP SA annotation on non-default ServiceAccounts used by pods
        if gcp_sa.is_none() && !pod_list.is_empty() && sa_name != "default" {
            issues.push(
                DebugIssue::new(
                    Severity::Info,
                    DebugCategory::Security,
                    "ServiceAccount",
                    &sa_name,
                    "No Workload Identity Configured",
                    format!("ServiceAccount '{}' is used by pods but has no Workload Identity annotation", sa_name),
                )
                .with_namespace(&sa_ns)
                .with_remediation(
                    "Consider enabling Workload Identity for better GCP service authentication",
                ),
            );
        }
    }

    Ok(issues)
}

/// Check for Autopilot mode constraints
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
pub fn is_gke(nodes: &[Node]) -> bool {
    nodes.iter().any(|node| {
        node.metadata
            .labels
            .as_ref()
            .map(|labels| {
                labels.contains_key("cloud.google.com/gke-nodepool")
                    || labels.contains_key("cloud.google.com/gke-os-distribution")
            })
            .unwrap_or(false)
    })
}

/// Check if cluster is GKE Autopilot
pub fn is_gke_autopilot(nodes: &[Node]) -> bool {
    nodes.iter().any(|node| {
        node.metadata
            .labels
            .as_ref()
            .map(|labels| labels.contains_key("cloud.google.com/gke-autopilot"))
            .unwrap_or(false)
    })
}
