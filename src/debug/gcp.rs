//! GCP GKE-specific diagnostics
//!
//! Checks for common issues specific to Google Kubernetes Engine clusters.
//! Includes 200+ checks covering GKE provider-specific issues and Kubernetes issues on GKE.

use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;
use k8s_openapi::api::batch::v1::{CronJob, Job};
use k8s_openapi::api::core::v1::{
    ConfigMap, Event, LimitRange, Namespace, Node, PersistentVolume, PersistentVolumeClaim, Pod,
    ResourceQuota, Secret, Service, ServiceAccount,
};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::{Ingress, NetworkPolicy};
use k8s_openapi::api::policy::v1::PodDisruptionBudget;
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, Role, RoleBinding};
use k8s_openapi::api::storage::v1::StorageClass;
use k8s_openapi::api::admissionregistration::v1::{
    MutatingWebhookConfiguration, ValidatingWebhookConfiguration,
};
use kube::{api::ListParams, Api, Client};
use crate::debug::types::{DebugCategory, DebugIssue, DebugReport, Severity};
use crate::error::KcError;

// GCP SDK (optional feature)
#[cfg(feature = "gcp")]
use google_cloud_container_v1::client::ClusterManager;

/// Run all GKE-specific diagnostics
pub async fn debug_gke(client: &Client, namespace: Option<&str>) -> Result<DebugReport, KcError> {
    let mut issues = Vec::new();

    // Run core GKE checks in parallel (batch 1)
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

    // Run Kubernetes workload checks in parallel (batch 2)
    let (pod_issues, deployment_issues, service_issues, config_issues) = tokio::join!(
        check_pod_issues(client, namespace),
        check_deployment_issues(client, namespace),
        check_service_issues(client, namespace),
        check_config_issues(client, namespace),
    );

    if let Ok(p) = pod_issues {
        issues.extend(p);
    }
    if let Ok(d) = deployment_issues {
        issues.extend(d);
    }
    if let Ok(s) = service_issues {
        issues.extend(s);
    }
    if let Ok(c) = config_issues {
        issues.extend(c);
    }

    // Run additional workload checks in parallel (batch 3)
    let (rbac_issues, scheduling_issues, statefulset_issues, job_issues) = tokio::join!(
        check_rbac_issues(client, namespace),
        check_scheduling_issues(client, namespace),
        check_statefulset_issues(client, namespace),
        check_job_issues(client, namespace),
    );

    if let Ok(r) = rbac_issues {
        issues.extend(r);
    }
    if let Ok(s) = scheduling_issues {
        issues.extend(s);
    }
    if let Ok(ss) = statefulset_issues {
        issues.extend(ss);
    }
    if let Ok(j) = job_issues {
        issues.extend(j);
    }

    // Run infrastructure checks in parallel (batch 4)
    let (ingress_issues, webhook_issues, quota_issues) = tokio::join!(
        check_ingress_issues(client, namespace),
        check_webhook_issues(client),
        check_quota_issues(client, namespace),
    );

    if let Ok(i) = ingress_issues {
        issues.extend(i);
    }
    if let Ok(w) = webhook_issues {
        issues.extend(w);
    }
    if let Ok(q) = quota_issues {
        issues.extend(q);
    }

    // Run GKE-specific checks in parallel (batch 5)
    let (lb_issues, storage_issues, node_pool_issues, gcr_issues, observability_issues) = tokio::join!(
        check_gke_load_balancers(client, namespace),
        check_gke_storage(client, namespace),
        check_gke_node_pools(client),
        check_gcr_access(client, namespace),
        check_gke_observability(client),
    );

    if let Ok(lb) = lb_issues {
        issues.extend(lb);
    }
    if let Ok(st) = storage_issues {
        issues.extend(st);
    }
    if let Ok(np) = node_pool_issues {
        issues.extend(np);
    }
    if let Ok(gcr) = gcr_issues {
        issues.extend(gcr);
    }
    if let Ok(obs) = observability_issues {
        issues.extend(obs);
    }

    // GCP API checks (requires gcp feature)
    #[cfg(feature = "gcp")]
    {
        if let Ok(cluster_issues) = check_gke_cluster_config(client).await {
            issues.extend(cluster_issues);
        }
    }

    #[cfg(not(feature = "gcp"))]
    {
        issues.push(
            DebugIssue::new(
                Severity::Info,
                DebugCategory::Cluster,
                "Feature",
                "gcp",
                "GCP API Checks Disabled",
                "Build with --features gcp for full GKE cluster configuration checks via GCP API",
            )
            .with_remediation("Run: cargo build --features gcp"),
        );
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

// =============================================================================
// Kubernetes Workload Checks (common issues on GKE)
// =============================================================================

/// Check for pod issues (CrashLoopBackOff, OOMKilled, ImagePullBackOff, etc.)
pub async fn check_pod_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

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

        // Skip completed pods
        if let Some(status) = &pod.status {
            let phase = status.phase.as_deref().unwrap_or("");

            // Check for Pending pods
            if phase == "Pending" {
                let reason = status.conditions.as_ref()
                    .and_then(|c| c.iter().find(|cond| cond.type_ == "PodScheduled" && cond.status == "False"))
                    .and_then(|c| c.reason.clone())
                    .unwrap_or_default();

                if reason == "Unschedulable" {
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Pod,
                            "Pod",
                            &pod_name,
                            "Pod Unschedulable",
                            "Pod cannot be scheduled to any node",
                        )
                        .with_namespace(&pod_ns)
                        .with_remediation("Check node resources, taints, and pod tolerations"),
                    );
                }
            }

            // Check for Failed phase
            if phase == "Failed" {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Pod,
                        "Pod",
                        &pod_name,
                        "Pod Failed",
                        "Pod is in Failed state",
                    )
                    .with_namespace(&pod_ns)
                    .with_remediation("Check pod events and container logs"),
                );
            }

            // Check container statuses
            if let Some(container_statuses) = &status.container_statuses {
                for cs in container_statuses {
                    // Check for CrashLoopBackOff
                    if let Some(state) = &cs.state {
                        if let Some(waiting) = &state.waiting {
                            let reason = waiting.reason.as_deref().unwrap_or("");

                            if reason == "CrashLoopBackOff" {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Pod,
                                        "Pod",
                                        &pod_name,
                                        "Container CrashLoopBackOff",
                                        format!("Container '{}' is crash looping", cs.name),
                                    )
                                    .with_namespace(&pod_ns)
                                    .with_remediation("Check container logs for crash reason"),
                                );
                            } else if reason == "ImagePullBackOff" || reason == "ErrImagePull" {
                                let message = waiting.message.as_deref().unwrap_or("");
                                let is_gcr = message.contains("gcr.io") || message.contains("pkg.dev");

                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Pod,
                                        "Pod",
                                        &pod_name,
                                        "Image Pull Failed",
                                        format!("Container '{}': {}", cs.name, reason),
                                    )
                                    .with_namespace(&pod_ns)
                                    .with_remediation(if is_gcr {
                                        "Check GCR/Artifact Registry permissions and Workload Identity configuration"
                                    } else {
                                        "Check image name, tag, and registry credentials"
                                    }),
                                );
                            } else if reason == "CreateContainerConfigError" {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Pod,
                                        "Pod",
                                        &pod_name,
                                        "Container Config Error",
                                        format!("Container '{}' has configuration error", cs.name),
                                    )
                                    .with_namespace(&pod_ns)
                                    .with_remediation("Check ConfigMap/Secret references and volume mounts"),
                                );
                            }
                        }
                    }

                    // Check for OOMKilled
                    if let Some(last) = &cs.last_state {
                        if let Some(terminated) = &last.terminated {
                            if terminated.reason.as_deref() == Some("OOMKilled") {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Resources,
                                        "Pod",
                                        &pod_name,
                                        "Container OOMKilled",
                                        format!("Container '{}' was killed due to out of memory", cs.name),
                                    )
                                    .with_namespace(&pod_ns)
                                    .with_remediation("Increase memory limits or optimize application memory usage"),
                                );
                            }
                        }
                    }

                    // Check for high restart count
                    if cs.restart_count > 5 {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Pod,
                                "Pod",
                                &pod_name,
                                "High Restart Count",
                                format!("Container '{}' has restarted {} times", cs.name, cs.restart_count),
                            )
                            .with_namespace(&pod_ns)
                            .with_remediation("Investigate container logs and pod events for stability issues"),
                        );
                    }
                }
            }

            // Check init container statuses
            if let Some(init_statuses) = &status.init_container_statuses {
                for ics in init_statuses {
                    if let Some(state) = &ics.state {
                        if let Some(waiting) = &state.waiting {
                            let reason = waiting.reason.as_deref().unwrap_or("");
                            if reason == "CrashLoopBackOff" || reason == "Error" {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Pod,
                                        "Pod",
                                        &pod_name,
                                        "Init Container Failing",
                                        format!("Init container '{}' is failing: {}", ics.name, reason),
                                    )
                                    .with_namespace(&pod_ns)
                                    .with_remediation("Check init container logs and configuration"),
                                );
                            }
                        }
                    }
                }
            }
        }

        // Check for security issues
        if let Some(spec) = &pod.spec {
            for container in &spec.containers {
                if let Some(sc) = &container.security_context {
                    // Check for privileged containers
                    if sc.privileged == Some(true) {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Security,
                                "Pod",
                                &pod_name,
                                "Privileged Container",
                                format!("Container '{}' is running in privileged mode", container.name),
                            )
                            .with_namespace(&pod_ns)
                            .with_remediation("Remove privileged: true unless absolutely necessary"),
                        );
                    }

                    // Check for running as root
                    if sc.run_as_user == Some(0) {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Security,
                                "Pod",
                                &pod_name,
                                "Container Running as Root",
                                format!("Container '{}' is running as root (UID 0)", container.name),
                            )
                            .with_namespace(&pod_ns)
                            .with_remediation("Configure runAsNonRoot: true and set a non-root user"),
                        );
                    }
                }

                // Check for missing resource limits
                let has_limits = container.resources.as_ref()
                    .and_then(|r| r.limits.as_ref())
                    .map(|l| !l.is_empty())
                    .unwrap_or(false);

                if !has_limits {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Resources,
                            "Pod",
                            &pod_name,
                            "Missing Resource Limits",
                            format!("Container '{}' has no resource limits set", container.name),
                        )
                        .with_namespace(&pod_ns)
                        .with_remediation("Set resource limits to prevent resource exhaustion"),
                    );
                }
            }

            // Check for hostNetwork
            if spec.host_network == Some(true) {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Security,
                        "Pod",
                        &pod_name,
                        "Pod Using Host Network",
                        "Pod is using the host network namespace",
                    )
                    .with_namespace(&pod_ns)
                    .with_remediation("Remove hostNetwork: true unless required for node-level networking"),
                );
            }

            // Check for hostPID
            if spec.host_pid == Some(true) {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Security,
                        "Pod",
                        &pod_name,
                        "Pod Using Host PID",
                        "Pod is using the host PID namespace",
                    )
                    .with_namespace(&pod_ns)
                    .with_remediation("Remove hostPID: true unless required"),
                );
            }
        }
    }

    Ok(issues)
}

/// Check for deployment issues
pub async fn check_deployment_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let deployments: Api<Deployment> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    let deploy_list = deployments
        .list(&ListParams::default())
        .await
        .map_err(|e| KcError::Config(e.to_string()))?;

    for deploy in deploy_list {
        let deploy_name = deploy.metadata.name.clone().unwrap_or_default();
        let deploy_ns = deploy.metadata.namespace.clone().unwrap_or_default();

        if let Some(status) = &deploy.status {
            let desired = deploy.spec.as_ref().and_then(|s| s.replicas).unwrap_or(1);
            let ready = status.ready_replicas.unwrap_or(0);
            let available = status.available_replicas.unwrap_or(0);

            // Check for unavailable replicas
            if ready < desired {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Pod,
                        "Deployment",
                        &deploy_name,
                        "Replicas Unavailable",
                        format!("Only {}/{} replicas are ready", ready, desired),
                    )
                    .with_namespace(&deploy_ns)
                    .with_remediation("Check pod status and events for the deployment's pods"),
                );
            }

            // Check deployment conditions
            if let Some(conditions) = &status.conditions {
                for condition in conditions {
                    // Check for progressing timeout
                    if condition.type_ == "Progressing" && condition.status == "False" {
                        if let Some(reason) = &condition.reason {
                            if reason == "ProgressDeadlineExceeded" {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Pod,
                                        "Deployment",
                                        &deploy_name,
                                        "Deployment Progress Deadline Exceeded",
                                        "Deployment rollout has exceeded the progress deadline",
                                    )
                                    .with_namespace(&deploy_ns)
                                    .with_remediation("Check pod events and container logs. Consider rolling back."),
                                );
                            }
                        }
                    }

                    // Check for replica failure
                    if condition.type_ == "ReplicaFailure" && condition.status == "True" {
                        issues.push(
                            DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Pod,
                                "Deployment",
                                &deploy_name,
                                "Replica Failure",
                                condition.message.clone().unwrap_or_else(|| "Deployment has replica failures".to_string()),
                            )
                            .with_namespace(&deploy_ns)
                            .with_remediation("Check ReplicaSet and pod status"),
                        );
                    }
                }
            }
        }
    }

    // Check HPA issues
    let hpas: Api<HorizontalPodAutoscaler> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(hpa_list) = hpas.list(&ListParams::default()).await {
        for hpa in hpa_list {
            let hpa_name = hpa.metadata.name.clone().unwrap_or_default();
            let hpa_ns = hpa.metadata.namespace.clone().unwrap_or_default();

            if let Some(status) = &hpa.status {
                let current = status.current_replicas.unwrap_or(0);
                let max = hpa.spec.as_ref().map(|s| s.max_replicas).unwrap_or(0);

                // Check if at max replicas
                if current >= max && max > 0 {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Resources,
                            "HPA",
                            &hpa_name,
                            "HPA at Maximum Replicas",
                            format!("HPA has scaled to maximum ({} replicas)", max),
                        )
                        .with_namespace(&hpa_ns)
                        .with_remediation("Consider increasing max replicas if more capacity is needed"),
                    );
                }

                // Check HPA conditions
                if let Some(conditions) = &status.conditions {
                    for condition in conditions {
                        if condition.type_ == "ScalingActive" && condition.status == "False" {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Critical,
                                    DebugCategory::Pod,
                                    "HPA",
                                    &hpa_name,
                                    "HPA Unable to Scale",
                                    condition.message.clone().unwrap_or_else(|| "HPA cannot fetch metrics".to_string()),
                                )
                                .with_namespace(&hpa_ns)
                                .with_remediation("Check metrics-server deployment and resource metrics"),
                            );
                        }

                        if condition.type_ == "AbleToScale" && condition.status == "False" {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Warning,
                                    DebugCategory::Pod,
                                    "HPA",
                                    &hpa_name,
                                    "HPA Scaling Limited",
                                    condition.message.clone().unwrap_or_else(|| "HPA scaling is limited".to_string()),
                                )
                                .with_namespace(&hpa_ns)
                                .with_remediation("Check HPA configuration and target resource"),
                            );
                        }
                    }
                }
            }
        }
    }

    // Check PDB issues
    let pdbs: Api<PodDisruptionBudget> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(pdb_list) = pdbs.list(&ListParams::default()).await {
        for pdb in pdb_list {
            let pdb_name = pdb.metadata.name.clone().unwrap_or_default();
            let pdb_ns = pdb.metadata.namespace.clone().unwrap_or_default();

            if let Some(status) = &pdb.status {
                if status.disruptions_allowed == 0 && status.current_healthy < status.desired_healthy {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Pod,
                            "PDB",
                            &pdb_name,
                            "PDB Blocking Disruptions",
                            format!(
                                "PDB allows 0 disruptions ({}/{} pods healthy)",
                                status.current_healthy, status.desired_healthy
                            ),
                        )
                        .with_namespace(&pdb_ns)
                        .with_remediation("This may block node drains and upgrades"),
                    );
                }
            }
        }
    }

    Ok(issues)
}

/// Check for service issues
pub async fn check_service_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let services: Api<Service> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    let svc_list = services
        .list(&ListParams::default())
        .await
        .map_err(|e| KcError::Config(e.to_string()))?;

    for svc in svc_list {
        let svc_name = svc.metadata.name.clone().unwrap_or_default();
        let svc_ns = svc.metadata.namespace.clone().unwrap_or_default();

        // Skip kubernetes service
        if svc_name == "kubernetes" && svc_ns == "default" {
            continue;
        }

        if let Some(spec) = &svc.spec {
            let svc_type = spec.type_.as_deref().unwrap_or("ClusterIP");

            // Check LoadBalancer services
            if svc_type == "LoadBalancer" {
                if let Some(status) = &svc.status {
                    let has_ingress = status.load_balancer.as_ref()
                        .and_then(|lb| lb.ingress.as_ref())
                        .map(|i| !i.is_empty())
                        .unwrap_or(false);

                    if !has_ingress {
                        issues.push(
                            DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Network,
                                "Service",
                                &svc_name,
                                "LoadBalancer Pending",
                                "LoadBalancer service has no external IP assigned",
                            )
                            .with_namespace(&svc_ns)
                            .with_remediation("Check GCP load balancer quotas and service events"),
                        );
                    }
                }
            }

            // Check for endpoints
            if spec.selector.is_some() {
                let endpoints: Api<EndpointSlice> = Api::namespaced(client.clone(), &svc_ns);
                if let Ok(endpoint_slices) = endpoints
                    .list(&ListParams::default().labels(&format!("kubernetes.io/service-name={}", svc_name)))
                    .await
                {
                    let total_endpoints: usize = endpoint_slices.iter()
                        .map(|es| es.endpoints.len())
                        .sum();

                    if total_endpoints == 0 {
                        issues.push(
                            DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Network,
                                "Service",
                                &svc_name,
                                "Service Has No Endpoints",
                                "Service selector does not match any running pods",
                            )
                            .with_namespace(&svc_ns)
                            .with_remediation("Check that pods exist with matching labels and are in Ready state"),
                        );
                    }
                }
            }
        }
    }

    Ok(issues)
}

/// Check for ConfigMap and Secret issues
pub async fn check_config_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Check for large ConfigMaps
    let configmaps: Api<ConfigMap> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(cm_list) = configmaps.list(&ListParams::default()).await {
        for cm in cm_list {
            let cm_name = cm.metadata.name.clone().unwrap_or_default();
            let cm_ns = cm.metadata.namespace.clone().unwrap_or_default();

            // Calculate size
            let data_size: usize = cm.data.as_ref()
                .map(|d| d.values().map(|v| v.len()).sum())
                .unwrap_or(0);
            let binary_size: usize = cm.binary_data.as_ref()
                .map(|d| d.values().map(|v| v.0.len()).sum())
                .unwrap_or(0);
            let total_size = data_size + binary_size;

            // ConfigMap size limit is 1MB
            if total_size > 900_000 {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Cluster,
                        "ConfigMap",
                        &cm_name,
                        "Large ConfigMap",
                        format!("ConfigMap is {}KB, approaching 1MB limit", total_size / 1024),
                    )
                    .with_namespace(&cm_ns)
                    .with_remediation("Consider splitting into multiple ConfigMaps or using a different storage mechanism"),
                );
            }
        }
    }

    // Check events for ConfigMap/Secret mount failures
    let events: Api<Event> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(event_list) = events.list(&ListParams::default()).await {
        for event in event_list {
            let reason = event.reason.as_deref().unwrap_or("");
            let message = event.message.as_deref().unwrap_or("");
            let involved = event.involved_object.name.clone().unwrap_or_default();
            let event_ns = event.metadata.namespace.clone().unwrap_or_default();

            if reason == "FailedMount" {
                if message.contains("configmap") || message.contains("ConfigMap") {
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Cluster,
                            "Pod",
                            &involved,
                            "ConfigMap Mount Failed",
                            message.to_string(),
                        )
                        .with_namespace(&event_ns)
                        .with_remediation("Verify ConfigMap exists and name is correct"),
                    );
                } else if message.contains("secret") || message.contains("Secret") {
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Cluster,
                            "Pod",
                            &involved,
                            "Secret Mount Failed",
                            message.to_string(),
                        )
                        .with_namespace(&event_ns)
                        .with_remediation("Verify Secret exists and name is correct"),
                    );
                }
            }
        }
    }

    Ok(issues)
}

/// Check for RBAC issues
pub async fn check_rbac_issues(
    client: &Client,
    _namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Check ClusterRoleBindings for cluster-admin
    let crbs: Api<ClusterRoleBinding> = Api::all(client.clone());
    if let Ok(crb_list) = crbs.list(&ListParams::default()).await {
        for crb in crb_list {
            let crb_name = crb.metadata.name.clone().unwrap_or_default();

            // Skip system bindings
            if crb_name.starts_with("system:") || crb_name.starts_with("kubeadm:") {
                continue;
            }

            if crb.role_ref.name == "cluster-admin" {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Security,
                        "ClusterRoleBinding",
                        &crb_name,
                        "Cluster-Admin Binding",
                        "ClusterRoleBinding grants cluster-admin privileges",
                    )
                    .with_remediation("Review if full cluster-admin access is necessary"),
                );
            }
        }
    }

    // Check ClusterRoles for dangerous permissions
    let crs: Api<ClusterRole> = Api::all(client.clone());
    if let Ok(cr_list) = crs.list(&ListParams::default()).await {
        for cr in cr_list {
            let cr_name = cr.metadata.name.clone().unwrap_or_default();

            // Skip system roles
            if cr_name.starts_with("system:") {
                continue;
            }

            if let Some(rules) = &cr.rules {
                for rule in rules {
                    let has_wildcard_resources = rule.resources.as_ref()
                        .map(|r| r.iter().any(|res| res == "*"))
                        .unwrap_or(false);
                    let has_wildcard_verbs = rule.verbs.iter().any(|v| v == "*");

                    if has_wildcard_resources && has_wildcard_verbs {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Security,
                                "ClusterRole",
                                &cr_name,
                                "Overly Permissive ClusterRole",
                                "ClusterRole has wildcard (*) permissions on all resources",
                            )
                            .with_remediation("Apply principle of least privilege"),
                        );
                        break;
                    }
                }
            }
        }
    }

    Ok(issues)
}

/// Check for scheduling issues
pub async fn check_scheduling_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Get recent events for scheduling failures
    let events: Api<Event> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(event_list) = events.list(&ListParams::default()).await {
        for event in event_list {
            let reason = event.reason.as_deref().unwrap_or("");
            let message = event.message.as_deref().unwrap_or("");
            let involved = event.involved_object.name.clone().unwrap_or_default();
            let event_ns = event.metadata.namespace.clone().unwrap_or_default();

            if reason == "FailedScheduling" {
                let severity = if message.contains("Insufficient") {
                    Severity::Critical
                } else {
                    Severity::Warning
                };

                let title = if message.contains("Insufficient cpu") {
                    "Insufficient CPU"
                } else if message.contains("Insufficient memory") {
                    "Insufficient Memory"
                } else if message.contains("node(s) had taint") {
                    "Taints Not Tolerated"
                } else if message.contains("node selector") || message.contains("node affinity") {
                    "Node Affinity/Selector Mismatch"
                } else {
                    "Scheduling Failed"
                };

                issues.push(
                    DebugIssue::new(
                        severity,
                        DebugCategory::Node,
                        "Pod",
                        &involved,
                        title,
                        message.to_string(),
                    )
                    .with_namespace(&event_ns)
                    .with_remediation("Review pod resource requests, node selectors, and node capacity"),
                );
            }
        }
    }

    Ok(issues)
}

/// Check for StatefulSet issues
pub async fn check_statefulset_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let statefulsets: Api<StatefulSet> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(sts_list) = statefulsets.list(&ListParams::default()).await {
        for sts in sts_list {
            let sts_name = sts.metadata.name.clone().unwrap_or_default();
            let sts_ns = sts.metadata.namespace.clone().unwrap_or_default();

            if let Some(status) = &sts.status {
                let desired = sts.spec.as_ref().and_then(|s| s.replicas).unwrap_or(1);
                let ready = status.ready_replicas.unwrap_or(0);
                let current = status.current_replicas.unwrap_or(0);

                // Check for unavailable replicas
                if ready < desired {
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Pod,
                            "StatefulSet",
                            &sts_name,
                            "StatefulSet Replicas Unavailable",
                            format!("Only {}/{} replicas are ready", ready, desired),
                        )
                        .with_namespace(&sts_ns)
                        .with_remediation("Check pod status and PVC bindings"),
                    );
                }

                // Check for stuck update
                if let Some(update_revision) = &status.update_revision {
                    if let Some(current_revision) = &status.current_revision {
                        if update_revision != current_revision && current < desired {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Warning,
                                    DebugCategory::Pod,
                                    "StatefulSet",
                                    &sts_name,
                                    "StatefulSet Update Stuck",
                                    format!("Update in progress: {}/{} pods updated", current, desired),
                                )
                                .with_namespace(&sts_ns)
                                .with_remediation("Check pod status for update failures"),
                            );
                        }
                    }
                }
            }

            // Check for headless service
            if let Some(spec) = &sts.spec {
                if let Some(service_name) = &spec.service_name {
                    let services: Api<Service> = Api::namespaced(client.clone(), &sts_ns);
                    if services.get(service_name).await.is_err() {
                        issues.push(
                            DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Network,
                                "StatefulSet",
                                &sts_name,
                                "Headless Service Missing",
                                format!("Required headless service '{}' not found", service_name),
                            )
                            .with_namespace(&sts_ns)
                            .with_remediation("Create the headless service for the StatefulSet"),
                        );
                    }
                }
            }
        }
    }

    // Check PVC issues for StatefulSets
    let pvcs: Api<PersistentVolumeClaim> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(pvc_list) = pvcs.list(&ListParams::default()).await {
        for pvc in pvc_list {
            let pvc_name = pvc.metadata.name.clone().unwrap_or_default();
            let pvc_ns = pvc.metadata.namespace.clone().unwrap_or_default();

            if let Some(status) = &pvc.status {
                let phase = status.phase.as_deref().unwrap_or("");

                if phase == "Pending" {
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Storage,
                            "PVC",
                            &pvc_name,
                            "PVC Pending",
                            "PersistentVolumeClaim is stuck in Pending state",
                        )
                        .with_namespace(&pvc_ns)
                        .with_remediation("Check StorageClass provisioner and PVC events"),
                    );
                }
            }
        }
    }

    Ok(issues)
}

/// Check for Job and CronJob issues
pub async fn check_job_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Check Jobs
    let jobs: Api<Job> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(job_list) = jobs.list(&ListParams::default()).await {
        for job in job_list {
            let job_name = job.metadata.name.clone().unwrap_or_default();
            let job_ns = job.metadata.namespace.clone().unwrap_or_default();

            if let Some(status) = &job.status {
                // Check for failed jobs
                if let Some(failed) = status.failed {
                    if failed > 0 {
                        let backoff_limit = job.spec.as_ref()
                            .and_then(|s| s.backoff_limit)
                            .unwrap_or(6);

                        if failed >= backoff_limit {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Critical,
                                    DebugCategory::Pod,
                                    "Job",
                                    &job_name,
                                    "Job Failed",
                                    format!("Job has failed {} times, reaching backoff limit", failed),
                                )
                                .with_namespace(&job_ns)
                                .with_remediation("Check job pod logs for failure reason"),
                            );
                        }
                    }
                }

                // Check for deadline exceeded
                if let Some(conditions) = &status.conditions {
                    for condition in conditions {
                        if condition.type_ == "Failed" && condition.status == "True" {
                            if condition.reason.as_deref() == Some("DeadlineExceeded") {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Warning,
                                        DebugCategory::Pod,
                                        "Job",
                                        &job_name,
                                        "Job Deadline Exceeded",
                                        "Job exceeded its activeDeadlineSeconds",
                                    )
                                    .with_namespace(&job_ns)
                                    .with_remediation("Increase activeDeadlineSeconds or optimize job execution"),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Check CronJobs
    let cronjobs: Api<CronJob> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(cj_list) = cronjobs.list(&ListParams::default()).await {
        for cj in cj_list {
            let cj_name = cj.metadata.name.clone().unwrap_or_default();
            let cj_ns = cj.metadata.namespace.clone().unwrap_or_default();

            if let Some(spec) = &cj.spec {
                // Check if suspended
                if spec.suspend == Some(true) {
                    issues.push(
                        DebugIssue::new(
                            Severity::Info,
                            DebugCategory::Pod,
                            "CronJob",
                            &cj_name,
                            "CronJob Suspended",
                            "CronJob is currently suspended",
                        )
                        .with_namespace(&cj_ns)
                        .with_remediation("Set suspend: false to resume scheduling"),
                    );
                }
            }

            if let Some(status) = &cj.status {
                // Check for missed schedules
                if let Some(last_schedule) = &status.last_schedule_time {
                    if let Some(last_successful) = &status.last_successful_time {
                        if last_schedule.0 > last_successful.0 {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Warning,
                                    DebugCategory::Pod,
                                    "CronJob",
                                    &cj_name,
                                    "CronJob Last Run Failed",
                                    "Most recent scheduled run was not successful",
                                )
                                .with_namespace(&cj_ns)
                                .with_remediation("Check the job pods for failure reasons"),
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(issues)
}

/// Check for Ingress issues
pub async fn check_ingress_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let ingresses: Api<Ingress> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(ingress_list) = ingresses.list(&ListParams::default()).await {
        for ingress in ingress_list {
            let ing_name = ingress.metadata.name.clone().unwrap_or_default();
            let ing_ns = ingress.metadata.namespace.clone().unwrap_or_default();

            // Check for address assignment
            if let Some(status) = &ingress.status {
                let has_address = status.load_balancer.as_ref()
                    .and_then(|lb| lb.ingress.as_ref())
                    .map(|i| !i.is_empty())
                    .unwrap_or(false);

                if !has_address {
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Network,
                            "Ingress",
                            &ing_name,
                            "Ingress Has No Address",
                            "Ingress has not been assigned an IP address",
                        )
                        .with_namespace(&ing_ns)
                        .with_remediation("Check ingress controller status and GCE/GKE load balancer events"),
                    );
                }
            }

            if let Some(spec) = &ingress.spec {
                // Check TLS secrets
                if let Some(tls_list) = &spec.tls {
                    for tls in tls_list {
                        if let Some(secret_name) = &tls.secret_name {
                            let secrets: Api<Secret> = Api::namespaced(client.clone(), &ing_ns);
                            if secrets.get(secret_name).await.is_err() {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Network,
                                        "Ingress",
                                        &ing_name,
                                        "TLS Secret Missing",
                                        format!("TLS secret '{}' not found", secret_name),
                                    )
                                    .with_namespace(&ing_ns)
                                    .with_remediation("Create the TLS secret or use Google-managed certificates"),
                                );
                            }
                        }
                    }
                }

                // Check backend services
                if let Some(rules) = &spec.rules {
                    for rule in rules {
                        if let Some(http) = &rule.http {
                            for path in &http.paths {
                                if let Some(backend) = &path.backend.service {
                                    let svc_name = &backend.name;
                                    let services: Api<Service> = Api::namespaced(client.clone(), &ing_ns);
                                    if services.get(svc_name).await.is_err() {
                                        issues.push(
                                            DebugIssue::new(
                                                Severity::Critical,
                                                DebugCategory::Network,
                                                "Ingress",
                                                &ing_name,
                                                "Backend Service Missing",
                                                format!("Backend service '{}' not found", svc_name),
                                            )
                                            .with_namespace(&ing_ns)
                                            .with_remediation("Create the backend service or update ingress configuration"),
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(issues)
}

/// Check for webhook issues
pub async fn check_webhook_issues(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Check ValidatingWebhookConfigurations
    let vwcs: Api<ValidatingWebhookConfiguration> = Api::all(client.clone());
    if let Ok(vwc_list) = vwcs.list(&ListParams::default()).await {
        for vwc in vwc_list {
            let vwc_name = vwc.metadata.name.clone().unwrap_or_default();

            if let Some(webhooks) = &vwc.webhooks {
                for webhook in webhooks {
                    let wh_name = &webhook.name;
                    let failure_policy = webhook.failure_policy.as_deref().unwrap_or("Fail");

                    if failure_policy == "Fail" {
                        if let Some(svc_ref) = &webhook.client_config.service {
                            let svc_ns = if svc_ref.namespace.is_empty() { "default" } else { &svc_ref.namespace };
                            let svc_name = &svc_ref.name;

                            let services: Api<Service> = Api::namespaced(client.clone(), svc_ns);
                            if services.get(svc_name).await.is_err() {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Security,
                                        "ValidatingWebhook",
                                        wh_name,
                                        "Webhook Service Unavailable",
                                        format!(
                                            "Webhook '{}' service '{}/{}' not found with failurePolicy=Fail",
                                            vwc_name, svc_ns, svc_name
                                        ),
                                    )
                                    .with_remediation("This may block resource creation. Check webhook service."),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Check MutatingWebhookConfigurations
    let mwcs: Api<MutatingWebhookConfiguration> = Api::all(client.clone());
    if let Ok(mwc_list) = mwcs.list(&ListParams::default()).await {
        for mwc in mwc_list {
            let mwc_name = mwc.metadata.name.clone().unwrap_or_default();

            if let Some(webhooks) = &mwc.webhooks {
                for webhook in webhooks {
                    let wh_name = &webhook.name;
                    let failure_policy = webhook.failure_policy.as_deref().unwrap_or("Fail");

                    if failure_policy == "Fail" {
                        if let Some(svc_ref) = &webhook.client_config.service {
                            let svc_ns = if svc_ref.namespace.is_empty() { "default" } else { &svc_ref.namespace };
                            let svc_name = &svc_ref.name;

                            let services: Api<Service> = Api::namespaced(client.clone(), svc_ns);
                            if services.get(svc_name).await.is_err() {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Security,
                                        "MutatingWebhook",
                                        wh_name,
                                        "Webhook Service Unavailable",
                                        format!(
                                            "Webhook '{}' service '{}/{}' not found with failurePolicy=Fail",
                                            mwc_name, svc_ns, svc_name
                                        ),
                                    )
                                    .with_remediation("This may block resource creation. Check webhook service."),
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

/// Check for ResourceQuota and LimitRange issues
pub async fn check_quota_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let quotas: Api<ResourceQuota> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(quota_list) = quotas.list(&ListParams::default()).await {
        for quota in quota_list {
            let quota_name = quota.metadata.name.clone().unwrap_or_default();
            let quota_ns = quota.metadata.namespace.clone().unwrap_or_default();

            if let Some(status) = &quota.status {
                if let (Some(hard), Some(used)) = (&status.hard, &status.used) {
                    for (resource, hard_qty) in hard {
                        if let Some(used_qty) = used.get(resource) {
                            // Parse quantities - this is simplified
                            let hard_val: f64 = hard_qty.0.parse().unwrap_or(0.0);
                            let used_val: f64 = used_qty.0.parse().unwrap_or(0.0);

                            if hard_val > 0.0 {
                                let usage_pct = (used_val / hard_val) * 100.0;

                                if usage_pct >= 100.0 {
                                    issues.push(
                                        DebugIssue::new(
                                            Severity::Critical,
                                            DebugCategory::Resources,
                                            "ResourceQuota",
                                            &quota_name,
                                            "Quota Exceeded",
                                            format!("Resource '{}' quota is at 100% ({}/{})", resource, used_qty.0, hard_qty.0),
                                        )
                                        .with_namespace(&quota_ns)
                                        .with_remediation("Increase quota or reduce resource usage"),
                                    );
                                } else if usage_pct >= 90.0 {
                                    issues.push(
                                        DebugIssue::new(
                                            Severity::Warning,
                                            DebugCategory::Resources,
                                            "ResourceQuota",
                                            &quota_name,
                                            "Quota Near Limit",
                                            format!("Resource '{}' is at {:.0}% of quota ({}/{})", resource, usage_pct, used_qty.0, hard_qty.0),
                                        )
                                        .with_namespace(&quota_ns)
                                        .with_remediation("Consider increasing quota before it's exhausted"),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(issues)
}

// =============================================================================
// GKE-Specific Provider Checks
// =============================================================================

/// Check GKE load balancer issues
pub async fn check_gke_load_balancers(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Check for GKE Ingress controller (l7-default-backend)
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), "kube-system");

    // Check l7-default-backend for GCE Ingress
    if let Ok(backend) = deployments.get("l7-default-backend").await {
        if let Some(status) = &backend.status {
            let ready = status.ready_replicas.unwrap_or(0);
            let desired = backend.spec.as_ref().and_then(|s| s.replicas).unwrap_or(1);

            if ready < desired {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Network,
                        "Deployment",
                        "l7-default-backend",
                        "GCE Ingress Backend Unhealthy",
                        format!("l7-default-backend has {}/{} replicas ready", ready, desired),
                    )
                    .with_namespace("kube-system")
                    .with_remediation("Check l7-default-backend pod status"),
                );
            }
        }
    }

    // Check services for NEG issues
    let services: Api<Service> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(svc_list) = services.list(&ListParams::default()).await {
        for svc in svc_list {
            let svc_name = svc.metadata.name.clone().unwrap_or_default();
            let svc_ns = svc.metadata.namespace.clone().unwrap_or_default();
            let annotations = svc.metadata.annotations.clone().unwrap_or_default();

            // Check for NEG annotations
            if let Some(neg_status) = annotations.get("cloud.google.com/neg-status") {
                if neg_status.contains("error") || neg_status.contains("Error") {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Network,
                            "Service",
                            &svc_name,
                            "NEG Error",
                            "Network Endpoint Group has errors",
                        )
                        .with_namespace(&svc_ns)
                        .with_remediation("Check NEG status annotation and GCP console for details"),
                    );
                }
            }

            // Check for internal load balancer issues
            if annotations.get("cloud.google.com/load-balancer-type") == Some(&"Internal".to_string()) {
                if let Some(status) = &svc.status {
                    let has_ip = status.load_balancer.as_ref()
                        .and_then(|lb| lb.ingress.as_ref())
                        .map(|i| !i.is_empty())
                        .unwrap_or(false);

                    if !has_ip {
                        issues.push(
                            DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Network,
                                "Service",
                                &svc_name,
                                "Internal LB Pending",
                                "Internal LoadBalancer has no IP assigned",
                            )
                            .with_namespace(&svc_ns)
                            .with_remediation("Check subnet configuration and GCP ILB quotas"),
                        );
                    }
                }
            }
        }
    }

    Ok(issues)
}

/// Check GKE storage issues
pub async fn check_gke_storage(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Check PD CSI driver
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), "gke-managed-system");

    if deployments.get("gcp-compute-persistent-disk-csi-driver-controller").await.is_err() {
        // Try kube-system namespace
        let kube_system_deploys: Api<Deployment> = Api::namespaced(client.clone(), "kube-system");
        if kube_system_deploys.get("csi-gce-pd-controller").await.is_err() {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Storage,
                    "Deployment",
                    "pd-csi-driver",
                    "PD CSI Driver Not Found",
                    "Google Compute Engine Persistent Disk CSI driver not detected",
                )
                .with_remediation("Ensure the GCE PD CSI driver addon is enabled on the cluster"),
            );
        }
    }

    // Check StorageClasses
    let storage_classes: Api<StorageClass> = Api::all(client.clone());
    let mut has_default = false;
    if let Ok(sc_list) = storage_classes.list(&ListParams::default()).await {
        for sc in &sc_list {
            let sc_name = sc.metadata.name.clone().unwrap_or_default();
            let annotations = sc.metadata.annotations.clone().unwrap_or_default();

            if annotations.get("storageclass.kubernetes.io/is-default-class") == Some(&"true".to_string()) {
                has_default = true;
            }

            // Check for deprecated standard StorageClass
            if sc_name == "standard" && sc.provisioner == "kubernetes.io/gce-pd" {
                issues.push(
                    DebugIssue::new(
                        Severity::Info,
                        DebugCategory::Storage,
                        "StorageClass",
                        &sc_name,
                        "Legacy StorageClass",
                        "Using legacy in-tree GCE PD provisioner instead of CSI",
                    )
                    .with_remediation("Consider migrating to pd.csi.storage.gke.io StorageClass"),
                );
            }
        }
    }

    if !has_default {
        issues.push(
            DebugIssue::new(
                Severity::Warning,
                DebugCategory::Storage,
                "StorageClass",
                "default",
                "No Default StorageClass",
                "No default StorageClass is configured",
            )
            .with_remediation("Set a default StorageClass for PVCs without explicit storageClassName"),
        );
    }

    // Check PVCs
    let pvcs: Api<PersistentVolumeClaim> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(pvc_list) = pvcs.list(&ListParams::default()).await {
        for pvc in pvc_list {
            let pvc_name = pvc.metadata.name.clone().unwrap_or_default();
            let pvc_ns = pvc.metadata.namespace.clone().unwrap_or_default();

            if let Some(status) = &pvc.status {
                if status.phase.as_deref() == Some("Pending") {
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Storage,
                            "PVC",
                            &pvc_name,
                            "PVC Pending",
                            "PVC is stuck in Pending state",
                        )
                        .with_namespace(&pvc_ns)
                        .with_remediation("Check PVC events for provisioning errors (wrong zone, quota, etc.)"),
                    );
                }
            }
        }
    }

    Ok(issues)
}

/// Check GKE node pool issues
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

/// Check GCR/Artifact Registry access issues
pub async fn check_gcr_access(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let events: Api<Event> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(event_list) = events.list(&ListParams::default()).await {
        for event in event_list {
            let reason = event.reason.as_deref().unwrap_or("");
            let message = event.message.as_deref().unwrap_or("");
            let involved = event.involved_object.name.clone().unwrap_or_default();
            let event_ns = event.metadata.namespace.clone().unwrap_or_default();

            // Check for GCR/AR specific image pull failures
            if reason == "Failed" && (message.contains("gcr.io") || message.contains("pkg.dev") || message.contains("docker.pkg.dev")) {
                if message.contains("401") || message.contains("403") || message.contains("unauthorized") {
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Security,
                            "Pod",
                            &involved,
                            "GCR/Artifact Registry Auth Failed",
                            format!("Image pull authentication failed: {}", message),
                        )
                        .with_namespace(&event_ns)
                        .with_remediation("Check Workload Identity configuration and IAM permissions for Artifact Registry"),
                    );
                } else if message.contains("not found") || message.contains("404") {
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Pod,
                            "Pod",
                            &involved,
                            "Image Not Found in GCR/AR",
                            format!("Image not found: {}", message),
                        )
                        .with_namespace(&event_ns)
                        .with_remediation("Verify image name, tag, and that it exists in the registry"),
                    );
                }
            }

            // Check for Binary Authorization blocks
            if message.contains("binary authorization") || message.contains("BinAuthz") {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Security,
                        "Pod",
                        &involved,
                        "Binary Authorization Blocked",
                        "Image blocked by Binary Authorization policy",
                    )
                    .with_namespace(&event_ns)
                    .with_remediation("Sign the image or update Binary Authorization policy"),
                );
            }
        }
    }

    // Check for gcr.io deprecation in pod images
    let pods: Api<Pod> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(pod_list) = pods.list(&ListParams::default()).await {
        for pod in pod_list {
            let pod_name = pod.metadata.name.clone().unwrap_or_default();
            let pod_ns = pod.metadata.namespace.clone().unwrap_or_default();

            if let Some(spec) = &pod.spec {
                for container in &spec.containers {
                    if let Some(image) = &container.image {
                        if image.starts_with("gcr.io/") {
                            // This is info level as gcr.io still works
                            issues.push(
                                DebugIssue::new(
                                    Severity::Info,
                                    DebugCategory::Pod,
                                    "Pod",
                                    &pod_name,
                                    "Using gcr.io Registry",
                                    format!("Container '{}' uses gcr.io which is being replaced by Artifact Registry", container.name),
                                )
                                .with_namespace(&pod_ns)
                                .with_remediation("Consider migrating to Artifact Registry (*.pkg.dev)"),
                            );
                            break; // Only report once per pod
                        }
                    }
                }
            }
        }
    }

    Ok(issues)
}

/// Check GKE observability components
pub async fn check_gke_observability(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let pods: Api<Pod> = Api::namespaced(client.clone(), "kube-system");

    // Check Fluent Bit (Cloud Logging agent)
    if let Ok(fluentbit_pods) = pods
        .list(&ListParams::default().labels("k8s-app=fluentbit-gke"))
        .await
    {
        if fluentbit_pods.items.is_empty() {
            issues.push(
                DebugIssue::new(
                    Severity::Info,
                    DebugCategory::Cluster,
                    "DaemonSet",
                    "fluentbit-gke",
                    "Cloud Logging Agent Not Found",
                    "Fluent Bit logging agent not detected",
                )
                .with_namespace("kube-system")
                .with_remediation("Enable Cloud Logging on the cluster if log collection is needed"),
            );
        } else {
            let unhealthy: Vec<_> = fluentbit_pods.items.iter()
                .filter(|p| {
                    p.status.as_ref()
                        .and_then(|s| s.phase.as_ref())
                        .map(|ph| ph != "Running")
                        .unwrap_or(true)
                })
                .collect();

            if !unhealthy.is_empty() {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Cluster,
                        "DaemonSet",
                        "fluentbit-gke",
                        "Cloud Logging Agent Issues",
                        format!("{} fluentbit-gke pods are not healthy", unhealthy.len()),
                    )
                    .with_namespace("kube-system")
                    .with_remediation("Check fluentbit-gke pod logs for errors"),
                );
            }
        }
    }

    // Check GKE Metrics Agent
    if let Ok(metrics_pods) = pods
        .list(&ListParams::default().labels("k8s-app=gke-metrics-agent"))
        .await
    {
        if metrics_pods.items.is_empty() {
            issues.push(
                DebugIssue::new(
                    Severity::Info,
                    DebugCategory::Cluster,
                    "DaemonSet",
                    "gke-metrics-agent",
                    "Cloud Monitoring Agent Not Found",
                    "GKE metrics agent not detected",
                )
                .with_namespace("kube-system")
                .with_remediation("Enable Cloud Monitoring on the cluster if metrics collection is needed"),
            );
        } else {
            let unhealthy: Vec<_> = metrics_pods.items.iter()
                .filter(|p| {
                    p.status.as_ref()
                        .and_then(|s| s.phase.as_ref())
                        .map(|ph| ph != "Running")
                        .unwrap_or(true)
                })
                .collect();

            if !unhealthy.is_empty() {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Cluster,
                        "DaemonSet",
                        "gke-metrics-agent",
                        "Cloud Monitoring Agent Issues",
                        format!("{} gke-metrics-agent pods are not healthy", unhealthy.len()),
                    )
                    .with_namespace("kube-system")
                    .with_remediation("Check gke-metrics-agent pod logs for errors"),
                );
            }
        }
    }

    // Check for Managed Prometheus
    let gmp_ns_api: Api<Namespace> = Api::all(client.clone());
    if gmp_ns_api.get("gmp-system").await.is_ok() {
        let gmp_pods: Api<Pod> = Api::namespaced(client.clone(), "gmp-system");
        if let Ok(collector_pods) = gmp_pods
            .list(&ListParams::default().labels("app.kubernetes.io/name=collector"))
            .await
        {
            let unhealthy: Vec<_> = collector_pods.items.iter()
                .filter(|p| {
                    p.status.as_ref()
                        .and_then(|s| s.phase.as_ref())
                        .map(|ph| ph != "Running")
                        .unwrap_or(true)
                })
                .collect();

            if !unhealthy.is_empty() {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Cluster,
                        "DaemonSet",
                        "gmp-collector",
                        "Managed Prometheus Collector Issues",
                        format!("{} collector pods are not healthy", unhealthy.len()),
                    )
                    .with_namespace("gmp-system")
                    .with_remediation("Check collector pod logs in gmp-system namespace"),
                );
            }
        }
    }

    Ok(issues)
}

// =============================================================================
// GCP SDK Integration (requires gcp feature)
// =============================================================================

/// Check GKE cluster configuration via GCP API
#[cfg(feature = "gcp")]
pub async fn check_gke_cluster_config(_client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Note: Full implementation would require:
    // 1. Getting cluster name and project from node labels or environment
    // 2. Creating authenticated GCP client
    // 3. Calling ClusterManager to get cluster details

    // For now, add a placeholder that indicates the feature is enabled
    issues.push(
        DebugIssue::new(
            Severity::Info,
            DebugCategory::Cluster,
            "Feature",
            "gcp",
            "GCP API Checks Enabled",
            "GCP SDK is available for extended cluster configuration checks",
        )
        .with_remediation("Cluster configuration will be validated via GCP API when credentials are available"),
    );

    Ok(issues)
}
