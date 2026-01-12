//! Azure AKS-specific diagnostics
//!
//! Checks for common issues specific to Azure Kubernetes Service clusters.

use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, StatefulSet};
use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;
use k8s_openapi::api::batch::v1::{CronJob, Job};
use k8s_openapi::api::core::v1::{
    ConfigMap, Event, Namespace, Node, PersistentVolumeClaim, Pod,
    ResourceQuota, Secret, Service, ServiceAccount,
};
use k8s_openapi::api::discovery::v1::EndpointSlice;
use k8s_openapi::api::networking::v1::Ingress;
use k8s_openapi::api::policy::v1::PodDisruptionBudget;
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding};
use k8s_openapi::api::storage::v1::StorageClass;
use k8s_openapi::api::admissionregistration::v1::{MutatingWebhookConfiguration, ValidatingWebhookConfiguration};
use kube::{api::ListParams, Api, Client};
use crate::debug::types::{DebugCategory, DebugIssue, DebugReport, Severity};
use crate::error::KcError;

// Azure SDK integration (optional, requires azure feature)
#[cfg(feature = "azure")]
use azure_identity::ManagedIdentityCredential;
#[cfg(feature = "azure")]
#[allow(unused_imports)]
use azure_mgmt_containerservice::Client as AksClient;

/// Run all AKS-specific diagnostics
pub async fn debug_aks(client: &Client, namespace: Option<&str>) -> Result<DebugReport, KcError> {
    let mut issues = Vec::new();

    // Run checks in 5 parallel batches

    // Batch 1: Core K8s checks
    let (pod_issues, deploy_issues, svc_issues, config_issues, rbac_issues) = tokio::join!(
        check_pod_issues(client, namespace),
        check_deployment_issues(client, namespace),
        check_service_issues(client, namespace),
        check_config_issues(client, namespace),
        check_rbac_issues(client, namespace),
    );

    // Batch 2: More K8s checks
    let (scheduling_issues, sts_issues, job_issues, ingress_issues, webhook_issues) = tokio::join!(
        check_scheduling_issues(client, namespace),
        check_statefulset_issues(client, namespace),
        check_job_issues(client, namespace),
        check_ingress_issues(client, namespace),
        check_webhook_issues(client),
    );

    // Batch 3: Resource and quota checks
    let quota_issues = check_quota_issues(client, namespace).await;

    // Batch 4: AKS-specific provider checks
    let (identity_issues, cni_issues, component_issues, virtual_node_issues) = tokio::join!(
        check_azure_identity(client, namespace),
        check_azure_cni(client),
        check_aks_components(client),
        check_virtual_nodes(client, namespace),
    );

    // Batch 5: More AKS-specific checks
    let (lb_issues, storage_issues, node_pool_issues, acr_issues, obs_issues) = tokio::join!(
        check_aks_load_balancers(client, namespace),
        check_aks_storage(client, namespace),
        check_aks_node_pools(client),
        check_acr_access(client, namespace),
        check_aks_observability(client),
    );

    // Collect all issues
    if let Ok(i) = pod_issues { issues.extend(i); }
    if let Ok(i) = deploy_issues { issues.extend(i); }
    if let Ok(i) = svc_issues { issues.extend(i); }
    if let Ok(i) = config_issues { issues.extend(i); }
    if let Ok(i) = rbac_issues { issues.extend(i); }
    if let Ok(i) = scheduling_issues { issues.extend(i); }
    if let Ok(i) = sts_issues { issues.extend(i); }
    if let Ok(i) = job_issues { issues.extend(i); }
    if let Ok(i) = ingress_issues { issues.extend(i); }
    if let Ok(i) = webhook_issues { issues.extend(i); }
    if let Ok(i) = quota_issues { issues.extend(i); }
    if let Ok(i) = identity_issues { issues.extend(i); }
    if let Ok(i) = cni_issues { issues.extend(i); }
    if let Ok(i) = component_issues { issues.extend(i); }
    if let Ok(i) = virtual_node_issues { issues.extend(i); }
    if let Ok(i) = lb_issues { issues.extend(i); }
    if let Ok(i) = storage_issues { issues.extend(i); }
    if let Ok(i) = node_pool_issues { issues.extend(i); }
    if let Ok(i) = acr_issues { issues.extend(i); }
    if let Ok(i) = obs_issues { issues.extend(i); }

    // Add Azure SDK cluster checks if feature enabled
    #[cfg(feature = "azure")]
    {
        if let Ok(i) = check_aks_cluster_config().await {
            issues.extend(i);
        }
    }

    Ok(DebugReport::new("aks", issues))
}

// =============================================================================
// Kubernetes-Level Checks (shared patterns)
// =============================================================================

/// Check for common pod issues
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

    if let Ok(pod_list) = pods.list(&ListParams::default()).await {
        for pod in pod_list {
            let pod_name = pod.metadata.name.clone().unwrap_or_default();
            let pod_ns = pod.metadata.namespace.clone().unwrap_or_default();

            if let Some(status) = &pod.status {
                let phase = status.phase.as_deref().unwrap_or("");

                // Check for failed pods
                if phase == "Failed" {
                    let reason = status.reason.as_deref().unwrap_or("Unknown");
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Pod,
                            "Pod",
                            &pod_name,
                            "Pod Failed",
                            format!("Pod is in Failed state: {}", reason),
                        )
                        .with_namespace(&pod_ns)
                        .with_remediation("Check pod events and logs for failure reason"),
                    );
                }

                // Check container statuses
                if let Some(container_statuses) = &status.container_statuses {
                    for cs in container_statuses {
                        if let Some(waiting) = &cs.state.as_ref().and_then(|s| s.waiting.as_ref()) {
                            let reason = waiting.reason.as_deref().unwrap_or("Unknown");
                            let message = waiting.message.as_deref().unwrap_or("");

                            match reason {
                                "CrashLoopBackOff" => {
                                    issues.push(
                                        DebugIssue::new(
                                            Severity::Critical,
                                            DebugCategory::Pod,
                                            "Pod",
                                            &pod_name,
                                            "CrashLoopBackOff",
                                            format!("Container '{}' is crash looping", cs.name),
                                        )
                                        .with_namespace(&pod_ns)
                                        .with_remediation("Check container logs for crash reason"),
                                    );
                                }
                                "ImagePullBackOff" | "ErrImagePull" => {
                                    issues.push(
                                        DebugIssue::new(
                                            Severity::Critical,
                                            DebugCategory::Pod,
                                            "Pod",
                                            &pod_name,
                                            "ImagePullBackOff",
                                            format!("Container '{}' cannot pull image: {}", cs.name, message),
                                        )
                                        .with_namespace(&pod_ns)
                                        .with_remediation("Check image name, ACR authentication, and network access"),
                                    );
                                }
                                "CreateContainerConfigError" => {
                                    issues.push(
                                        DebugIssue::new(
                                            Severity::Critical,
                                            DebugCategory::Pod,
                                            "Pod",
                                            &pod_name,
                                            "Container Config Error",
                                            format!("Container '{}' config error: {}", cs.name, message),
                                        )
                                        .with_namespace(&pod_ns)
                                        .with_remediation("Check ConfigMap/Secret references and environment variables"),
                                    );
                                }
                                _ => {}
                            }
                        }

                        // Check for OOMKilled
                        if let Some(terminated) = &cs.state.as_ref().and_then(|s| s.terminated.as_ref()) {
                            if terminated.reason.as_deref() == Some("OOMKilled") {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Resources,
                                        "Pod",
                                        &pod_name,
                                        "OOMKilled",
                                        format!("Container '{}' was killed due to OOM", cs.name),
                                    )
                                    .with_namespace(&pod_ns)
                                    .with_remediation("Increase memory limits or optimize application memory usage"),
                                );
                            }
                        }

                        // Check restart count
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
                                .with_remediation("Investigate container logs for recurring failures"),
                            );
                        }
                    }
                }
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

    if let Ok(deploy_list) = deployments.list(&ListParams::default()).await {
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
                            "Deployment Replicas Unavailable",
                            format!("Only {}/{} replicas are ready", ready, desired),
                        )
                        .with_namespace(&deploy_ns)
                        .with_remediation("Check pod status and events for scheduling or startup issues"),
                    );
                }

                // Check for stuck rollouts
                if let Some(conditions) = &status.conditions {
                    for condition in conditions {
                        if condition.type_ == "Progressing" && condition.status == "False" {
                            if condition.reason.as_deref() == Some("ProgressDeadlineExceeded") {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Pod,
                                        "Deployment",
                                        &deploy_name,
                                        "Deployment Rollout Stuck",
                                        "Deployment rollout has exceeded progress deadline",
                                    )
                                    .with_namespace(&deploy_ns)
                                    .with_remediation("Check pod status for issues preventing rollout completion"),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Check HPAs
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
                    }
                }
            }
        }
    }

    // Check PDBs
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

    if let Ok(svc_list) = services.list(&ListParams::default()).await {
        for svc in svc_list {
            let svc_name = svc.metadata.name.clone().unwrap_or_default();
            let svc_ns = svc.metadata.namespace.clone().unwrap_or_default();

            if let Some(spec) = &svc.spec {
                // Check LoadBalancer services
                if spec.type_.as_deref() == Some("LoadBalancer") {
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
                                    "LoadBalancer Pending",
                                    "LoadBalancer service has no external IP assigned",
                                )
                                .with_namespace(&svc_ns)
                                .with_remediation("Check Azure Standard Load Balancer quotas and service events"),
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
    }

    Ok(issues)
}

/// Check for ConfigMap and Secret issues
pub async fn check_config_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let configmaps: Api<ConfigMap> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(cm_list) = configmaps.list(&ListParams::default()).await {
        for cm in cm_list {
            let cm_name = cm.metadata.name.clone().unwrap_or_default();
            let cm_ns = cm.metadata.namespace.clone().unwrap_or_default();

            let data_size: usize = cm.data.as_ref()
                .map(|d| d.values().map(|v| v.len()).sum())
                .unwrap_or(0);
            let binary_size: usize = cm.binary_data.as_ref()
                .map(|d| d.values().map(|v| v.0.len()).sum())
                .unwrap_or(0);
            let total_size = data_size + binary_size;

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

    // Check events for mount failures
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

    let crbs: Api<ClusterRoleBinding> = Api::all(client.clone());
    if let Ok(crb_list) = crbs.list(&ListParams::default()).await {
        for crb in crb_list {
            let crb_name = crb.metadata.name.clone().unwrap_or_default();

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

    let crs: Api<ClusterRole> = Api::all(client.clone());
    if let Ok(cr_list) = crs.list(&ListParams::default()).await {
        for cr in cr_list {
            let cr_name = cr.metadata.name.clone().unwrap_or_default();

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

    // Check PVC issues
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
                        .with_remediation("Check ingress controller status and Azure App Gateway events"),
                    );
                }
            }

            if let Some(spec) = &ingress.spec {
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
                                    .with_remediation("Create the TLS secret or configure Key Vault integration"),
                                );
                            }
                        }
                    }
                }

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

/// Check for ResourceQuota issues
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
// AKS-Specific Provider Checks
// =============================================================================

/// Check for Azure AD/Entra and Managed Identity issues
pub async fn check_azure_identity(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let kube_system_pods: Api<Pod> = Api::namespaced(client.clone(), "kube-system");

    // Check for AAD Pod Identity components (legacy)
    if let Ok(aad_pods) = kube_system_pods
        .list(&ListParams::default().labels("app=aad-pod-identity"))
        .await
    {
        if !aad_pods.items.is_empty() {
            let unhealthy: Vec<_> = aad_pods.items
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
    }

    // Check for Workload Identity webhook
    if let Ok(wi_webhook) = kube_system_pods
        .list(&ListParams::default().labels("azure-workload-identity.io/system=true"))
        .await
    {
        if !wi_webhook.items.is_empty() {
            let unhealthy: Vec<_> = wi_webhook.items
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
    }

    // Check ServiceAccounts for Workload Identity annotations
    let service_accounts: Api<ServiceAccount> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(sa_list) = service_accounts.list(&ListParams::default()).await {
        for sa in sa_list {
            let sa_name = sa.metadata.name.clone().unwrap_or_default();
            let sa_ns = sa.metadata.namespace.clone().unwrap_or_default();
            let annotations = sa.metadata.annotations.clone().unwrap_or_default();

            let client_id = annotations.get("azure.workload.identity/client-id");
            let tenant_id = annotations.get("azure.workload.identity/tenant-id");

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
    }

    Ok(issues)
}

/// Check Azure CNI health and IP allocation
pub async fn check_azure_cni(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let nodes: Api<Node> = Api::all(client.clone());
    if let Ok(node_list) = nodes.list(&ListParams::default()).await {
        for node in node_list {
            let node_name = node.metadata.name.clone().unwrap_or_default();

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

                if let Some(allocatable) = &status.allocatable {
                    if let Some(pods) = allocatable.get("pods") {
                        let max_pods: i32 = pods.0.parse().unwrap_or(0);
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
    }

    // Check for Azure NPM (Network Policy Manager)
    let pods: Api<Pod> = Api::namespaced(client.clone(), "kube-system");
    if let Ok(npm_pods) = pods
        .list(&ListParams::default().labels("k8s-app=azure-npm"))
        .await
    {
        if !npm_pods.items.is_empty() {
            let unhealthy: Vec<_> = npm_pods.items
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
    }

    Ok(issues)
}

/// Check AKS-specific system components
pub async fn check_aks_components(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let pods: Api<Pod> = Api::namespaced(client.clone(), "kube-system");

    // Check coredns-autoscaler
    if let Ok(autoscaler_pods) = pods
        .list(&ListParams::default().labels("k8s-app=coredns-autoscaler"))
        .await
    {
        if !autoscaler_pods.items.is_empty() {
            let unhealthy: Vec<_> = autoscaler_pods.items
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
    }

    // Check Azure Policy pods
    if let Ok(policy_pods) = pods
        .list(&ListParams::default().labels("app=azure-policy"))
        .await
    {
        if !policy_pods.items.is_empty() {
            let unhealthy: Vec<_> = policy_pods.items
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
    }

    // Check metrics-server (AKS managed)
    if let Ok(metrics_pods) = pods
        .list(&ListParams::default().labels("k8s-app=metrics-server"))
        .await
    {
        if metrics_pods.items.is_empty() {
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
            let unhealthy: Vec<_> = metrics_pods.items
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
                    .with_remediation("Check metrics-server pod logs"),
                );
            }
        }
    }

    // Check Key Vault provider for Secrets Store CSI
    if let Ok(kv_pods) = pods
        .list(&ListParams::default().labels("app=secrets-store-csi-driver-provider-azure"))
        .await
    {
        if !kv_pods.items.is_empty() {
            let unhealthy: Vec<_> = kv_pods.items
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
                        "DaemonSet",
                        "secrets-store-csi-driver-provider-azure",
                        "Key Vault Provider Issues",
                        format!("{} Key Vault provider pods are not running", unhealthy.len()),
                    )
                    .with_namespace("kube-system")
                    .with_remediation("Check secrets-store-csi-driver-provider-azure logs"),
                );
            }
        }
    }

    Ok(issues)
}

/// Check for virtual node (ACI) issues
pub async fn check_virtual_nodes(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let nodes: Api<Node> = Api::all(client.clone());
    if let Ok(node_list) = nodes.list(&ListParams::default()).await {
        let virtual_nodes: Vec<_> = node_list
            .iter()
            .filter(|n| {
                n.metadata
                    .labels
                    .as_ref()
                    .map(|l| l.get("type").map(|v| v == "virtual-kubelet").unwrap_or(false))
                    .unwrap_or(false)
            })
            .collect();

        for vn in &virtual_nodes {
            let node_name = vn.metadata.name.clone().unwrap_or_default();

            if let Some(status) = &vn.status {
                if let Some(conditions) = &status.conditions {
                    for condition in conditions {
                        if condition.type_ == "Ready" && condition.status != "True" {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Critical,
                                    DebugCategory::Cluster,
                                    "Node",
                                    &node_name,
                                    "Virtual Node Not Ready",
                                    condition
                                        .message
                                        .clone()
                                        .unwrap_or_else(|| "Virtual node is not ready".to_string()),
                                )
                                .with_remediation("Check virtual-kubelet pod logs in kube-system namespace"),
                            );
                        }
                    }
                }
            }
        }

        if !virtual_nodes.is_empty() {
            let pods: Api<Pod> = Api::namespaced(client.clone(), "kube-system");
            if let Ok(vk_pods) = pods
                .list(&ListParams::default().labels("app=virtual-kubelet-linux-aci"))
                .await
            {
                let unhealthy: Vec<_> = vk_pods.items
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
                            DebugCategory::Cluster,
                            "Deployment",
                            "virtual-kubelet",
                            "Virtual Kubelet Unhealthy",
                            format!("{} virtual-kubelet pods are not running", unhealthy.len()),
                        )
                        .with_namespace("kube-system")
                        .with_remediation("Check virtual-kubelet pod logs"),
                    );
                }
            }
        }
    }

    Ok(issues)
}

/// Check AKS load balancer issues
pub async fn check_aks_load_balancers(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Check AGIC (Application Gateway Ingress Controller)
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), "default");
    if let Ok(agic) = deployments.get("ingress-appgw-deployment").await {
        if let Some(status) = &agic.status {
            let ready = status.ready_replicas.unwrap_or(0);
            if ready == 0 {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Network,
                        "Deployment",
                        "ingress-appgw-deployment",
                        "AGIC Not Ready",
                        "Application Gateway Ingress Controller has no ready replicas",
                    )
                    .with_namespace("default")
                    .with_remediation("Check AGIC pod logs and Application Gateway health"),
                );
            }
        }
    }

    // Check services for LoadBalancer issues
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

            if let Some(spec) = &svc.spec {
                // Check for internal load balancer
                if annotations.get("service.beta.kubernetes.io/azure-load-balancer-internal") == Some(&"true".to_string()) {
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
                                .with_remediation("Check subnet configuration and Azure ILB quotas"),
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(issues)
}

/// Check AKS storage issues
pub async fn check_aks_storage(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Check Azure Disk CSI driver
    let daemonsets: Api<DaemonSet> = Api::namespaced(client.clone(), "kube-system");
    if daemonsets.get("azuredisk-csi-driver").await.is_err()
        && daemonsets.get("csi-azuredisk-node").await.is_err() {
        issues.push(
            DebugIssue::new(
                Severity::Warning,
                DebugCategory::Storage,
                "DaemonSet",
                "azuredisk-csi-driver",
                "Azure Disk CSI Driver Not Found",
                "Azure Disk CSI driver not detected",
            )
            .with_remediation("Ensure the Azure Disk CSI driver is enabled on the cluster"),
        );
    }

    // Check Azure File CSI driver
    if daemonsets.get("azurefile-csi-driver").await.is_err()
        && daemonsets.get("csi-azurefile-node").await.is_err() {
        issues.push(
            DebugIssue::new(
                Severity::Warning,
                DebugCategory::Storage,
                "DaemonSet",
                "azurefile-csi-driver",
                "Azure File CSI Driver Not Found",
                "Azure File CSI driver not detected",
            )
            .with_remediation("Ensure the Azure File CSI driver is enabled on the cluster"),
        );
    }

    // Check StorageClasses
    let storage_classes: Api<StorageClass> = Api::all(client.clone());
    let mut has_default = false;
    if let Ok(sc_list) = storage_classes.list(&ListParams::default()).await {
        for sc in &sc_list {
            let annotations = sc.metadata.annotations.clone().unwrap_or_default();

            if annotations.get("storageclass.kubernetes.io/is-default-class") == Some(&"true".to_string()) {
                has_default = true;
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
                        .with_remediation("Check PVC events for provisioning errors"),
                    );
                }
            }
        }
    }

    Ok(issues)
}

/// Check AKS node pool issues
pub async fn check_aks_node_pools(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let nodes: Api<Node> = Api::all(client.clone());
    if let Ok(node_list) = nodes.list(&ListParams::default()).await {
        for node in node_list {
            let node_name = node.metadata.name.clone().unwrap_or_default();
            let labels = node.metadata.labels.clone().unwrap_or_default();

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
                                    .with_remediation("Check Azure CNI configuration and node networking"),
                                );
                            }
                            _ => {}
                        }
                    }
                }
            }

            // Check for spot node issues
            if labels.get("kubernetes.azure.com/scalesetpriority") == Some(&"spot".to_string()) {
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
                                        "Spot Node Issue",
                                        "Spot VM node may have been evicted",
                                    )
                                    .with_remediation("This is expected behavior for spot nodes"),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Check Cluster Autoscaler
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), "kube-system");
    if let Ok(ca) = deployments.get("cluster-autoscaler").await {
        if let Some(status) = &ca.status {
            let ready = status.ready_replicas.unwrap_or(0);
            if ready == 0 {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Cluster,
                        "Deployment",
                        "cluster-autoscaler",
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

/// Check ACR access issues
pub async fn check_acr_access(
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

            // Check for ACR specific image pull failures
            if reason == "Failed" && message.contains("azurecr.io") {
                if message.contains("401") || message.contains("403") || message.contains("unauthorized") {
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Security,
                            "Pod",
                            &involved,
                            "ACR Authentication Failed",
                            format!("Image pull authentication failed: {}", message),
                        )
                        .with_namespace(&event_ns)
                        .with_remediation("Check ACR attach or image pull secret configuration"),
                    );
                } else if message.contains("not found") || message.contains("404") {
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Pod,
                            "Pod",
                            &involved,
                            "Image Not Found in ACR",
                            format!("Image not found: {}", message),
                        )
                        .with_namespace(&event_ns)
                        .with_remediation("Verify image name, tag, and that it exists in the ACR"),
                    );
                }
            }
        }
    }

    Ok(issues)
}

/// Check AKS observability components
pub async fn check_aks_observability(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let pods: Api<Pod> = Api::namespaced(client.clone(), "kube-system");

    // Check Azure Monitor Agent (Container Insights)
    if let Ok(omsagent_pods) = pods
        .list(&ListParams::default().labels("component=oms-agent"))
        .await
    {
        if omsagent_pods.items.is_empty() {
            issues.push(
                DebugIssue::new(
                    Severity::Info,
                    DebugCategory::Cluster,
                    "DaemonSet",
                    "omsagent",
                    "Container Insights Not Found",
                    "Azure Monitor Agent (omsagent) not detected",
                )
                .with_namespace("kube-system")
                .with_remediation("Enable Container Insights on the cluster for monitoring"),
            );
        } else {
            let unhealthy: Vec<_> = omsagent_pods.items.iter()
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
                        "omsagent",
                        "Container Insights Agent Issues",
                        format!("{} omsagent pods are not healthy", unhealthy.len()),
                    )
                    .with_namespace("kube-system")
                    .with_remediation("Check omsagent pod logs for errors"),
                );
            }
        }
    }

    // Check Azure Managed Prometheus
    if let Ok(prom_pods) = pods
        .list(&ListParams::default().labels("app=prometheus-operator"))
        .await
    {
        if !prom_pods.items.is_empty() {
            let unhealthy: Vec<_> = prom_pods.items.iter()
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
                        "Deployment",
                        "prometheus-operator",
                        "Azure Managed Prometheus Issues",
                        format!("{} prometheus pods are not healthy", unhealthy.len()),
                    )
                    .with_namespace("kube-system")
                    .with_remediation("Check prometheus pod logs"),
                );
            }
        }
    }

    Ok(issues)
}

// =============================================================================
// Azure SDK Integration (optional, requires azure feature)
// =============================================================================

#[cfg(feature = "azure")]
pub async fn check_aks_cluster_config() -> Result<Vec<DebugIssue>, KcError> {
    // Azure SDK cluster config checks would go here
    // This is a placeholder for Azure-specific API calls
    Ok(Vec::new())
}

// =============================================================================
// AKS Detection
// =============================================================================

/// Detect if the cluster is running on AKS
pub fn is_aks(nodes: &[Node]) -> bool {
    nodes.iter().any(|node| {
        let labels = node.metadata.labels.as_ref();
        let provider_id = node
            .spec
            .as_ref()
            .and_then(|s| s.provider_id.as_ref());

        // Check for AKS-specific labels
        let has_aks_labels = labels
            .map(|l| {
                l.contains_key("kubernetes.azure.com/agentpool")
                    || l.contains_key("kubernetes.azure.com/cluster")
                    || l.contains_key("kubernetes.azure.com/mode")
                    || l.contains_key("agentpool")
            })
            .unwrap_or(false);

        // Check for Azure provider ID
        let has_azure_provider = provider_id
            .map(|p| p.starts_with("azure://"))
            .unwrap_or(false);

        has_aks_labels || has_azure_provider
    })
}

/// Detect if the cluster has virtual nodes (ACI virtual kubelet)
pub fn has_virtual_nodes(nodes: &[Node]) -> bool {
    nodes.iter().any(|node| {
        let labels = node.metadata.labels.as_ref();

        // Check for virtual-kubelet type label
        labels
            .map(|l| {
                l.get("type")
                    .map(|v| v == "virtual-kubelet")
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    })
}
