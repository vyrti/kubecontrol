//! Kubernetes workload checks for EKS
//!
//! Checks for Pod, Deployment, Service, StatefulSet, Job, and Ingress issues.

use crate::debug::types::{DebugCategory, DebugIssue, Severity};
use crate::error::KcError;
use k8s_openapi::api::apps::v1::{Deployment, StatefulSet};
use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;
use k8s_openapi::api::batch::v1::{CronJob, Job};
use k8s_openapi::api::core::v1::{Pod, Service};
use k8s_openapi::api::networking::v1::Ingress;
use k8s_openapi::api::policy::v1::PodDisruptionBudget;
use kube::{api::ListParams, Api, Client};

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

        // Skip completed pods (Jobs)
        let phase = pod
            .status
            .as_ref()
            .and_then(|s| s.phase.as_ref())
            .map(|p| p.as_str())
            .unwrap_or("");

        if phase == "Succeeded" {
            continue;
        }

        // Check pod phase
        if phase == "Failed" {
            let reason = pod
                .status
                .as_ref()
                .and_then(|s| s.reason.as_ref())
                .map(|r| r.as_str())
                .unwrap_or("unknown");

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
            continue;
        }

        // Check for Pending pods
        if phase == "Pending" {
            let pending_duration = pod
                .metadata
                .creation_timestamp
                .as_ref()
                .map(|ts| {
                    let now = chrono::Utc::now();
                    let created: chrono::DateTime<chrono::Utc> = ts.0;
                    now.signed_duration_since(created).num_seconds()
                })
                .unwrap_or(0);

            // Only alert if pending for more than 5 minutes
            if pending_duration > 300 {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Pod,
                        "Pod",
                        &pod_name,
                        "Pod Stuck Pending",
                        format!(
                            "Pod has been pending for {} seconds. Check scheduling constraints.",
                            pending_duration
                        ),
                    )
                    .with_namespace(&pod_ns)
                    .with_remediation(
                        "Check pod events for scheduling errors: insufficient resources, taints, node selectors",
                    ),
                );
            }
            continue;
        }

        // Check container statuses for Running pods
        if let Some(status) = &pod.status {
            // Check init container statuses
            if let Some(init_statuses) = &status.init_container_statuses {
                for init_cs in init_statuses {
                    if let Some(state) = &init_cs.state {
                        if let Some(waiting) = &state.waiting {
                            let reason = waiting.reason.as_deref().unwrap_or("unknown");
                            let message = waiting.message.as_deref().unwrap_or("");

                            if reason == "CrashLoopBackOff" {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Pod,
                                        "Pod",
                                        &pod_name,
                                        "Init Container CrashLoopBackOff",
                                        format!(
                                            "Init container '{}' is in CrashLoopBackOff: {}",
                                            init_cs.name, message
                                        ),
                                    )
                                    .with_namespace(&pod_ns)
                                    .with_remediation(
                                        "Check init container logs: kubectl logs POD -c INIT_CONTAINER",
                                    ),
                                );
                            }
                        }
                    }
                }
            }

            // Check container statuses
            if let Some(container_statuses) = &status.container_statuses {
                for cs in container_statuses {
                    let restart_count = cs.restart_count;

                    // Check for high restart count
                    if restart_count > 5 {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Pod,
                                "Pod",
                                &pod_name,
                                "High Restart Count",
                                format!(
                                    "Container '{}' has restarted {} times",
                                    cs.name, restart_count
                                ),
                            )
                            .with_namespace(&pod_ns)
                            .with_remediation("Check container logs and previous logs: kubectl logs POD -c CONTAINER --previous"),
                        );
                    }

                    // Check current state
                    if let Some(state) = &cs.state {
                        if let Some(waiting) = &state.waiting {
                            let reason = waiting.reason.as_deref().unwrap_or("unknown");
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
                                            format!(
                                                "Container '{}' is in CrashLoopBackOff: {}",
                                                cs.name, message
                                            ),
                                        )
                                        .with_namespace(&pod_ns)
                                        .with_remediation(
                                            "Check container logs: kubectl logs POD -c CONTAINER --previous",
                                        ),
                                    );
                                }
                                "ImagePullBackOff" | "ErrImagePull" => {
                                    let remediation = if message.contains("repository does not exist")
                                        || message.contains("not found")
                                    {
                                        "Verify image name and tag exist in the registry"
                                    } else if message.contains("unauthorized") || message.contains("denied") {
                                        "Check image pull secrets and ECR/registry authentication"
                                    } else {
                                        "Check image name, tag, and pull secrets configuration"
                                    };

                                    issues.push(
                                        DebugIssue::new(
                                            Severity::Critical,
                                            DebugCategory::Pod,
                                            "Pod",
                                            &pod_name,
                                            "Image Pull Failed",
                                            format!(
                                                "Container '{}' cannot pull image: {}",
                                                cs.name, message
                                            ),
                                        )
                                        .with_namespace(&pod_ns)
                                        .with_remediation(remediation),
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
                                            format!(
                                                "Container '{}' has configuration error: {}",
                                                cs.name, message
                                            ),
                                        )
                                        .with_namespace(&pod_ns)
                                        .with_remediation(
                                            "Check ConfigMaps, Secrets, and environment variable references",
                                        ),
                                    );
                                }
                                "ContainerCreating" => {
                                    // Check if stuck for too long
                                    let pending_duration = pod
                                        .metadata
                                        .creation_timestamp
                                        .as_ref()
                                        .map(|ts| {
                                            let now = chrono::Utc::now();
                                            let created: chrono::DateTime<chrono::Utc> = ts.0;
                                            now.signed_duration_since(created).num_seconds()
                                        })
                                        .unwrap_or(0);

                                    if pending_duration > 300 {
                                        issues.push(
                                            DebugIssue::new(
                                                Severity::Critical,
                                                DebugCategory::Pod,
                                                "Pod",
                                                &pod_name,
                                                "Stuck Creating Container",
                                                format!(
                                                    "Container '{}' stuck in ContainerCreating for {} seconds",
                                                    cs.name, pending_duration
                                                ),
                                            )
                                            .with_namespace(&pod_ns)
                                            .with_remediation(
                                                "Check pod events for volume mount or network issues",
                                            ),
                                        );
                                    }
                                }
                                _ => {}
                            }
                        }

                        if let Some(terminated) = &state.terminated {
                            let exit_code = terminated.exit_code;
                            let reason = terminated.reason.as_deref().unwrap_or("unknown");

                            if reason == "OOMKilled" || exit_code == 137 {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Pod,
                                        "Pod",
                                        &pod_name,
                                        "OOMKilled",
                                        format!(
                                            "Container '{}' was killed due to Out Of Memory",
                                            cs.name
                                        ),
                                    )
                                    .with_namespace(&pod_ns)
                                    .with_remediation(
                                        "Increase memory limits or optimize application memory usage",
                                    ),
                                );
                            } else if exit_code == 1 {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Warning,
                                        DebugCategory::Pod,
                                        "Pod",
                                        &pod_name,
                                        "Container Error Exit",
                                        format!(
                                            "Container '{}' exited with error code 1",
                                            cs.name
                                        ),
                                    )
                                    .with_namespace(&pod_ns)
                                    .with_remediation(
                                        "Check container logs for application errors",
                                    ),
                                );
                            }
                        }
                    }

                    // Check last termination state for OOMKilled
                    if let Some(last_state) = &cs.last_state {
                        if let Some(terminated) = &last_state.terminated {
                            if terminated.reason.as_deref() == Some("OOMKilled") {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Warning,
                                        DebugCategory::Pod,
                                        "Pod",
                                        &pod_name,
                                        "Previous OOMKill",
                                        format!(
                                            "Container '{}' was previously OOMKilled",
                                            cs.name
                                        ),
                                    )
                                    .with_namespace(&pod_ns)
                                    .with_remediation(
                                        "Increase memory limits or optimize application memory usage",
                                    ),
                                );
                            }
                        }
                    }
                }
            }

            // Check for Evicted pods
            if let Some(reason) = &status.reason {
                if reason == "Evicted" {
                    let message = status.message.as_deref().unwrap_or("unknown reason");
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Pod,
                            "Pod",
                            &pod_name,
                            "Pod Evicted",
                            format!("Pod was evicted: {}", message),
                        )
                        .with_namespace(&pod_ns)
                        .with_remediation(
                            "Check node resources (disk pressure, memory pressure) and pod priority",
                        ),
                    );
                }
            }
        }

        // Check for security concerns in pod spec
        if let Some(spec) = &pod.spec {
            for container in &spec.containers {
                // Check for privileged containers
                if let Some(sec_ctx) = &container.security_context {
                    if sec_ctx.privileged == Some(true) {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Security,
                                "Pod",
                                &pod_name,
                                "Privileged Container",
                                format!("Container '{}' is running as privileged", container.name),
                            )
                            .with_namespace(&pod_ns)
                            .with_remediation(
                                "Avoid privileged containers unless absolutely necessary",
                            ),
                        );
                    }

                    if sec_ctx.run_as_user == Some(0) {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Security,
                                "Pod",
                                &pod_name,
                                "Running as Root",
                                format!("Container '{}' is running as root (UID 0)", container.name),
                            )
                            .with_namespace(&pod_ns)
                            .with_remediation(
                                "Set runAsNonRoot: true and specify a non-root runAsUser",
                            ),
                        );
                    }
                }

                // Check for missing resource limits
                let has_limits = container
                    .resources
                    .as_ref()
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
                            "No Resource Limits",
                            format!(
                                "Container '{}' has no resource limits set",
                                container.name
                            ),
                        )
                        .with_namespace(&pod_ns)
                        .with_remediation("Set CPU and memory limits to prevent resource contention"),
                    );
                }
            }

            // Check for host networking
            if spec.host_network == Some(true) {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Security,
                        "Pod",
                        &pod_name,
                        "Host Network Enabled",
                        "Pod is using host network namespace",
                    )
                    .with_namespace(&pod_ns)
                    .with_remediation("Avoid hostNetwork unless required for network monitoring"),
                );
            }

            if spec.host_pid == Some(true) {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Security,
                        "Pod",
                        &pod_name,
                        "Host PID Enabled",
                        "Pod is using host PID namespace",
                    )
                    .with_namespace(&pod_ns)
                    .with_remediation("Avoid hostPID unless required for process monitoring"),
                );
            }
        }
    }

    Ok(issues)
}
pub async fn check_deployment_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    use k8s_openapi::api::apps::v1::Deployment;
    use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;

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
            let desired = deploy
                .spec
                .as_ref()
                .and_then(|s| s.replicas)
                .unwrap_or(1);
            let available = status.available_replicas.unwrap_or(0);
            let ready = status.ready_replicas.unwrap_or(0);
            let updated = status.updated_replicas.unwrap_or(0);

            // Check for unavailable replicas
            if available < desired {
                let unavailable = desired - available;
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Deployment,
                        "Deployment",
                        &deploy_name,
                        "Replicas Unavailable",
                        format!(
                            "{} of {} replicas unavailable",
                            unavailable, desired
                        ),
                    )
                    .with_namespace(&deploy_ns)
                    .with_remediation("Check pod status and events for the deployment"),
                );
            }

            // Check for rollout issues
            if let Some(conditions) = &status.conditions {
                for condition in conditions {
                    if condition.type_ == "Progressing"
                        && condition.status == "False"
                        && condition.reason.as_deref() == Some("ProgressDeadlineExceeded")
                    {
                        issues.push(
                            DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Deployment,
                                "Deployment",
                                &deploy_name,
                                "Rollout Deadline Exceeded",
                                "Deployment rollout has exceeded its progress deadline",
                            )
                            .with_namespace(&deploy_ns)
                            .with_remediation(
                                "Check pod events and consider increasing progressDeadlineSeconds",
                            ),
                        );
                    }

                    if condition.type_ == "Available" && condition.status == "False" {
                        issues.push(
                            DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Deployment,
                                "Deployment",
                                &deploy_name,
                                "Deployment Not Available",
                                format!(
                                    "Deployment is not available: {}",
                                    condition.message.as_deref().unwrap_or("unknown reason")
                                ),
                            )
                            .with_namespace(&deploy_ns)
                            .with_remediation("Check pod status and events for the deployment"),
                        );
                    }

                    if condition.type_ == "ReplicaFailure" && condition.status == "True" {
                        issues.push(
                            DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Deployment,
                                "Deployment",
                                &deploy_name,
                                "Replica Failure",
                                format!(
                                    "Deployment has replica failure: {}",
                                    condition.message.as_deref().unwrap_or("unknown reason")
                                ),
                            )
                            .with_namespace(&deploy_ns)
                            .with_remediation("Check pod status and events"),
                        );
                    }
                }
            }

            // Check for stuck rollout (updated != desired)
            if updated < desired && updated > 0 {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Deployment,
                        "Deployment",
                        &deploy_name,
                        "Rollout In Progress",
                        format!(
                            "Rollout in progress: {} of {} replicas updated",
                            updated, desired
                        ),
                    )
                    .with_namespace(&deploy_ns)
                    .with_remediation("Monitor rollout progress or check for stuck pods"),
                );
            }

            // Check if not ready
            if ready < desired && ready < available {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Deployment,
                        "Deployment",
                        &deploy_name,
                        "Replicas Not Ready",
                        format!(
                            "{} of {} replicas not ready",
                            desired - ready,
                            desired
                        ),
                    )
                    .with_namespace(&deploy_ns)
                    .with_remediation("Check readiness probes and pod status"),
                );
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
                let desired = status.desired_replicas;
                let max = hpa
                    .spec
                    .as_ref()
                    .map(|s| s.max_replicas)
                    .unwrap_or(10);

                // Check if at max replicas
                if current >= max && desired > current {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Resources,
                            "HPA",
                            &hpa_name,
                            "HPA at Maximum Replicas",
                            format!(
                                "HPA is at maximum replicas ({}) but wants {}",
                                max, desired
                            ),
                        )
                        .with_namespace(&hpa_ns)
                        .with_remediation("Consider increasing maxReplicas or adding more nodes"),
                    );
                }

                // Check for scaling issues
                if let Some(conditions) = &status.conditions {
                    for condition in conditions {
                        if condition.type_ == "ScalingActive" && condition.status == "False" {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Critical,
                                    DebugCategory::Resources,
                                    "HPA",
                                    &hpa_name,
                                    "HPA Scaling Inactive",
                                    format!(
                                        "HPA cannot scale: {}",
                                        condition.message.as_deref().unwrap_or("unknown reason")
                                    ),
                                )
                                .with_namespace(&hpa_ns)
                                .with_remediation("Check metrics-server and HPA target reference"),
                            );
                        }

                        if condition.type_ == "AbleToScale" && condition.status == "False" {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Critical,
                                    DebugCategory::Resources,
                                    "HPA",
                                    &hpa_name,
                                    "HPA Unable to Scale",
                                    format!(
                                        "HPA unable to scale: {}",
                                        condition.message.as_deref().unwrap_or("unknown reason")
                                    ),
                                )
                                .with_namespace(&hpa_ns)
                                .with_remediation("Check HPA target and resource availability"),
                            );
                        }

                        if condition.type_ == "ScalingLimited" && condition.status == "True" {
                            let reason = condition.reason.as_deref().unwrap_or("");
                            if reason.contains("ReadyPodCount") || reason.contains("TooManyReplicas") {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Warning,
                                        DebugCategory::Resources,
                                        "HPA",
                                        &hpa_name,
                                        "HPA Scaling Limited",
                                        format!(
                                            "HPA scaling is limited: {}",
                                            condition.message.as_deref().unwrap_or(reason)
                                        ),
                                    )
                                    .with_namespace(&hpa_ns)
                                    .with_remediation("Review min/max replicas configuration"),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Check PodDisruptionBudgets
    let pdbs: Api<k8s_openapi::api::policy::v1::PodDisruptionBudget> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(pdb_list) = pdbs.list(&ListParams::default()).await {
        for pdb in pdb_list {
            let pdb_name = pdb.metadata.name.clone().unwrap_or_default();
            let pdb_ns = pdb.metadata.namespace.clone().unwrap_or_default();

            if let Some(status) = &pdb.status {
                let disruptions_allowed = status.disruptions_allowed;
                let current_healthy = status.current_healthy;
                let desired_healthy = status.desired_healthy;

                if disruptions_allowed == 0 && current_healthy < desired_healthy {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Resources,
                            "PDB",
                            &pdb_name,
                            "PDB Blocking Disruptions",
                            format!(
                                "PDB allows 0 disruptions (current: {}, desired: {}). May block node drains.",
                                current_healthy, desired_healthy
                            ),
                        )
                        .with_namespace(&pdb_ns)
                        .with_remediation("Review minAvailable/maxUnavailable settings"),
                    );
                }
            }
        }
    }

    Ok(issues)
}

/// Check for service issues (no endpoints, selector mismatch)
pub async fn check_service_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    use k8s_openapi::api::core::v1::{Endpoints, Service};
    use k8s_openapi::api::discovery::v1::EndpointSlice;

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

        // Skip services without selectors (ExternalName, headless without selector)
        let selector = svc
            .spec
            .as_ref()
            .and_then(|s| s.selector.as_ref());

        if selector.is_none() || selector.map(|s| s.is_empty()).unwrap_or(true) {
            continue;
        }

        // Check for LoadBalancer services
        let svc_type = svc
            .spec
            .as_ref()
            .and_then(|s| s.type_.as_ref())
            .map(|t| t.as_str())
            .unwrap_or("ClusterIP");

        if svc_type == "LoadBalancer" {
            // Check if LoadBalancer has an external IP
            let has_external_ip = svc
                .status
                .as_ref()
                .and_then(|s| s.load_balancer.as_ref())
                .and_then(|lb| lb.ingress.as_ref())
                .map(|ing| !ing.is_empty())
                .unwrap_or(false);

            if !has_external_ip {
                // Check how long it's been pending
                let pending_duration = svc
                    .metadata
                    .creation_timestamp
                    .as_ref()
                    .map(|ts| {
                        let now = chrono::Utc::now();
                        let created: chrono::DateTime<chrono::Utc> = ts.0;
                        now.signed_duration_since(created).num_seconds()
                    })
                    .unwrap_or(0);

                if pending_duration > 300 {
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Service,
                            "Service",
                            &svc_name,
                            "LoadBalancer Pending",
                            format!(
                                "LoadBalancer service has no external IP after {} seconds",
                                pending_duration
                            ),
                        )
                        .with_namespace(&svc_ns)
                        .with_remediation(
                            "Check AWS Load Balancer Controller logs and service events",
                        ),
                    );
                }
            }
        }

        // Check endpoints
        let endpoints: Api<Endpoints> = Api::namespaced(client.clone(), &svc_ns);
        if let Ok(ep) = endpoints.get(&svc_name).await {
            let has_endpoints = ep
                .subsets
                .as_ref()
                .map(|subsets| {
                    subsets
                        .iter()
                        .any(|s| s.addresses.as_ref().map(|a| !a.is_empty()).unwrap_or(false))
                })
                .unwrap_or(false);

            if !has_endpoints {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Service,
                        "Service",
                        &svc_name,
                        "No Endpoints",
                        "Service has no ready endpoints. Traffic will fail.",
                    )
                    .with_namespace(&svc_ns)
                    .with_remediation(
                        "Check if pods match the service selector and are in Ready state",
                    ),
                );
            }
        }

        // Check EndpointSlices for unhealthy endpoints
        let endpoint_slices: Api<EndpointSlice> = Api::namespaced(client.clone(), &svc_ns);
        let label_selector = format!("kubernetes.io/service-name={}", svc_name);
        if let Ok(ep_slices) = endpoint_slices
            .list(&ListParams::default().labels(&label_selector))
            .await
        {
            for slice in ep_slices {
                let endpoints = &slice.endpoints;
                let unhealthy_count = endpoints
                    .iter()
                    .filter(|ep| {
                        ep.conditions
                            .as_ref()
                            .and_then(|c| c.ready)
                            .map(|r| !r)
                            .unwrap_or(false)
                    })
                    .count();

                if unhealthy_count > 0 && !endpoints.is_empty() {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Service,
                            "Service",
                            &svc_name,
                                "Unhealthy Endpoints",
                                format!(
                                    "{} of {} endpoints are not ready",
                                    unhealthy_count,
                                    endpoints.len()
                                ),
                            )
                            .with_namespace(&svc_ns)
                            .with_remediation("Check pod readiness probes and pod status"),
                        );
                    }
            }
        }
    }

    Ok(issues)
}

/// Check for ConfigMap and Secret issues
pub async fn check_statefulset_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    use k8s_openapi::api::apps::v1::StatefulSet;
    use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Service};

    let mut issues = Vec::new();

    let statefulsets: Api<StatefulSet> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    let sts_list = statefulsets
        .list(&ListParams::default())
        .await
        .map_err(|e| KcError::Config(e.to_string()))?;

    for sts in sts_list {
        let sts_name = sts.metadata.name.clone().unwrap_or_default();
        let sts_ns = sts.metadata.namespace.clone().unwrap_or_default();

        if let Some(status) = &sts.status {
            let desired = sts
                .spec
                .as_ref()
                .and_then(|s| s.replicas)
                .unwrap_or(1);
            let ready = status.ready_replicas.unwrap_or(0);
            let current = status.current_replicas.unwrap_or(0);
            let updated = status.updated_replicas.unwrap_or(0);

            // Check for unavailable replicas
            if ready < desired {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Deployment,
                        "StatefulSet",
                        &sts_name,
                        "StatefulSet Not Ready",
                        format!(
                            "{} of {} replicas ready",
                            ready, desired
                        ),
                    )
                    .with_namespace(&sts_ns)
                    .with_remediation("Check pod status and PVC bindings"),
                );
            }

            // Check for update in progress
            if updated < desired && updated > 0 {
                let current_revision = status.current_revision.as_deref().unwrap_or("unknown");
                let update_revision = status.update_revision.as_deref().unwrap_or("unknown");

                if current_revision != update_revision {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Deployment,
                            "StatefulSet",
                            &sts_name,
                            "Rolling Update In Progress",
                            format!(
                                "Update in progress: {} of {} pods updated",
                                updated, desired
                            ),
                        )
                        .with_namespace(&sts_ns)
                        .with_remediation("Monitor rollout progress"),
                    );
                }
            }

            // Check for collision count (indicates naming conflicts)
            if let Some(collision_count) = status.collision_count {
                if collision_count > 0 {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Deployment,
                            "StatefulSet",
                            &sts_name,
                            "Pod Name Collision",
                            format!(
                                "StatefulSet has {} name collisions",
                                collision_count
                            ),
                        )
                        .with_namespace(&sts_ns)
                        .with_remediation("Check for orphaned pods with same name"),
                    );
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
                            DebugCategory::Service,
                            "StatefulSet",
                            &sts_name,
                            "Headless Service Missing",
                            format!(
                                "StatefulSet references service '{}' which does not exist",
                                service_name
                            ),
                        )
                        .with_namespace(&sts_ns)
                        .with_remediation("Create the headless service for the StatefulSet"),
                    );
                }
            }

            // Check PVCs for the StatefulSet
            if let Some(vct) = &spec.volume_claim_templates {
                let pvcs: Api<PersistentVolumeClaim> = Api::namespaced(client.clone(), &sts_ns);
                let replicas = spec.replicas.unwrap_or(1);

                for template in vct {
                    let pvc_base_name = template.metadata.name.clone().unwrap_or_default();

                    for i in 0..replicas {
                        let pvc_name = format!("{}-{}-{}", pvc_base_name, sts_name, i);

                        if let Ok(pvc) = pvcs.get(&pvc_name).await {
                            let phase = pvc
                                .status
                                .as_ref()
                                .and_then(|s| s.phase.as_ref())
                                .map(|p| p.as_str())
                                .unwrap_or("Unknown");

                            if phase != "Bound" {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Storage,
                                        "PVC",
                                        &pvc_name,
                                        "PVC Not Bound",
                                        format!("PVC is in {} phase", phase),
                                    )
                                    .with_namespace(&sts_ns)
                                    .with_remediation(
                                        "Check PVC events and StorageClass provisioner",
                                    ),
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

/// Check for Job and CronJob issues
pub async fn check_job_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    use k8s_openapi::api::batch::v1::{CronJob, Job};

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
                        let backoff_limit = job
                            .spec
                            .as_ref()
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
                                    format!(
                                        "Job has failed {} times, backoff limit reached",
                                        failed
                                    ),
                                )
                                .with_namespace(&job_ns)
                                .with_remediation("Check job pod logs for failure reason"),
                            );
                        } else {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Warning,
                                    DebugCategory::Pod,
                                    "Job",
                                    &job_name,
                                    "Job Failing",
                                    format!(
                                        "Job has failed {} of {} attempts",
                                        failed, backoff_limit
                                    ),
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
                        if condition.type_ == "Failed"
                            && condition.status == "True"
                            && condition.reason.as_deref() == Some("DeadlineExceeded")
                        {
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
                                .with_remediation(
                                    "Increase activeDeadlineSeconds or optimize job performance",
                                ),
                            );
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
                        .with_remediation("Set suspend: false to enable scheduling"),
                    );
                }
            }

            if let Some(status) = &cj.status {
                // Check for missed schedules
                if let Some(last_schedule) = &status.last_schedule_time {
                    let now = chrono::Utc::now();
                    let last: chrono::DateTime<chrono::Utc> = last_schedule.0;
                    let since_last = now.signed_duration_since(last).num_hours();

                    // Alert if no runs in 24+ hours (may indicate issues)
                    if since_last > 24 {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Pod,
                                "CronJob",
                                &cj_name,
                                "CronJob Not Running",
                                format!(
                                    "No jobs scheduled in {} hours",
                                    since_last
                                ),
                            )
                            .with_namespace(&cj_ns)
                            .with_remediation("Check cron schedule and job history"),
                        );
                    }
                }

                // Check for too many active jobs (concurrency issue)
                let active_count = status.active.as_ref().map(|a| a.len()).unwrap_or(0);
                if active_count > 3 {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Pod,
                            "CronJob",
                            &cj_name,
                            "Many Active Jobs",
                            format!(
                                "CronJob has {} active jobs, may indicate job overlap",
                                active_count
                            ),
                        )
                        .with_namespace(&cj_ns)
                        .with_remediation(
                            "Review concurrencyPolicy and job completion time",
                        ),
                    );
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
    use k8s_openapi::api::networking::v1::Ingress;
    use k8s_openapi::api::core::v1::{Secret, Service};

    let mut issues = Vec::new();

    let ingresses: Api<Ingress> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    let ing_list = ingresses
        .list(&ListParams::default())
        .await
        .map_err(|e| KcError::Config(e.to_string()))?;

    // Track hosts for conflict detection
    let mut host_ingresses: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    for ing in &ing_list {
        let ing_name = ing.metadata.name.clone().unwrap_or_default();
        let ing_ns = ing.metadata.namespace.clone().unwrap_or_default();

        // Check for missing address
        let has_address = ing
            .status
            .as_ref()
            .and_then(|s| s.load_balancer.as_ref())
            .and_then(|lb| lb.ingress.as_ref())
            .map(|i| !i.is_empty())
            .unwrap_or(false);

        if !has_address {
            // Check how long ingress has existed
            let age = ing
                .metadata
                .creation_timestamp
                .as_ref()
                .map(|ts| {
                    let now = chrono::Utc::now();
                    let created: chrono::DateTime<chrono::Utc> = ts.0;
                    now.signed_duration_since(created).num_seconds()
                })
                .unwrap_or(0);

            if age > 300 {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Ingress,
                        "Ingress",
                        &ing_name,
                        "Ingress No Address",
                        "Ingress has no load balancer address after 5+ minutes",
                    )
                    .with_namespace(&ing_ns)
                    .with_remediation(
                        "Check ingress controller logs and AWS Load Balancer Controller status",
                    ),
                );
            }
        }

        if let Some(spec) = &ing.spec {
            // Check TLS secrets
            if let Some(tls_configs) = &spec.tls {
                let secrets: Api<Secret> = Api::namespaced(client.clone(), &ing_ns);

                for tls in tls_configs {
                    if let Some(secret_name) = &tls.secret_name {
                        if secrets.get(secret_name).await.is_err() {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Critical,
                                    DebugCategory::Ingress,
                                    "Ingress",
                                    &ing_name,
                                    "TLS Secret Missing",
                                    format!("TLS secret '{}' not found", secret_name),
                                )
                                .with_namespace(&ing_ns)
                                .with_remediation(
                                    "Create the TLS secret or use cert-manager for auto-provisioning",
                                ),
                            );
                        }
                    }

                    // Track hosts for conflict detection
                    if let Some(hosts) = &tls.hosts {
                        for host in hosts {
                            host_ingresses
                                .entry(host.clone())
                                .or_default()
                                .push(format!("{}/{}", ing_ns, ing_name));
                        }
                    }
                }
            }

            // Check backend services
            if let Some(rules) = &spec.rules {
                let services: Api<Service> = Api::namespaced(client.clone(), &ing_ns);

                for rule in rules {
                    if let Some(host) = &rule.host {
                        host_ingresses
                            .entry(host.clone())
                            .or_default()
                            .push(format!("{}/{}", ing_ns, ing_name));
                    }

                    if let Some(http) = &rule.http {
                        for path in &http.paths {
                            if let Some(backend) = &path.backend.service {
                                let svc_name = &backend.name;

                                if services.get(svc_name).await.is_err() {
                                    issues.push(
                                        DebugIssue::new(
                                            Severity::Critical,
                                            DebugCategory::Ingress,
                                            "Ingress",
                                            &ing_name,
                                            "Backend Service Missing",
                                            format!(
                                                "Backend service '{}' not found",
                                                svc_name
                                            ),
                                        )
                                        .with_namespace(&ing_ns)
                                        .with_remediation("Create the backend service"),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Check for host conflicts
    for (host, ingresses) in host_ingresses {
        if ingresses.len() > 1 {
            // Deduplicate
            let unique: std::collections::HashSet<_> = ingresses.into_iter().collect();
            if unique.len() > 1 {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Ingress,
                        "Ingress",
                        &host,
                        "Host Conflict",
                        format!(
                            "Host '{}' is defined in multiple Ingresses: {:?}",
                            host,
                            unique.iter().collect::<Vec<_>>()
                        ),
                    )
                    .with_remediation("Consolidate rules or use different hosts"),
                );
            }
        }
    }

    Ok(issues)
}
