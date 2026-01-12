//! Kubernetes workload checks for GKE
//!
//! Checks for Pod, Deployment, Service, StatefulSet, Job, and Ingress issues.

use crate::debug::types::{DebugCategory, DebugIssue, Severity};
use crate::error::KcError;
use k8s_openapi::api::apps::v1::{Deployment, StatefulSet};
use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;
use k8s_openapi::api::batch::v1::{CronJob, Job};
use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Pod, Secret, Service};
use k8s_openapi::api::discovery::v1::EndpointSlice;
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
