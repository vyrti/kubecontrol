//! Kubernetes workload checks for AKS
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
