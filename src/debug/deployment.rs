//! Deployment analysis
//!
//! Checks for deployment issues including:
//! - Replica availability
//! - Rollout status
//! - HPA conflicts
//! - PodDisruptionBudget issues

use super::types::*;
use crate::error::KcError;
use k8s_openapi::api::apps::v1::{Deployment, ReplicaSet};
use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;
use k8s_openapi::api::policy::v1::PodDisruptionBudget;
use kube::{Api, Client, api::ListParams};

/// Debug all deployments
pub async fn debug_deployments(
    client: &Client,
    namespace: Option<&str>,
) -> Result<DebugReport, KcError> {
    let deployments: Vec<Deployment> = if let Some(ns) = namespace {
        let api: Api<Deployment> = Api::namespaced(client.clone(), ns);
        api.list(&ListParams::default()).await?.items
    } else {
        let api: Api<Deployment> = Api::all(client.clone());
        api.list(&ListParams::default()).await?.items
    };

    let mut issues = Vec::new();
    let mut total_checks = 0;

    for deploy in &deployments {
        total_checks += 1;
        let deploy_issues = analyze_deployment(client, deploy).await?;
        issues.extend(deploy_issues);
    }

    Ok(DebugReport::with_check_count("deployment", issues, total_checks))
}

/// Debug a specific deployment
pub async fn debug_deployment(
    client: &Client,
    namespace: &str,
    name: &str,
) -> Result<DebugReport, KcError> {
    let api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    let deploy = api.get(name).await?;

    let issues = analyze_deployment(client, &deploy).await?;
    Ok(DebugReport::new("deployment", issues))
}

/// Analyze a single deployment
async fn analyze_deployment(client: &Client, deploy: &Deployment) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let name = deploy.metadata.name.as_deref().unwrap_or("unknown");
    let namespace = deploy.metadata.namespace.as_deref().unwrap_or("default");

    let status = match &deploy.status {
        Some(s) => s,
        None => return Ok(issues),
    };

    let spec = match &deploy.spec {
        Some(s) => s,
        None => return Ok(issues),
    };

    let desired = spec.replicas.unwrap_or(1);
    let ready = status.ready_replicas.unwrap_or(0);
    let available = status.available_replicas.unwrap_or(0);
    let updated = status.updated_replicas.unwrap_or(0);

    // Check replica counts
    if desired > 0 && ready == 0 {
        issues.push(
            DebugIssue::new(
                Severity::Critical,
                DebugCategory::Deployment,
                "Deployment",
                name,
                "No ready replicas",
                format!(
                    "Deployment {} has 0/{} replicas ready. The application is down.",
                    name, desired
                ),
            )
            .with_namespace(namespace)
            .with_remediation("Check pod status and events for failure reasons")
        );
    } else if ready < desired {
        issues.push(
            DebugIssue::new(
                Severity::Warning,
                DebugCategory::Deployment,
                "Deployment",
                name,
                format!("Degraded replicas ({}/{})", ready, desired),
                format!(
                    "Deployment {} has only {}/{} replicas ready.",
                    name, ready, desired
                ),
            )
            .with_namespace(namespace)
        );
    }

    // Check for rollout issues
    if updated < desired && ready < desired {
        issues.push(
            DebugIssue::new(
                Severity::Warning,
                DebugCategory::Deployment,
                "Deployment",
                name,
                "Rollout in progress or stuck",
                format!(
                    "Deployment {} has {}/{} updated replicas. Rollout may be in progress or stuck.",
                    name, updated, desired
                ),
            )
            .with_namespace(namespace)
            .with_remediation("Check rollout status with 'kubectl rollout status'")
        );
    }

    // Check deployment conditions
    if let Some(conditions) = &status.conditions {
        for condition in conditions {
            match condition.type_.as_str() {
                "Progressing" => {
                    if condition.status == "False" {
                        issues.push(
                            DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Deployment,
                                "Deployment",
                                name,
                                "Rollout failed",
                                format!(
                                    "Deployment {} rollout failed: {}",
                                    name,
                                    condition.message.as_deref().unwrap_or("Unknown reason")
                                ),
                            )
                            .with_namespace(namespace)
                            .with_remediation("Check pod errors and consider rolling back")
                        );
                    }
                }
                "Available" => {
                    if condition.status == "False" && desired > 0 {
                        issues.push(
                            DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Deployment,
                                "Deployment",
                                name,
                                "Deployment not available",
                                format!(
                                    "Deployment {} is not available: {}",
                                    name,
                                    condition.message.as_deref().unwrap_or("Unknown reason")
                                ),
                            )
                            .with_namespace(namespace)
                        );
                    }
                }
                "ReplicaFailure" => {
                    if condition.status == "True" {
                        issues.push(
                            DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Deployment,
                                "Deployment",
                                name,
                                "Replica creation failed",
                                format!(
                                    "Deployment {} failed to create replicas: {}",
                                    name,
                                    condition.message.as_deref().unwrap_or("Unknown reason")
                                ),
                            )
                            .with_namespace(namespace)
                        );
                    }
                }
                _ => {}
            }
        }
    }

    // Check for single replica (no HA)
    if desired == 1 && ready == 1 {
        issues.push(
            DebugIssue::new(
                Severity::Info,
                DebugCategory::Deployment,
                "Deployment",
                name,
                "Single replica deployment",
                format!("Deployment {} has only 1 replica. No high availability.", name),
            )
            .with_namespace(namespace)
            .with_remediation("Consider increasing replicas for production workloads")
        );
    }

    // Check ReplicaSet history
    let rs_issues = check_replicasets(client, deploy).await?;
    issues.extend(rs_issues);

    // Check HPA
    let hpa_issues = check_hpa(client, namespace, name).await?;
    issues.extend(hpa_issues);

    // Check PDB
    let pdb_issues = check_pdb(client, namespace, deploy).await?;
    issues.extend(pdb_issues);

    Ok(issues)
}

/// Check ReplicaSets for issues
async fn check_replicasets(client: &Client, deploy: &Deployment) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let namespace = deploy.metadata.namespace.as_deref().unwrap_or("default");
    let deploy_name = deploy.metadata.name.as_deref().unwrap_or("unknown");

    let api: Api<ReplicaSet> = Api::namespaced(client.clone(), namespace);
    let lp = ListParams::default();
    let replicasets = api.list(&lp).await?;

    // Find ReplicaSets owned by this deployment
    let mut owned_rs: Vec<&ReplicaSet> = Vec::new();

    for rs in &replicasets.items {
        if let Some(owners) = &rs.metadata.owner_references {
            if owners.iter().any(|o| o.kind == "Deployment" && o.name == deploy_name) {
                owned_rs.push(rs);
            }
        }
    }

    // Check for too many old ReplicaSets
    if owned_rs.len() > 10 {
        issues.push(
            DebugIssue::new(
                Severity::Info,
                DebugCategory::Deployment,
                "Deployment",
                deploy_name,
                format!("Many old ReplicaSets ({})", owned_rs.len()),
                format!(
                    "Deployment {} has {} ReplicaSets. Consider cleaning up old revisions.",
                    deploy_name, owned_rs.len()
                ),
            )
            .with_namespace(namespace)
            .with_remediation("Set revisionHistoryLimit to limit old ReplicaSets")
        );
    }

    // Check for failed ReplicaSets
    for rs in &owned_rs {
        let rs_name = rs.metadata.name.as_deref().unwrap_or("unknown");
        if let Some(status) = &rs.status {
            if let Some(conditions) = &status.conditions {
                for condition in conditions {
                    if condition.type_ == "ReplicaFailure" && condition.status == "True" {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Deployment,
                                "ReplicaSet",
                                rs_name,
                                "ReplicaSet failure",
                                format!(
                                    "ReplicaSet {} has replica failures: {}",
                                    rs_name,
                                    condition.message.as_deref().unwrap_or("Unknown")
                                ),
                            )
                            .with_namespace(namespace)
                        );
                    }
                }
            }
        }
    }

    Ok(issues)
}

/// Check HPA for the deployment
async fn check_hpa(
    client: &Client,
    namespace: &str,
    deploy_name: &str,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let api: Api<HorizontalPodAutoscaler> = Api::namespaced(client.clone(), namespace);
    let lp = ListParams::default();
    let hpas = api.list(&lp).await?;

    for hpa in &hpas.items {
        if let Some(spec) = &hpa.spec {
            let scale_ref = &spec.scale_target_ref;
            if scale_ref.kind == "Deployment" && scale_ref.name == deploy_name {
                let hpa_name = hpa.metadata.name.as_deref().unwrap_or("unknown");

                // Check HPA status
                if let Some(status) = &hpa.status {
                    let current = status.current_replicas.unwrap_or(0);
                    let desired = status.desired_replicas;

                    if current != desired {
                        issues.push(
                            DebugIssue::new(
                                Severity::Info,
                                DebugCategory::Deployment,
                                "HPA",
                                hpa_name,
                                format!("HPA scaling ({} -> {})", current, desired),
                                format!(
                                    "HPA {} is scaling deployment from {} to {} replicas",
                                    hpa_name, current, desired
                                ),
                            )
                            .with_namespace(namespace)
                        );
                    }

                    // Check if at max replicas
                    if current >= spec.max_replicas {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Deployment,
                                "HPA",
                                hpa_name,
                                "HPA at maximum replicas",
                                format!(
                                    "HPA {} is at maximum replicas ({}). Consider increasing max.",
                                    hpa_name, spec.max_replicas
                                ),
                            )
                            .with_namespace(namespace)
                        );
                    }

                    // Check conditions
                    if let Some(conditions) = &status.conditions {
                        for condition in conditions {
                            if condition.type_ == "ScalingLimited" && condition.status == "True" {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Warning,
                                        DebugCategory::Deployment,
                                        "HPA",
                                        hpa_name,
                                        "HPA scaling limited",
                                        format!(
                                            "HPA {} scaling is limited: {}",
                                            hpa_name,
                                            condition.message.as_deref().unwrap_or("Unknown reason")
                                        ),
                                    )
                                    .with_namespace(namespace)
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

/// Check PodDisruptionBudget
async fn check_pdb(
    client: &Client,
    namespace: &str,
    deploy: &Deployment,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let api: Api<PodDisruptionBudget> = Api::namespaced(client.clone(), namespace);
    let lp = ListParams::default();
    let pdbs = api.list(&lp).await?;

    let deploy_name = deploy.metadata.name.as_deref().unwrap_or("unknown");
    let deploy_labels = deploy.spec.as_ref()
        .and_then(|s| s.selector.match_labels.as_ref());

    for pdb in &pdbs.items {
        if let Some(spec) = &pdb.spec {
            if let Some(selector) = &spec.selector {
                // Check if PDB applies to this deployment
                if let Some(match_labels) = &selector.match_labels {
                    let applies = deploy_labels.map(|dl| {
                        match_labels.iter().all(|(k, v)| dl.get(k) == Some(v))
                    }).unwrap_or(false);

                    if applies {
                        let pdb_name = pdb.metadata.name.as_deref().unwrap_or("unknown");

                        if let Some(status) = &pdb.status {
                            let disruptions_allowed = status.disruptions_allowed;
                            let current_healthy = status.current_healthy;
                            let desired_healthy = status.desired_healthy;

                            if disruptions_allowed == 0 && current_healthy <= desired_healthy {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Warning,
                                        DebugCategory::Deployment,
                                        "PDB",
                                        pdb_name,
                                        "PDB blocking disruptions",
                                        format!(
                                            "PDB {} allows 0 disruptions. Current healthy: {}, desired: {}",
                                            pdb_name, current_healthy, desired_healthy
                                        ),
                                    )
                                    .with_namespace(namespace)
                                    .with_remediation("This may block node drains and upgrades")
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
