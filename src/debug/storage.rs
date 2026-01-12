//! Storage diagnostics
//!
//! Checks for storage issues including:
//! - PVC binding status
//! - PV availability
//! - StorageClass configuration
//! - CSI driver health

use super::types::*;
use crate::error::KcError;
use k8s_openapi::api::core::v1::{PersistentVolumeClaim, PersistentVolume, Pod};
use k8s_openapi::api::storage::v1::StorageClass;
use k8s_openapi::api::apps::v1::DaemonSet;
use kube::{Api, Client, api::ListParams};
use std::collections::HashSet;

/// Debug storage configuration
pub async fn debug_storage(
    client: &Client,
    namespace: Option<&str>,
) -> Result<DebugReport, KcError> {
    let mut issues = Vec::new();
    let mut total_checks = 0;

    // Check PVCs
    total_checks += 1;
    let pvc_issues = check_pvcs(client, namespace).await?;
    issues.extend(pvc_issues);

    // Check PVs
    total_checks += 1;
    let pv_issues = check_pvs(client).await?;
    issues.extend(pv_issues);

    // Check StorageClasses
    total_checks += 1;
    let sc_issues = check_storage_classes(client).await?;
    issues.extend(sc_issues);

    // Check CSI drivers
    total_checks += 1;
    let csi_issues = check_csi_drivers(client).await?;
    issues.extend(csi_issues);

    Ok(DebugReport::with_check_count("storage", issues, total_checks))
}

/// Check PVCs for issues
async fn check_pvcs(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let pvcs: Vec<PersistentVolumeClaim> = if let Some(ns) = namespace {
        let api: Api<PersistentVolumeClaim> = Api::namespaced(client.clone(), ns);
        api.list(&ListParams::default()).await?.items
    } else {
        let api: Api<PersistentVolumeClaim> = Api::all(client.clone());
        api.list(&ListParams::default()).await?.items
    };

    for pvc in &pvcs {
        let name = pvc.metadata.name.as_deref().unwrap_or("unknown");
        let ns = pvc.metadata.namespace.as_deref().unwrap_or("default");

        if let Some(status) = &pvc.status {
            let phase = status.phase.as_deref().unwrap_or("Unknown");

            match phase {
                "Pending" => {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Storage,
                            "PVC",
                            name,
                            "PVC pending binding",
                            format!(
                                "PVC {} is in Pending state. No matching PV available or provisioner not working.",
                                name
                            ),
                        )
                        .with_namespace(ns)
                        .with_remediation("Check StorageClass provisioner, PV availability, and access modes")
                    );
                }
                "Lost" => {
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Storage,
                            "PVC",
                            name,
                            "PVC lost its bound volume",
                            format!("PVC {} has lost its bound PersistentVolume. Data may be inaccessible.", name),
                        )
                        .with_namespace(ns)
                        .with_remediation("Investigate the missing PV and consider data recovery")
                    );
                }
                _ => {}
            }

            // Check capacity
            if let Some(spec) = &pvc.spec {
                if let Some(resources) = &spec.resources {
                    if let Some(requests) = &resources.requests {
                        if let Some(storage) = requests.get("storage") {
                            if let Some(capacity) = &status.capacity {
                                if let Some(actual) = capacity.get("storage") {
                                    // Compare requested vs actual
                                    if storage.0 != actual.0 {
                                        issues.push(
                                            DebugIssue::new(
                                                Severity::Info,
                                                DebugCategory::Storage,
                                                "PVC",
                                                name,
                                                "PVC capacity differs from request",
                                                format!(
                                                    "PVC {} requested {} but got {}",
                                                    name, storage.0, actual.0
                                                ),
                                            )
                                            .with_namespace(ns)
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

    // Check for orphaned PVCs (not used by any pod)
    let all_pods: Vec<Pod> = if let Some(ns) = namespace {
        let api: Api<Pod> = Api::namespaced(client.clone(), ns);
        api.list(&ListParams::default()).await?.items
    } else {
        let api: Api<Pod> = Api::all(client.clone());
        api.list(&ListParams::default()).await?.items
    };

    let used_pvcs: HashSet<(String, String)> = all_pods
        .iter()
        .filter_map(|p| {
            let ns = p.metadata.namespace.as_deref()?;
            let spec = p.spec.as_ref()?;
            let volumes = spec.volumes.as_ref()?;

            Some(volumes.iter().filter_map(move |v| {
                v.persistent_volume_claim.as_ref()
                    .map(|pvc| (ns.to_string(), pvc.claim_name.clone()))
            }))
        })
        .flatten()
        .collect();

    for pvc in &pvcs {
        let name = pvc.metadata.name.as_deref().unwrap_or("unknown");
        let ns = pvc.metadata.namespace.as_deref().unwrap_or("default");

        if pvc.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Bound") {
            if !used_pvcs.contains(&(ns.to_string(), name.to_string())) {
                issues.push(
                    DebugIssue::new(
                        Severity::Info,
                        DebugCategory::Storage,
                        "PVC",
                        name,
                        "PVC not used by any pod",
                        format!("PVC {} is bound but not mounted by any pod", name),
                    )
                    .with_namespace(ns)
                    .with_remediation("Consider deleting unused PVCs to free up storage")
                );
            }
        }
    }

    Ok(issues)
}

/// Check PVs for issues
async fn check_pvs(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let api: Api<PersistentVolume> = Api::all(client.clone());
    let pvs = api.list(&ListParams::default()).await?;

    for pv in &pvs.items {
        let name = pv.metadata.name.as_deref().unwrap_or("unknown");

        if let Some(status) = &pv.status {
            let phase = status.phase.as_deref().unwrap_or("Unknown");

            match phase {
                "Failed" => {
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Storage,
                            "PV",
                            name,
                            "PV in Failed state",
                            format!(
                                "PersistentVolume {} is in Failed state. Reason: {}",
                                name,
                                status.reason.as_deref().unwrap_or("Unknown")
                            ),
                        )
                        .with_remediation("Check storage backend and PV configuration")
                    );
                }
                "Released" => {
                    if let Some(spec) = &pv.spec {
                        let reclaim_policy = spec.persistent_volume_reclaim_policy.as_deref().unwrap_or("Retain");
                        if reclaim_policy == "Retain" {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Info,
                                    DebugCategory::Storage,
                                    "PV",
                                    name,
                                    "Released PV with Retain policy",
                                    format!(
                                        "PV {} is released and has Retain policy. Manual cleanup may be needed.",
                                        name
                                    ),
                                )
                                .with_remediation("Either reclaim the PV or delete it after backing up data")
                            );
                        }
                    }
                }
                _ => {}
            }
        }

        // Check for deprecated storage plugins
        if let Some(spec) = &pv.spec {
            if spec.flex_volume.is_some() {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Storage,
                        "PV",
                        name,
                        "Using deprecated FlexVolume",
                        format!("PV {} uses FlexVolume which is deprecated", name),
                    )
                    .with_remediation("Migrate to CSI driver")
                );
            }
        }
    }

    Ok(issues)
}

/// Check StorageClasses
async fn check_storage_classes(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let api: Api<StorageClass> = Api::all(client.clone());
    let storage_classes = api.list(&ListParams::default()).await?;

    if storage_classes.items.is_empty() {
        issues.push(
            DebugIssue::new(
                Severity::Warning,
                DebugCategory::Storage,
                "Cluster",
                "storage-classes",
                "No StorageClasses configured",
                "No StorageClasses are available. Dynamic provisioning will not work.",
            )
            .with_remediation("Create a StorageClass or install a CSI driver")
        );
        return Ok(issues);
    }

    let mut has_default = false;
    let mut default_count = 0;

    for sc in &storage_classes.items {
        let name = sc.metadata.name.as_deref().unwrap_or("unknown");

        // Check for default
        if let Some(annotations) = &sc.metadata.annotations {
            if annotations.get("storageclass.kubernetes.io/is-default-class") == Some(&"true".to_string()) {
                has_default = true;
                default_count += 1;
            }
        }

        // Check provisioner
        let provisioner = &sc.provisioner;
        if provisioner.contains("kubernetes.io/no-provisioner") {
            issues.push(
                DebugIssue::new(
                    Severity::Info,
                    DebugCategory::Storage,
                    "StorageClass",
                    name,
                    "Static provisioning StorageClass",
                    format!(
                        "StorageClass {} uses no-provisioner. PVs must be created manually.",
                        name
                    ),
                )
            );
        }
    }

    if !has_default {
        issues.push(
            DebugIssue::new(
                Severity::Info,
                DebugCategory::Storage,
                "Cluster",
                "storage-classes",
                "No default StorageClass",
                "No default StorageClass is set. PVCs must specify a storageClassName.",
            )
            .with_remediation("Set a default StorageClass with the is-default-class annotation")
        );
    }

    if default_count > 1 {
        issues.push(
            DebugIssue::new(
                Severity::Warning,
                DebugCategory::Storage,
                "Cluster",
                "storage-classes",
                format!("Multiple default StorageClasses ({})", default_count),
                format!("{} StorageClasses are marked as default. This is undefined behavior.", default_count),
            )
            .with_remediation("Ensure only one StorageClass is marked as default")
        );
    }

    Ok(issues)
}

/// Check CSI drivers
async fn check_csi_drivers(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Check for common CSI driver daemonsets
    let ds_api: Api<DaemonSet> = Api::namespaced(client.clone(), "kube-system");
    let daemonsets = ds_api.list(&ListParams::default()).await?;

    let csi_patterns = [
        "csi-", "ebs-csi", "gce-pd-csi", "azuredisk-csi", "longhorn", "rook-ceph"
    ];

    for ds in &daemonsets.items {
        let name = ds.metadata.name.as_deref().unwrap_or("");

        for pattern in &csi_patterns {
            if name.contains(pattern) {
                if let Some(status) = &ds.status {
                    let desired = status.desired_number_scheduled;
                    let ready = status.number_ready;

                    if ready < desired {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Storage,
                                "DaemonSet",
                                name,
                                format!("CSI driver not fully ready ({}/{})", ready, desired),
                                format!(
                                    "CSI driver {} has only {} of {} pods ready",
                                    name, ready, desired
                                ),
                            )
                            .with_namespace("kube-system")
                            .with_remediation("Check CSI driver pod logs for errors")
                        );
                    }
                }
                break;
            }
        }
    }

    Ok(issues)
}
