//! GKE storage checks
//!
//! Checks for Persistent Disk CSI, Filestore, and storage issues.

use crate::debug::types::{DebugCategory, DebugIssue, Severity};
use crate::error::KcError;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment};
use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Pod};
use k8s_openapi::api::storage::v1::StorageClass;
use kube::{api::ListParams, Api, Client};

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
