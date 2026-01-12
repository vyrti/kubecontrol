//! AKS storage checks
//!
//! Checks for Azure Disk CSI, Azure File CSI, and storage issues.

use crate::debug::types::{DebugCategory, DebugIssue, Severity};
use crate::error::KcError;
use k8s_openapi::api::apps::v1::DaemonSet;
use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Pod};
use k8s_openapi::api::storage::v1::StorageClass;
use kube::{api::ListParams, Api, Client};

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
