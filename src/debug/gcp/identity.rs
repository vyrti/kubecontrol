//! GKE Workload Identity checks
//!
//! Checks for GCP Workload Identity configuration issues.

use crate::debug::types::{DebugCategory, DebugIssue, Severity};
use crate::error::KcError;
use k8s_openapi::api::core::v1::{Pod, ServiceAccount};
use kube::{api::ListParams, Api, Client};

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
