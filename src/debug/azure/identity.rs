//! Azure Identity and AAD checks for AKS
//!
//! Checks for Azure AD, Workload Identity, and managed identity issues.

use crate::debug::types::{DebugCategory, DebugIssue, Severity};
use crate::error::KcError;
use k8s_openapi::api::apps::v1::DaemonSet;
use k8s_openapi::api::core::v1::{Pod, ServiceAccount};
use kube::{api::ListParams, Api, Client};

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
