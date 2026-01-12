//! ACR (Azure Container Registry) checks
//!
//! Checks for container registry authentication and image pull issues.

use crate::debug::types::{DebugCategory, DebugIssue, Severity};
use crate::error::KcError;
use k8s_openapi::api::core::v1::{Event, Pod};
use kube::{api::ListParams, Api, Client};

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
