//! GCR and Artifact Registry checks
//!
//! Checks for container registry authentication and image pull issues.

use crate::debug::types::{DebugCategory, DebugIssue, Severity};
use crate::error::KcError;
use k8s_openapi::api::core::v1::{Event, Pod};
use kube::{api::ListParams, Api, Client};

pub async fn check_gcr_access(
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

            // Check for GCR/AR specific image pull failures
            if reason == "Failed" && (message.contains("gcr.io") || message.contains("pkg.dev") || message.contains("docker.pkg.dev")) {
                if message.contains("401") || message.contains("403") || message.contains("unauthorized") {
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Security,
                            "Pod",
                            &involved,
                            "GCR/Artifact Registry Auth Failed",
                            format!("Image pull authentication failed: {}", message),
                        )
                        .with_namespace(&event_ns)
                        .with_remediation("Check Workload Identity configuration and IAM permissions for Artifact Registry"),
                    );
                } else if message.contains("not found") || message.contains("404") {
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Pod,
                            "Pod",
                            &involved,
                            "Image Not Found in GCR/AR",
                            format!("Image not found: {}", message),
                        )
                        .with_namespace(&event_ns)
                        .with_remediation("Verify image name, tag, and that it exists in the registry"),
                    );
                }
            }

            // Check for Binary Authorization blocks
            if message.contains("binary authorization") || message.contains("BinAuthz") {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Security,
                        "Pod",
                        &involved,
                        "Binary Authorization Blocked",
                        "Image blocked by Binary Authorization policy",
                    )
                    .with_namespace(&event_ns)
                    .with_remediation("Sign the image or update Binary Authorization policy"),
                );
            }
        }
    }

    // Check for gcr.io deprecation in pod images
    let pods: Api<Pod> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(pod_list) = pods.list(&ListParams::default()).await {
        for pod in pod_list {
            let pod_name = pod.metadata.name.clone().unwrap_or_default();
            let pod_ns = pod.metadata.namespace.clone().unwrap_or_default();

            if let Some(spec) = &pod.spec {
                for container in &spec.containers {
                    if let Some(image) = &container.image {
                        if image.starts_with("gcr.io/") {
                            // This is info level as gcr.io still works
                            issues.push(
                                DebugIssue::new(
                                    Severity::Info,
                                    DebugCategory::Pod,
                                    "Pod",
                                    &pod_name,
                                    "Using gcr.io Registry",
                                    format!("Container '{}' uses gcr.io which is being replaced by Artifact Registry", container.name),
                                )
                                .with_namespace(&pod_ns)
                                .with_remediation("Consider migrating to Artifact Registry (*.pkg.dev)"),
                            );
                            break; // Only report once per pod
                        }
                    }
                }
            }
        }
    }

    Ok(issues)
}
