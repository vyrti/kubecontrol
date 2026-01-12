//! ECR (Elastic Container Registry) checks
//!
//! Checks for ECR authentication and image pull issues.

use crate::debug::types::{DebugCategory, DebugIssue, Severity};
use crate::error::KcError;
use k8s_openapi::api::core::v1::Pod;
use kube::{api::ListParams, Api, Client};

pub async fn check_ecr_issues(
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

        // Check container images
        if let Some(spec) = &pod.spec {
            for container in &spec.containers {
                let image = container.image.as_deref().unwrap_or("");

                // Check if image is from ECR
                if image.contains(".dkr.ecr.") && image.contains(".amazonaws.com") {
                    // Check for image pull issues
                    if let Some(status) = &pod.status {
                        if let Some(container_statuses) = &status.container_statuses {
                            for cs in container_statuses {
                                if cs.name != container.name {
                                    continue;
                                }

                                if let Some(state) = &cs.state {
                                    if let Some(waiting) = &state.waiting {
                                        let reason = waiting.reason.as_deref().unwrap_or("");
                                        let message = waiting.message.as_deref().unwrap_or("");

                                        if reason == "ImagePullBackOff" || reason == "ErrImagePull" {
                                            let remediation = if message.contains("unauthorized")
                                                || message.contains("no basic auth")
                                            {
                                                "Check ECR authentication: ensure nodes have IAM permissions for ecr:GetAuthorizationToken, ecr:BatchGetImage, ecr:GetDownloadUrlForLayer"
                                            } else if message.contains("not found")
                                                || message.contains("manifest unknown")
                                            {
                                                "Verify image exists in ECR repository with correct tag"
                                            } else if message.contains("timeout") {
                                                "Check VPC endpoints for ECR or NAT gateway connectivity"
                                            } else {
                                                "Check ECR permissions and repository policy"
                                            };

                                            issues.push(
                                                DebugIssue::new(
                                                    Severity::Critical,
                                                    DebugCategory::Pod,
                                                    "Pod",
                                                    &pod_name,
                                                    "ECR Image Pull Failed",
                                                    format!(
                                                        "Cannot pull ECR image '{}': {}",
                                                        image, message
                                                    ),
                                                )
                                                .with_namespace(&pod_ns)
                                                .with_remediation(remediation),
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
    }

    // Check events for ECR-related issues
    let events: Api<k8s_openapi::api::core::v1::Event> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(event_list) = events.list(&ListParams::default()).await {
        for event in event_list {
            let message = event.message.as_deref().unwrap_or("");
            let reason = event.reason.as_deref().unwrap_or("");

            if (reason == "Failed" || reason == "FailedPull") && message.contains("ecr") {
                let involved = event
                    .involved_object
                    .name
                    .clone()
                    .unwrap_or_default();
                let event_ns = event.metadata.namespace.clone().unwrap_or_default();

                if message.contains("rate limit") {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Pod,
                            "Pod",
                            &involved,
                            "ECR Rate Limit",
                            "ECR pull rate limit exceeded",
                        )
                        .with_namespace(&event_ns)
                        .with_remediation(
                            "Use ECR pull-through cache or request rate limit increase",
                        ),
                    );
                }
            }
        }
    }

    Ok(issues)
}
