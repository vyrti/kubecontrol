//! Kubernetes configuration and RBAC checks for GKE
//!
//! Checks for ConfigMaps, Secrets, RBAC, Scheduling, Webhooks, and Quotas.

use crate::debug::types::{DebugCategory, DebugIssue, Severity};
use crate::error::KcError;
use k8s_openapi::api::admissionregistration::v1::{MutatingWebhookConfiguration, ValidatingWebhookConfiguration};
use k8s_openapi::api::core::v1::{ConfigMap, Event, Node, Pod, ResourceQuota, Secret, Service};
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding};
use kube::{api::ListParams, Api, Client};

pub async fn check_config_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Check for large ConfigMaps
    let configmaps: Api<ConfigMap> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(cm_list) = configmaps.list(&ListParams::default()).await {
        for cm in cm_list {
            let cm_name = cm.metadata.name.clone().unwrap_or_default();
            let cm_ns = cm.metadata.namespace.clone().unwrap_or_default();

            // Calculate size
            let data_size: usize = cm.data.as_ref()
                .map(|d| d.values().map(|v| v.len()).sum())
                .unwrap_or(0);
            let binary_size: usize = cm.binary_data.as_ref()
                .map(|d| d.values().map(|v| v.0.len()).sum())
                .unwrap_or(0);
            let total_size = data_size + binary_size;

            // ConfigMap size limit is 1MB
            if total_size > 900_000 {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Cluster,
                        "ConfigMap",
                        &cm_name,
                        "Large ConfigMap",
                        format!("ConfigMap is {}KB, approaching 1MB limit", total_size / 1024),
                    )
                    .with_namespace(&cm_ns)
                    .with_remediation("Consider splitting into multiple ConfigMaps or using a different storage mechanism"),
                );
            }
        }
    }

    // Check events for ConfigMap/Secret mount failures
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

            if reason == "FailedMount" {
                if message.contains("configmap") || message.contains("ConfigMap") {
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Cluster,
                            "Pod",
                            &involved,
                            "ConfigMap Mount Failed",
                            message.to_string(),
                        )
                        .with_namespace(&event_ns)
                        .with_remediation("Verify ConfigMap exists and name is correct"),
                    );
                } else if message.contains("secret") || message.contains("Secret") {
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Cluster,
                            "Pod",
                            &involved,
                            "Secret Mount Failed",
                            message.to_string(),
                        )
                        .with_namespace(&event_ns)
                        .with_remediation("Verify Secret exists and name is correct"),
                    );
                }
            }
        }
    }

    Ok(issues)
}

/// Check for RBAC issues
pub async fn check_rbac_issues(
    client: &Client,
    _namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Check ClusterRoleBindings for cluster-admin
    let crbs: Api<ClusterRoleBinding> = Api::all(client.clone());
    if let Ok(crb_list) = crbs.list(&ListParams::default()).await {
        for crb in crb_list {
            let crb_name = crb.metadata.name.clone().unwrap_or_default();

            // Skip system bindings
            if crb_name.starts_with("system:") || crb_name.starts_with("kubeadm:") {
                continue;
            }

            if crb.role_ref.name == "cluster-admin" {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Security,
                        "ClusterRoleBinding",
                        &crb_name,
                        "Cluster-Admin Binding",
                        "ClusterRoleBinding grants cluster-admin privileges",
                    )
                    .with_remediation("Review if full cluster-admin access is necessary"),
                );
            }
        }
    }

    // Check ClusterRoles for dangerous permissions
    let crs: Api<ClusterRole> = Api::all(client.clone());
    if let Ok(cr_list) = crs.list(&ListParams::default()).await {
        for cr in cr_list {
            let cr_name = cr.metadata.name.clone().unwrap_or_default();

            // Skip system roles
            if cr_name.starts_with("system:") {
                continue;
            }

            if let Some(rules) = &cr.rules {
                for rule in rules {
                    let has_wildcard_resources = rule.resources.as_ref()
                        .map(|r| r.iter().any(|res| res == "*"))
                        .unwrap_or(false);
                    let has_wildcard_verbs = rule.verbs.iter().any(|v| v == "*");

                    if has_wildcard_resources && has_wildcard_verbs {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Security,
                                "ClusterRole",
                                &cr_name,
                                "Overly Permissive ClusterRole",
                                "ClusterRole has wildcard (*) permissions on all resources",
                            )
                            .with_remediation("Apply principle of least privilege"),
                        );
                        break;
                    }
                }
            }
        }
    }

    Ok(issues)
}

/// Check for scheduling issues
pub async fn check_scheduling_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Get recent events for scheduling failures
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

            if reason == "FailedScheduling" {
                let severity = if message.contains("Insufficient") {
                    Severity::Critical
                } else {
                    Severity::Warning
                };

                let title = if message.contains("Insufficient cpu") {
                    "Insufficient CPU"
                } else if message.contains("Insufficient memory") {
                    "Insufficient Memory"
                } else if message.contains("node(s) had taint") {
                    "Taints Not Tolerated"
                } else if message.contains("node selector") || message.contains("node affinity") {
                    "Node Affinity/Selector Mismatch"
                } else {
                    "Scheduling Failed"
                };

                issues.push(
                    DebugIssue::new(
                        severity,
                        DebugCategory::Node,
                        "Pod",
                        &involved,
                        title,
                        message.to_string(),
                    )
                    .with_namespace(&event_ns)
                    .with_remediation("Review pod resource requests, node selectors, and node capacity"),
                );
            }
        }
    }

    Ok(issues)
}

/// Check for StatefulSet issues
pub async fn check_webhook_issues(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Check ValidatingWebhookConfigurations
    let vwcs: Api<ValidatingWebhookConfiguration> = Api::all(client.clone());
    if let Ok(vwc_list) = vwcs.list(&ListParams::default()).await {
        for vwc in vwc_list {
            let vwc_name = vwc.metadata.name.clone().unwrap_or_default();

            if let Some(webhooks) = &vwc.webhooks {
                for webhook in webhooks {
                    let wh_name = &webhook.name;
                    let failure_policy = webhook.failure_policy.as_deref().unwrap_or("Fail");

                    if failure_policy == "Fail" {
                        if let Some(svc_ref) = &webhook.client_config.service {
                            let svc_ns = if svc_ref.namespace.is_empty() { "default" } else { &svc_ref.namespace };
                            let svc_name = &svc_ref.name;

                            let services: Api<Service> = Api::namespaced(client.clone(), svc_ns);
                            if services.get(svc_name).await.is_err() {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Security,
                                        "ValidatingWebhook",
                                        wh_name,
                                        "Webhook Service Unavailable",
                                        format!(
                                            "Webhook '{}' service '{}/{}' not found with failurePolicy=Fail",
                                            vwc_name, svc_ns, svc_name
                                        ),
                                    )
                                    .with_remediation("This may block resource creation. Check webhook service."),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Check MutatingWebhookConfigurations
    let mwcs: Api<MutatingWebhookConfiguration> = Api::all(client.clone());
    if let Ok(mwc_list) = mwcs.list(&ListParams::default()).await {
        for mwc in mwc_list {
            let mwc_name = mwc.metadata.name.clone().unwrap_or_default();

            if let Some(webhooks) = &mwc.webhooks {
                for webhook in webhooks {
                    let wh_name = &webhook.name;
                    let failure_policy = webhook.failure_policy.as_deref().unwrap_or("Fail");

                    if failure_policy == "Fail" {
                        if let Some(svc_ref) = &webhook.client_config.service {
                            let svc_ns = if svc_ref.namespace.is_empty() { "default" } else { &svc_ref.namespace };
                            let svc_name = &svc_ref.name;

                            let services: Api<Service> = Api::namespaced(client.clone(), svc_ns);
                            if services.get(svc_name).await.is_err() {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Security,
                                        "MutatingWebhook",
                                        wh_name,
                                        "Webhook Service Unavailable",
                                        format!(
                                            "Webhook '{}' service '{}/{}' not found with failurePolicy=Fail",
                                            mwc_name, svc_ns, svc_name
                                        ),
                                    )
                                    .with_remediation("This may block resource creation. Check webhook service."),
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

/// Check for ResourceQuota and LimitRange issues
pub async fn check_quota_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let quotas: Api<ResourceQuota> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(quota_list) = quotas.list(&ListParams::default()).await {
        for quota in quota_list {
            let quota_name = quota.metadata.name.clone().unwrap_or_default();
            let quota_ns = quota.metadata.namespace.clone().unwrap_or_default();

            if let Some(status) = &quota.status {
                if let (Some(hard), Some(used)) = (&status.hard, &status.used) {
                    for (resource, hard_qty) in hard {
                        if let Some(used_qty) = used.get(resource) {
                            // Parse quantities - this is simplified
                            let hard_val: f64 = hard_qty.0.parse().unwrap_or(0.0);
                            let used_val: f64 = used_qty.0.parse().unwrap_or(0.0);

                            if hard_val > 0.0 {
                                let usage_pct = (used_val / hard_val) * 100.0;

                                if usage_pct >= 100.0 {
                                    issues.push(
                                        DebugIssue::new(
                                            Severity::Critical,
                                            DebugCategory::Resources,
                                            "ResourceQuota",
                                            &quota_name,
                                            "Quota Exceeded",
                                            format!("Resource '{}' quota is at 100% ({}/{})", resource, used_qty.0, hard_qty.0),
                                        )
                                        .with_namespace(&quota_ns)
                                        .with_remediation("Increase quota or reduce resource usage"),
                                    );
                                } else if usage_pct >= 90.0 {
                                    issues.push(
                                        DebugIssue::new(
                                            Severity::Warning,
                                            DebugCategory::Resources,
                                            "ResourceQuota",
                                            &quota_name,
                                            "Quota Near Limit",
                                            format!("Resource '{}' is at {:.0}% of quota ({}/{})", resource, usage_pct, used_qty.0, hard_qty.0),
                                        )
                                        .with_namespace(&quota_ns)
                                        .with_remediation("Consider increasing quota before it's exhausted"),
                                    );
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

