//! Kubernetes configuration and RBAC checks for EKS
//!
//! Checks for ConfigMaps, Secrets, RBAC, Scheduling, Webhooks, and Quotas.

use crate::debug::types::{DebugCategory, DebugIssue, Severity};
use crate::error::KcError;
use k8s_openapi::api::admissionregistration::v1::{MutatingWebhookConfiguration, ValidatingWebhookConfiguration};
use k8s_openapi::api::core::v1::{ConfigMap, Event, Node, Pod, ResourceQuota, Secret};
use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding};
use kube::{api::ListParams, Api, Client};

pub async fn check_config_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    use k8s_openapi::api::core::v1::{ConfigMap, Secret};

    let mut issues = Vec::new();

    // Check ConfigMaps
    let configmaps: Api<ConfigMap> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    let cm_list = configmaps
        .list(&ListParams::default())
        .await
        .map_err(|e| KcError::Config(e.to_string()))?;

    for cm in cm_list {
        let cm_name = cm.metadata.name.clone().unwrap_or_default();
        let cm_ns = cm.metadata.namespace.clone().unwrap_or_default();

        // Check for overly large ConfigMaps (> 1MB can cause issues)
        let size: usize = cm
            .data
            .as_ref()
            .map(|d| d.values().map(|v| v.len()).sum())
            .unwrap_or(0)
            + cm.binary_data
                .as_ref()
                .map(|d| d.values().map(|v| v.0.len()).sum())
                .unwrap_or(0);

        if size > 1_000_000 {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Resources,
                    "ConfigMap",
                    &cm_name,
                    "Large ConfigMap",
                    format!(
                        "ConfigMap is {} bytes, exceeding 1MB may cause issues",
                        size
                    ),
                )
                .with_namespace(&cm_ns)
                .with_remediation(
                    "Consider splitting into multiple ConfigMaps or using external storage",
                ),
            );
        }
    }

    // Check Secrets
    let secrets: Api<Secret> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    let secret_list = secrets
        .list(&ListParams::default())
        .await
        .map_err(|e| KcError::Config(e.to_string()))?;

    for secret in secret_list {
        let secret_name = secret.metadata.name.clone().unwrap_or_default();
        let secret_ns = secret.metadata.namespace.clone().unwrap_or_default();

        // Skip service account tokens and helm secrets
        let secret_type = secret.type_.as_deref().unwrap_or("");
        if secret_type == "kubernetes.io/service-account-token"
            || secret_type == "helm.sh/release.v1"
        {
            continue;
        }

        // Check for overly large Secrets
        let size: usize = secret
            .data
            .as_ref()
            .map(|d| d.values().map(|v| v.0.len()).sum())
            .unwrap_or(0);

        if size > 1_000_000 {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Resources,
                    "Secret",
                    &secret_name,
                    "Large Secret",
                    format!(
                        "Secret is {} bytes, exceeding 1MB may cause issues",
                        size
                    ),
                )
                .with_namespace(&secret_ns)
                .with_remediation(
                    "Consider using external secret management like AWS Secrets Manager",
                ),
            );
        }
    }

    // Check for pods referencing missing ConfigMaps/Secrets via events
    let events: Api<k8s_openapi::api::core::v1::Event> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(event_list) = events.list(&ListParams::default()).await {
        for event in event_list {
            let reason = event.reason.as_deref().unwrap_or("");
            let message = event.message.as_deref().unwrap_or("");
            let event_ns = event.metadata.namespace.clone().unwrap_or_default();
            let involved = event
                .involved_object
                .name
                .clone()
                .unwrap_or_default();

            if reason == "FailedMount" {
                if message.contains("configmap") && message.contains("not found") {
                    let cm_name = extract_resource_name(message, "configmap");
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Pod,
                            "Pod",
                            &involved,
                            "ConfigMap Not Found",
                            format!("Pod references missing ConfigMap: {}", cm_name),
                        )
                        .with_namespace(&event_ns)
                        .with_remediation("Create the ConfigMap or fix the reference"),
                    );
                }

                if message.contains("secret") && message.contains("not found") {
                    let secret_name = extract_resource_name(message, "secret");
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Pod,
                            "Pod",
                            &involved,
                            "Secret Not Found",
                            format!("Pod references missing Secret: {}", secret_name),
                        )
                        .with_namespace(&event_ns)
                        .with_remediation("Create the Secret or fix the reference"),
                    );
                }
            }
        }
    }

    Ok(issues)
}

/// Helper to extract resource name from event message
fn extract_resource_name(message: &str, resource_type: &str) -> String {
    // Try to extract name from patterns like:
    // "configmap \"my-config\" not found"
    // "secret 'my-secret' not found"
    let patterns = [
        format!("{} \"", resource_type),
        format!("{} '", resource_type),
        format!("{}s \"", resource_type),
        format!("{}s '", resource_type),
    ];

    for pattern in &patterns {
        if let Some(start) = message.find(pattern.as_str()) {
            let after_pattern = &message[start + pattern.len()..];
            if let Some(end) = after_pattern.find(|c| c == '"' || c == '\'') {
                return after_pattern[..end].to_string();
            }
        }
    }

    "unknown".to_string()
}

/// Check for RBAC issues (cluster-admin, wildcard permissions)
pub async fn check_rbac_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, Role, RoleBinding};

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
                let subjects = crb.subjects.as_ref().map(|s| s.len()).unwrap_or(0);
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Security,
                        "ClusterRoleBinding",
                        &crb_name,
                        "cluster-admin Binding",
                        format!(
                            "ClusterRoleBinding grants cluster-admin to {} subjects",
                            subjects
                        ),
                    )
                    .with_remediation(
                        "Review if all subjects need full cluster admin access",
                    ),
                );
            }
        }
    }

    // Check ClusterRoles for wildcard permissions
    let crs: Api<ClusterRole> = Api::all(client.clone());
    if let Ok(cr_list) = crs.list(&ListParams::default()).await {
        for cr in cr_list {
            let cr_name = cr.metadata.name.clone().unwrap_or_default();

            // Skip system roles
            if cr_name.starts_with("system:") || cr_name == "cluster-admin" {
                continue;
            }

            if let Some(rules) = &cr.rules {
                for rule in rules {
                    let has_wildcard_verbs = rule
                        .verbs
                        .iter()
                        .any(|v| v == "*");
                    let has_wildcard_resources = rule
                        .resources
                        .as_ref()
                        .map(|r| r.iter().any(|res| res == "*"))
                        .unwrap_or(false);
                    let has_wildcard_api_groups = rule
                        .api_groups
                        .as_ref()
                        .map(|g| g.iter().any(|group| group == "*"))
                        .unwrap_or(false);

                    if has_wildcard_verbs && has_wildcard_resources {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Security,
                                "ClusterRole",
                                &cr_name,
                                "Wildcard Permissions",
                                "ClusterRole has wildcard verbs on wildcard resources (*:*)",
                            )
                            .with_remediation(
                                "Use least-privilege principle: specify explicit verbs and resources",
                            ),
                        );
                        break;
                    }

                    if has_wildcard_api_groups && has_wildcard_resources {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Security,
                                "ClusterRole",
                                &cr_name,
                                "Broad API Group Access",
                                "ClusterRole has access to all API groups and resources",
                            )
                            .with_remediation(
                                "Restrict to specific API groups and resources",
                            ),
                        );
                        break;
                    }
                }
            }
        }
    }

    // Check Roles for dangerous permissions
    let roles: Api<Role> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(role_list) = roles.list(&ListParams::default()).await {
        for role in role_list {
            let role_name = role.metadata.name.clone().unwrap_or_default();
            let role_ns = role.metadata.namespace.clone().unwrap_or_default();

            if let Some(rules) = &role.rules {
                for rule in rules {
                    // Check for secrets access
                    let accesses_secrets = rule
                        .resources
                        .as_ref()
                        .map(|r| r.iter().any(|res| res == "secrets" || res == "*"))
                        .unwrap_or(false);

                    let can_read_secrets = accesses_secrets
                        && rule.verbs.iter().any(|v| {
                            v == "*" || v == "get" || v == "list" || v == "watch"
                        });

                    if can_read_secrets {
                        issues.push(
                            DebugIssue::new(
                                Severity::Info,
                                DebugCategory::Security,
                                "Role",
                                &role_name,
                                "Secrets Read Access",
                                "Role grants read access to secrets",
                            )
                            .with_namespace(&role_ns)
                            .with_remediation(
                                "Ensure only necessary roles can read secrets",
                            ),
                        );
                    }
                }
            }
        }
    }

    // Check for pods using default ServiceAccount
    let pods: Api<Pod> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(pod_list) = pods.list(&ListParams::default()).await {
        for pod in pod_list {
            let pod_name = pod.metadata.name.clone().unwrap_or_default();
            let pod_ns = pod.metadata.namespace.clone().unwrap_or_default();

            // Skip system namespaces
            if pod_ns == "kube-system" || pod_ns == "kube-public" || pod_ns == "kube-node-lease" {
                continue;
            }

            let sa_name = pod
                .spec
                .as_ref()
                .and_then(|s| s.service_account_name.as_ref())
                .map(|s| s.as_str())
                .unwrap_or("default");

            if sa_name == "default" {
                issues.push(
                    DebugIssue::new(
                        Severity::Info,
                        DebugCategory::Security,
                        "Pod",
                        &pod_name,
                        "Using Default ServiceAccount",
                        "Pod is using the default ServiceAccount",
                    )
                    .with_namespace(&pod_ns)
                    .with_remediation(
                        "Create a dedicated ServiceAccount with minimal permissions",
                    ),
                );
            }
        }
    }

    Ok(issues)
}

/// Check for scheduling issues (resources, affinity, taints)
pub async fn check_scheduling_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Check events for scheduling failures
    let events: Api<k8s_openapi::api::core::v1::Event> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(event_list) = events.list(&ListParams::default()).await {
        for event in event_list {
            let reason = event.reason.as_deref().unwrap_or("");
            let message = event.message.as_deref().unwrap_or("");
            let event_ns = event.metadata.namespace.clone().unwrap_or_default();
            let involved = event
                .involved_object
                .name
                .clone()
                .unwrap_or_default();
            let kind = event
                .involved_object
                .kind
                .as_deref()
                .unwrap_or("Unknown");

            if reason == "FailedScheduling" {
                let severity = Severity::Critical;

                if message.contains("Insufficient cpu") {
                    issues.push(
                        DebugIssue::new(
                            severity,
                            DebugCategory::Resources,
                            kind,
                            &involved,
                            "Insufficient CPU",
                            format!("Cannot schedule: {}", message),
                        )
                        .with_namespace(&event_ns)
                        .with_remediation(
                            "Reduce CPU requests, add more nodes, or use Cluster Autoscaler",
                        ),
                    );
                } else if message.contains("Insufficient memory") {
                    issues.push(
                        DebugIssue::new(
                            severity,
                            DebugCategory::Resources,
                            kind,
                            &involved,
                            "Insufficient Memory",
                            format!("Cannot schedule: {}", message),
                        )
                        .with_namespace(&event_ns)
                        .with_remediation(
                            "Reduce memory requests, add more nodes, or use Cluster Autoscaler",
                        ),
                    );
                } else if message.contains("node(s) didn't match node selector")
                    || message.contains("node(s) didn't match Pod's node affinity")
                {
                    issues.push(
                        DebugIssue::new(
                            severity,
                            DebugCategory::Pod,
                            kind,
                            &involved,
                            "Node Selector/Affinity No Match",
                            format!("Cannot schedule: {}", message),
                        )
                        .with_namespace(&event_ns)
                        .with_remediation(
                            "Review nodeSelector/nodeAffinity and ensure matching nodes exist",
                        ),
                    );
                } else if message.contains("had taint") || message.contains("untolerated taint") {
                    issues.push(
                        DebugIssue::new(
                            severity,
                            DebugCategory::Pod,
                            kind,
                            &involved,
                            "Taints Not Tolerated",
                            format!("Cannot schedule: {}", message),
                        )
                        .with_namespace(&event_ns)
                        .with_remediation(
                            "Add tolerations for the node taints or remove taints from nodes",
                        ),
                    );
                } else if message.contains("pod affinity") || message.contains("pod anti-affinity") {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Pod,
                            kind,
                            &involved,
                            "Pod Affinity Conflict",
                            format!("Scheduling constrained by pod affinity: {}", message),
                        )
                        .with_namespace(&event_ns)
                        .with_remediation(
                            "Review podAffinity/podAntiAffinity rules and ensure adequate nodes",
                        ),
                    );
                } else if message.contains("volume") {
                    issues.push(
                        DebugIssue::new(
                            severity,
                            DebugCategory::Storage,
                            kind,
                            &involved,
                            "Volume Scheduling Issue",
                            format!("Volume scheduling problem: {}", message),
                        )
                        .with_namespace(&event_ns)
                        .with_remediation(
                            "Check PVC/PV availability and zone constraints",
                        ),
                    );
                } else if message.contains("TopologySpreadConstraint") {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Pod,
                            kind,
                            &involved,
                            "Topology Spread Constraint",
                            format!("Topology constraint issue: {}", message),
                        )
                        .with_namespace(&event_ns)
                        .with_remediation(
                            "Review topologySpreadConstraints and node distribution",
                        ),
                    );
                } else {
                    // Generic scheduling failure
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Pod,
                            kind,
                            &involved,
                            "Scheduling Failed",
                            format!("Failed to schedule: {}", message),
                        )
                        .with_namespace(&event_ns)
                        .with_remediation("Check pod requirements and node resources"),
                    );
                }
            }

            // Check for preemption events
            if reason == "Preempted" {
                issues.push(
                    DebugIssue::new(
                        Severity::Info,
                        DebugCategory::Pod,
                        kind,
                        &involved,
                        "Pod Preempted",
                        format!("Pod was preempted: {}", message),
                    )
                    .with_namespace(&event_ns)
                    .with_remediation(
                        "Review PriorityClass settings and resource requests",
                    ),
                );
            }
        }
    }

    Ok(issues)
}

/// Check for StatefulSet issues
pub async fn check_webhook_issues(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    use k8s_openapi::api::admissionregistration::v1::{
        MutatingWebhookConfiguration, ValidatingWebhookConfiguration,
    };

    let mut issues = Vec::new();

    // Check ValidatingWebhookConfigurations
    let vwcs: Api<ValidatingWebhookConfiguration> = Api::all(client.clone());
    if let Ok(vwc_list) = vwcs.list(&ListParams::default()).await {
        let mut total_webhooks = 0;

        for vwc in vwc_list {
            let vwc_name = vwc.metadata.name.clone().unwrap_or_default();

            if let Some(webhooks) = &vwc.webhooks {
                total_webhooks += webhooks.len();

                for webhook in webhooks {
                    let wh_name = &webhook.name;

                    // Check failure policy
                    let failure_policy = webhook.failure_policy.as_deref().unwrap_or("Fail");
                    if failure_policy == "Fail" {
                        // Check if service is available
                        if let Some(svc_ref) = &webhook.client_config.service {
                            let svc_ns = if svc_ref.namespace.is_empty() { "default" } else { &svc_ref.namespace };
                            let svc_name = &svc_ref.name;

                            let services: Api<k8s_openapi::api::core::v1::Service> =
                                Api::namespaced(client.clone(), svc_ns);

                            if services.get(svc_name).await.is_err() {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Security,
                                        "ValidatingWebhook",
                                        wh_name,
                                        "Webhook Service Unavailable",
                                        format!(
                                            "Webhook '{}' service '{}/{}' not found (failurePolicy=Fail)",
                                            wh_name, svc_ns, svc_name
                                        ),
                                    )
                                    .with_remediation(
                                        "Deploy the webhook service or change failurePolicy to Ignore",
                                    ),
                                );
                            }
                        }
                    }

                    // Check timeout
                    let timeout = webhook.timeout_seconds.unwrap_or(10);
                    if timeout > 15 {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Security,
                                "ValidatingWebhook",
                                wh_name,
                                "High Webhook Timeout",
                                format!(
                                    "Webhook '{}' has {}s timeout, may cause API latency",
                                    wh_name, timeout
                                ),
                            )
                            .with_remediation("Consider reducing timeout to under 10 seconds"),
                        );
                    }
                }
            }
        }

        // Check for too many webhooks
        if total_webhooks > 20 {
            issues.push(
                DebugIssue::new(
                    Severity::Info,
                    DebugCategory::Security,
                    "Webhook",
                    "cluster",
                    "Many Validating Webhooks",
                    format!(
                        "{} validating webhooks configured, may impact API performance",
                        total_webhooks
                    ),
                )
                .with_remediation("Review if all webhooks are necessary"),
            );
        }
    }

    // Check MutatingWebhookConfigurations
    let mwcs: Api<MutatingWebhookConfiguration> = Api::all(client.clone());
    if let Ok(mwc_list) = mwcs.list(&ListParams::default()).await {
        let mut total_webhooks = 0;

        for mwc in mwc_list {
            let mwc_name = mwc.metadata.name.clone().unwrap_or_default();

            if let Some(webhooks) = &mwc.webhooks {
                total_webhooks += webhooks.len();

                for webhook in webhooks {
                    let wh_name = &webhook.name;

                    // Check failure policy
                    let failure_policy = webhook.failure_policy.as_deref().unwrap_or("Fail");
                    if failure_policy == "Fail" {
                        if let Some(svc_ref) = &webhook.client_config.service {
                            let svc_ns = if svc_ref.namespace.is_empty() { "default" } else { &svc_ref.namespace };
                            let svc_name = &svc_ref.name;

                            let services: Api<k8s_openapi::api::core::v1::Service> =
                                Api::namespaced(client.clone(), svc_ns);

                            if services.get(svc_name).await.is_err() {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Security,
                                        "MutatingWebhook",
                                        wh_name,
                                        "Webhook Service Unavailable",
                                        format!(
                                            "Webhook '{}' service '{}/{}' not found (failurePolicy=Fail)",
                                            wh_name, svc_ns, svc_name
                                        ),
                                    )
                                    .with_remediation(
                                        "Deploy the webhook service or change failurePolicy to Ignore",
                                    ),
                                );
                            }
                        }
                    }
                }
            }
        }

        if total_webhooks > 20 {
            issues.push(
                DebugIssue::new(
                    Severity::Info,
                    DebugCategory::Security,
                    "Webhook",
                    "cluster",
                    "Many Mutating Webhooks",
                    format!(
                        "{} mutating webhooks configured, may impact API performance",
                        total_webhooks
                    ),
                )
                .with_remediation("Review if all webhooks are necessary"),
            );
        }
    }

    // Check events for webhook failures
    let events: Api<k8s_openapi::api::core::v1::Event> = Api::all(client.clone());
    if let Ok(event_list) = events.list(&ListParams::default()).await {
        for event in event_list {
            let message = event.message.as_deref().unwrap_or("");
            let reason = event.reason.as_deref().unwrap_or("");

            if message.contains("webhook") && message.contains("timeout") {
                let involved = event
                    .involved_object
                    .name
                    .clone()
                    .unwrap_or_default();
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Security,
                        "Webhook",
                        &involved,
                        "Webhook Timeout",
                        format!("Webhook timeout detected: {}", message),
                    )
                    .with_remediation("Check webhook service health and network connectivity"),
                );
            }

            if reason == "FailedAdmission" || message.contains("admission webhook") {
                let involved = event
                    .involved_object
                    .name
                    .clone()
                    .unwrap_or_default();
                let event_ns = event.metadata.namespace.clone().unwrap_or_default();
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Security,
                        "Webhook",
                        &involved,
                        "Admission Webhook Rejected",
                        format!("Resource rejected by admission webhook: {}", message),
                    )
                    .with_namespace(&event_ns)
                    .with_remediation("Review webhook rules or fix resource spec"),
                );
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
    use k8s_openapi::api::core::v1::{LimitRange, Namespace, ResourceQuota};

    let mut issues = Vec::new();

    // Check ResourceQuotas
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
                let hard = status.hard.as_ref();
                let used = status.used.as_ref();

                if let (Some(hard), Some(used)) = (hard, used) {
                    for (resource, hard_val) in hard {
                        if let Some(used_val) = used.get(resource) {
                            // Parse quantities
                            let hard_num: f64 = parse_quantity(&hard_val.0);
                            let used_num: f64 = parse_quantity(&used_val.0);

                            if hard_num > 0.0 {
                                let usage_pct = (used_num / hard_num) * 100.0;

                                if used_num >= hard_num {
                                    issues.push(
                                        DebugIssue::new(
                                            Severity::Critical,
                                            DebugCategory::Resources,
                                            "ResourceQuota",
                                            &quota_name,
                                            "Quota Exceeded",
                                            format!(
                                                "Resource '{}' quota exhausted: {} / {}",
                                                resource, used_val.0, hard_val.0
                                            ),
                                        )
                                        .with_namespace(&quota_ns)
                                        .with_remediation(
                                            "Increase quota or reduce resource usage",
                                        ),
                                    );
                                } else if usage_pct >= 90.0 {
                                    issues.push(
                                        DebugIssue::new(
                                            Severity::Warning,
                                            DebugCategory::Resources,
                                            "ResourceQuota",
                                            &quota_name,
                                            "Quota Near Limit",
                                            format!(
                                                "Resource '{}' at {:.0}% of quota: {} / {}",
                                                resource, usage_pct, used_val.0, hard_val.0
                                            ),
                                        )
                                        .with_namespace(&quota_ns)
                                        .with_remediation(
                                            "Consider increasing quota before exhaustion",
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

    // Check if namespaces have quotas (informational)
    if namespace.is_none() {
        let namespaces: Api<Namespace> = Api::all(client.clone());
        if let Ok(ns_list) = namespaces.list(&ListParams::default()).await {
            for ns in ns_list {
                let ns_name = ns.metadata.name.clone().unwrap_or_default();

                // Skip system namespaces
                if ns_name.starts_with("kube-") || ns_name == "default" {
                    continue;
                }

                let ns_quotas: Api<ResourceQuota> = Api::namespaced(client.clone(), &ns_name);
                if let Ok(quota_list) = ns_quotas.list(&ListParams::default()).await {
                    if quota_list.items.is_empty() {
                        issues.push(
                            DebugIssue::new(
                                Severity::Info,
                                DebugCategory::Resources,
                                "Namespace",
                                &ns_name,
                                "No ResourceQuota",
                                "Namespace has no ResourceQuota configured",
                            )
                            .with_remediation(
                                "Consider adding ResourceQuota for resource governance",
                            ),
                        );
                    }
                }
            }
        }
    }

    // Check LimitRanges
    let limit_ranges: Api<LimitRange> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    // Check for events related to quota/limit issues
    let events: Api<k8s_openapi::api::core::v1::Event> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(event_list) = events.list(&ListParams::default()).await {
        for event in event_list {
            let reason = event.reason.as_deref().unwrap_or("");
            let message = event.message.as_deref().unwrap_or("");

            if reason == "FailedCreate" && message.contains("exceeded quota") {
                let involved = event
                    .involved_object
                    .name
                    .clone()
                    .unwrap_or_default();
                let event_ns = event.metadata.namespace.clone().unwrap_or_default();
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Resources,
                        "ResourceQuota",
                        &involved,
                        "Quota Exceeded",
                        format!("Resource creation blocked by quota: {}", message),
                    )
                    .with_namespace(&event_ns)
                    .with_remediation("Increase quota or reduce resource requests"),
                );
            }

            if message.contains("LimitRange") || reason == "LimitRangeViolation" {
                let involved = event
                    .involved_object
                    .name
                    .clone()
                    .unwrap_or_default();
                let event_ns = event.metadata.namespace.clone().unwrap_or_default();
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Resources,
                        "LimitRange",
                        &involved,
                        "LimitRange Violation",
                        format!("Resource violates LimitRange: {}", message),
                    )
                    .with_namespace(&event_ns)
                    .with_remediation("Adjust resource requests/limits to comply with LimitRange"),
                );
            }
        }
    }

    Ok(issues)
}

/// Parse Kubernetes quantity string to f64
fn parse_quantity(s: &str) -> f64 {
    let s = s.trim();
    if s.is_empty() {
        return 0.0;
    }

    // Handle suffixes
    let (num_str, multiplier) = if s.ends_with("Ki") {
        (&s[..s.len() - 2], 1024.0)
    } else if s.ends_with("Mi") {
        (&s[..s.len() - 2], 1024.0 * 1024.0)
    } else if s.ends_with("Gi") {
        (&s[..s.len() - 2], 1024.0 * 1024.0 * 1024.0)
    } else if s.ends_with("Ti") {
        (&s[..s.len() - 2], 1024.0 * 1024.0 * 1024.0 * 1024.0)
    } else if s.ends_with('k') || s.ends_with('K') {
        (&s[..s.len() - 1], 1000.0)
    } else if s.ends_with('m') {
        (&s[..s.len() - 1], 0.001)
    } else if s.ends_with('M') {
        (&s[..s.len() - 1], 1_000_000.0)
    } else if s.ends_with('G') {
        (&s[..s.len() - 1], 1_000_000_000.0)
    } else {
        (s, 1.0)
    };

    num_str.parse::<f64>().unwrap_or(0.0) * multiplier
}

