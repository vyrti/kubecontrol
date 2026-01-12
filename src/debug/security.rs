//! Security audit
//!
//! Checks for security issues including:
//! - Pods running as root
//! - Privileged containers
//! - Host namespace usage
//! - RBAC misconfigurations
//! - Secret exposure

use super::types::*;
use crate::error::KcError;
use k8s_openapi::api::core::v1::{Pod, ServiceAccount};
use k8s_openapi::api::rbac::v1::ClusterRoleBinding;
use kube::{Api, Client, api::ListParams};

/// Run security audit
pub async fn debug_security(
    client: &Client,
    namespace: Option<&str>,
) -> Result<DebugReport, KcError> {
    let mut issues = Vec::new();
    let mut total_checks = 0;

    // Check pod security
    total_checks += 1;
    let pod_issues = check_pod_security(client, namespace).await?;
    issues.extend(pod_issues);

    // Check RBAC
    total_checks += 1;
    let rbac_issues = check_rbac(client).await?;
    issues.extend(rbac_issues);

    // Check service accounts
    total_checks += 1;
    let sa_issues = check_service_accounts(client, namespace).await?;
    issues.extend(sa_issues);

    Ok(DebugReport::with_check_count("security", issues, total_checks))
}

/// Check pod security configuration
async fn check_pod_security(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let pods: Vec<Pod> = if let Some(ns) = namespace {
        let api: Api<Pod> = Api::namespaced(client.clone(), ns);
        api.list(&ListParams::default()).await?.items
    } else {
        let api: Api<Pod> = Api::all(client.clone());
        api.list(&ListParams::default()).await?.items
    };

    for pod in &pods {
        let name = pod.metadata.name.as_deref().unwrap_or("unknown");
        let ns = pod.metadata.namespace.as_deref().unwrap_or("default");

        // Skip system namespaces for some checks
        let is_system_ns = ns == "kube-system" || ns == "kube-public" || ns == "kube-node-lease";

        let spec = match &pod.spec {
            Some(s) => s,
            None => continue,
        };

        // Check host namespaces
        if spec.host_network == Some(true) {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Security,
                    "Pod",
                    name,
                    "Uses hostNetwork",
                    format!("Pod {} uses host network namespace, bypassing network isolation", name),
                )
                .with_namespace(ns)
                .with_remediation("Remove hostNetwork unless absolutely required")
            );
        }

        if spec.host_pid == Some(true) {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Security,
                    "Pod",
                    name,
                    "Uses hostPID",
                    format!("Pod {} uses host PID namespace, can see all host processes", name),
                )
                .with_namespace(ns)
                .with_remediation("Remove hostPID unless absolutely required")
            );
        }

        if spec.host_ipc == Some(true) {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Security,
                    "Pod",
                    name,
                    "Uses hostIPC",
                    format!("Pod {} uses host IPC namespace", name),
                )
                .with_namespace(ns)
                .with_remediation("Remove hostIPC unless absolutely required")
            );
        }

        // Check pod-level security context
        let pod_runs_as_root = spec.security_context.as_ref()
            .and_then(|sc| sc.run_as_user)
            .map(|uid| uid == 0)
            .unwrap_or(false);

        let pod_run_as_non_root = spec.security_context.as_ref()
            .and_then(|sc| sc.run_as_non_root)
            .unwrap_or(false);

        // Check each container
        for container in &spec.containers {
            let container_name = &container.name;

            // Check privileged
            let is_privileged = container.security_context.as_ref()
                .and_then(|sc| sc.privileged)
                .unwrap_or(false);

            if is_privileged {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Security,
                        "Container",
                        container_name,
                        "Privileged container",
                        format!(
                            "Container {} in pod {} runs in privileged mode with full host access",
                            container_name, name
                        ),
                    )
                    .with_namespace(ns)
                    .with_remediation("Remove privileged: true unless absolutely required")
                );
            }

            // Check root user
            let container_runs_as_root = container.security_context.as_ref()
                .and_then(|sc| sc.run_as_user)
                .map(|uid| uid == 0)
                .unwrap_or(pod_runs_as_root);

            let container_run_as_non_root = container.security_context.as_ref()
                .and_then(|sc| sc.run_as_non_root)
                .unwrap_or(pod_run_as_non_root);

            if container_runs_as_root && !container_run_as_non_root && !is_system_ns {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Security,
                        "Container",
                        container_name,
                        "Runs as root",
                        format!(
                            "Container {} in pod {} runs as root user (UID 0)",
                            container_name, name
                        ),
                    )
                    .with_namespace(ns)
                    .with_remediation("Set runAsNonRoot: true and runAsUser to a non-zero UID")
                );
            }

            // Check capabilities
            if let Some(sc) = &container.security_context {
                if let Some(caps) = &sc.capabilities {
                    if let Some(add) = &caps.add {
                        let dangerous_caps = ["SYS_ADMIN", "NET_ADMIN", "ALL"];
                        for cap in add {
                            if dangerous_caps.contains(&cap.as_str()) {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Warning,
                                        DebugCategory::Security,
                                        "Container",
                                        container_name,
                                        format!("Has {} capability", cap),
                                        format!(
                                            "Container {} in pod {} has elevated capability: {}",
                                            container_name, name, cap
                                        ),
                                    )
                                    .with_namespace(ns)
                                    .with_remediation("Drop unnecessary capabilities")
                                );
                            }
                        }
                    }
                }

                // Check allowPrivilegeEscalation
                if sc.allow_privilege_escalation == Some(true) {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Security,
                            "Container",
                            container_name,
                            "Allows privilege escalation",
                            format!(
                                "Container {} in pod {} allows privilege escalation",
                                container_name, name
                            ),
                        )
                        .with_namespace(ns)
                        .with_remediation("Set allowPrivilegeEscalation: false")
                    );
                }
            }

            // Check for secrets in environment variables
            if let Some(env) = &container.env {
                for var in env {
                    if let Some(value_from) = &var.value_from {
                        if value_from.secret_key_ref.is_some() {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Info,
                                    DebugCategory::Security,
                                    "Container",
                                    container_name,
                                    "Secret exposed as env var",
                                    format!(
                                        "Container {} in pod {} exposes secret as environment variable '{}'",
                                        container_name, name, var.name
                                    ),
                                )
                                .with_namespace(ns)
                                .with_remediation("Consider mounting secrets as files instead")
                            );
                        }
                    }
                }
            }
        }

        // Check for missing security context
        if spec.security_context.is_none() && !is_system_ns {
            let has_container_sc = spec.containers.iter()
                .any(|c| c.security_context.is_some());

            if !has_container_sc {
                issues.push(
                    DebugIssue::new(
                        Severity::Info,
                        DebugCategory::Security,
                        "Pod",
                        name,
                        "No security context defined",
                        format!("Pod {} has no security context. Using default (potentially root)", name),
                    )
                    .with_namespace(ns)
                    .with_remediation("Define a security context with runAsNonRoot and other restrictions")
                );
            }
        }
    }

    Ok(issues)
}

/// Check RBAC configuration
async fn check_rbac(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Check ClusterRoleBindings
    let crb_api: Api<ClusterRoleBinding> = Api::all(client.clone());
    let crbs = crb_api.list(&ListParams::default()).await?;

    for crb in &crbs.items {
        let name = crb.metadata.name.as_deref().unwrap_or("unknown");

        // Skip system bindings
        if name.starts_with("system:") || name.starts_with("kubeadm:") {
            continue;
        }

        let role_ref = &crb.role_ref;
        if role_ref.name == "cluster-admin" {
            if let Some(subjects) = &crb.subjects {
                for subject in subjects {
                    // Check for non-system subjects bound to cluster-admin
                    if subject.kind == "ServiceAccount" || subject.kind == "User" || subject.kind == "Group" {
                        let subject_name = &subject.name;
                        if !subject_name.starts_with("system:") {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Warning,
                                    DebugCategory::Security,
                                    "ClusterRoleBinding",
                                    name,
                                    format!("{} has cluster-admin access", subject.kind),
                                    format!(
                                        "{} '{}' is bound to cluster-admin role via {}",
                                        subject.kind, subject_name, name
                                    ),
                                )
                                .with_remediation("Review if cluster-admin access is necessary. Use more restrictive roles.")
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(issues)
}

/// Check service accounts
async fn check_service_accounts(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let sas: Vec<ServiceAccount> = if let Some(ns) = namespace {
        let api: Api<ServiceAccount> = Api::namespaced(client.clone(), ns);
        api.list(&ListParams::default()).await?.items
    } else {
        let api: Api<ServiceAccount> = Api::all(client.clone());
        api.list(&ListParams::default()).await?.items
    };

    for sa in &sas {
        let name = sa.metadata.name.as_deref().unwrap_or("unknown");
        let ns = sa.metadata.namespace.as_deref().unwrap_or("default");

        // Skip default service accounts in system namespaces
        if name == "default" && (ns == "kube-system" || ns == "kube-public") {
            continue;
        }

        // Check automount token
        if sa.automount_service_account_token == Some(true) && name != "default" {
            issues.push(
                DebugIssue::new(
                    Severity::Info,
                    DebugCategory::Security,
                    "ServiceAccount",
                    name,
                    "Auto-mounts API token",
                    format!(
                        "ServiceAccount {} in {} automatically mounts API token",
                        name, ns
                    ),
                )
                .with_namespace(ns)
                .with_remediation("Set automountServiceAccountToken: false if not needed")
            );
        }
    }

    Ok(issues)
}
