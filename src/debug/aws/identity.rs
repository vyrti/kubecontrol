//! AWS IAM and Identity checks for EKS
//!
//! Includes IRSA (IAM Roles for Service Accounts), Pod Identity, and cluster authentication.

use crate::debug::types::{DebugCategory, DebugIssue, Severity};
use crate::error::KcError;
use k8s_openapi::api::core::v1::{Pod, ServiceAccount};
use kube::{api::ListParams, Api, Client};

#[cfg(feature = "aws")]
use super::AwsClients;

/// Check for IAM Roles for Service Accounts (IRSA) issues (K8s-side only)
pub async fn check_irsa(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Get ServiceAccounts
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

        // Check for IRSA role-arn annotation
        let role_arn = annotations.get("eks.amazonaws.com/role-arn");

        // Skip default ServiceAccounts without IRSA
        if sa_name == "default" && role_arn.is_none() {
            continue;
        }

        // Get pods using this ServiceAccount
        let pods: Api<Pod> = Api::namespaced(client.clone(), &sa_ns);
        let pod_list = pods
            .list(&ListParams::default().fields(&format!("spec.serviceAccountName={}", sa_name)))
            .await
            .map(|list| list.items)
            .unwrap_or_default();

        if let Some(arn) = role_arn {
            // Validate ARN format
            if !arn.starts_with("arn:aws:iam::") || !arn.contains(":role/") {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Security,
                        "ServiceAccount",
                        &sa_name,
                        "Invalid IRSA Role ARN Format",
                        format!("ServiceAccount has invalid IAM role ARN format: {}", arn),
                    )
                    .with_namespace(&sa_ns)
                    .with_remediation("Use format: arn:aws:iam::ACCOUNT_ID:role/ROLE_NAME"),
                );
            }

            // Check if pods have the expected IRSA environment variables
            for pod in &pod_list {
                let pod_name = pod.metadata.name.clone().unwrap_or_default();

                if let Some(spec) = &pod.spec {
                    for container in &spec.containers {
                        let has_irsa_env = container
                            .env
                            .as_ref()
                            .map(|envs| {
                                envs.iter().any(|e| {
                                    e.name == "AWS_ROLE_ARN"
                                        || e.name == "AWS_WEB_IDENTITY_TOKEN_FILE"
                                })
                            })
                            .unwrap_or(false);

                        let has_irsa_volume = spec
                            .volumes
                            .as_ref()
                            .map(|vols| {
                                vols.iter()
                                    .any(|v| v.name.contains("aws-iam-token") || v.name.contains("eks-"))
                            })
                            .unwrap_or(false);

                        if !has_irsa_env && !has_irsa_volume {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Warning,
                                    DebugCategory::Security,
                                    "Pod",
                                    &pod_name,
                                    "IRSA Not Injected",
                                    format!(
                                        "Pod uses ServiceAccount '{}' with IRSA but token not injected into container '{}'",
                                        sa_name, container.name
                                    ),
                                )
                                .with_namespace(&sa_ns)
                                .with_remediation(
                                    "Ensure the EKS Pod Identity Webhook is running in kube-system",
                                ),
                            );
                        }
                    }
                }

                // Check for IRSA-related issues in pod status
                if let Some(status) = &pod.status {
                    if let Some(container_statuses) = &status.container_statuses {
                        for cs in container_statuses {
                            if let Some(state) = &cs.state {
                                if let Some(waiting) = &state.waiting {
                                    if let Some(message) = &waiting.message {
                                        if message.contains("sts.amazonaws.com")
                                            || message.contains("AssumeRoleWithWebIdentity")
                                            || message.contains("AccessDenied")
                                        {
                                            issues.push(
                                                DebugIssue::new(
                                                    Severity::Critical,
                                                    DebugCategory::Security,
                                                    "Pod",
                                                    &pod_name,
                                                    "IRSA Authentication Failed",
                                                    format!("Pod has IRSA authentication issues: {}", message),
                                                )
                                                .with_namespace(&sa_ns)
                                                .with_remediation(
                                                    "Verify IAM role trust policy allows the OIDC provider and correct service account",
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

            // Info: ServiceAccount with IRSA but no pods
            if pod_list.is_empty() && sa_name != "default" {
                issues.push(
                    DebugIssue::new(
                        Severity::Info,
                        DebugCategory::Security,
                        "ServiceAccount",
                        &sa_name,
                        "IRSA Configured But Unused",
                        format!(
                            "ServiceAccount '{}' has IRSA annotation but no pods are using it",
                            sa_name
                        ),
                    )
                    .with_namespace(&sa_ns),
                );
            }
        } else if !pod_list.is_empty() && sa_name != "default" {
            // Non-default SA used by pods but no IRSA - informational
            issues.push(
                DebugIssue::new(
                    Severity::Info,
                    DebugCategory::Security,
                    "ServiceAccount",
                    &sa_name,
                    "No IRSA Configured",
                    format!(
                        "ServiceAccount '{}' is used by {} pods but has no IRSA annotation",
                        sa_name,
                        pod_list.len()
                    ),
                )
                .with_namespace(&sa_ns)
                .with_remediation(
                    "Consider enabling IRSA for fine-grained AWS permissions instead of node IAM role",
                ),
            );
        }
    }

    Ok(issues)
}

/// Check EKS Pod Identity configuration
pub async fn check_pod_identity(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let pods: Api<Pod> = Api::namespaced(client.clone(), "kube-system");

    // Check for EKS Pod Identity Agent
    let pod_identity_agent = pods
        .list(&ListParams::default().labels("app.kubernetes.io/name=eks-pod-identity-agent"))
        .await
        .map(|list| list.items)
        .unwrap_or_default();

    let has_pod_identity_agent = !pod_identity_agent.is_empty();

    if has_pod_identity_agent {
        let unhealthy: Vec<_> = pod_identity_agent
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
                    "eks-pod-identity-agent",
                    "Pod Identity Agent Unhealthy",
                    format!(
                        "{} of {} Pod Identity agent pods are not running",
                        unhealthy.len(),
                        pod_identity_agent.len()
                    ),
                )
                .with_namespace("kube-system")
                .with_remediation("Check eks-pod-identity-agent pod logs and events"),
            );
        }
    }

    // Check for ServiceAccounts that might benefit from Pod Identity
    let service_accounts: Api<ServiceAccount> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    let sa_list = service_accounts
        .list(&ListParams::default())
        .await
        .map(|list| list.items)
        .unwrap_or_default();

    for sa in sa_list {
        let sa_name = sa.metadata.name.clone().unwrap_or_default();
        let sa_ns = sa.metadata.namespace.clone().unwrap_or_default();
        let annotations = sa.metadata.annotations.clone().unwrap_or_default();

        // Check if using both IRSA and potentially Pod Identity
        let has_irsa = annotations.contains_key("eks.amazonaws.com/role-arn");
        let has_pod_identity_annotation = annotations.contains_key("eks.amazonaws.com/pod-identity-association");

        if has_irsa && has_pod_identity_annotation {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Security,
                    "ServiceAccount",
                    &sa_name,
                    "Both IRSA and Pod Identity Configured",
                    "ServiceAccount has both IRSA annotation and Pod Identity association. This may cause confusion.",
                )
                .with_namespace(&sa_ns)
                .with_remediation("Choose one method: IRSA or Pod Identity, and remove the other"),
            );
        }
    }

    Ok(issues)
}

/// Check EKS cluster configuration via AWS API (requires AWS credentials)
#[cfg(feature = "aws")]
pub async fn check_eks_cluster_config(
    aws: &AwsClients,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let Some(cluster_name) = &aws.cluster_name else {
        return Ok(issues);
    };

    match aws.eks.describe_cluster().name(cluster_name).send().await {
        Ok(response) => {
            if let Some(cluster) = response.cluster {
                // Check OIDC provider
                let has_oidc = cluster
                    .identity
                    .as_ref()
                    .and_then(|i| i.oidc.as_ref())
                    .and_then(|o| o.issuer.as_ref())
                    .is_some();

                if !has_oidc {
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Security,
                            "Cluster",
                            cluster_name,
                            "OIDC Provider Not Configured",
                            "EKS cluster does not have an OIDC provider. IRSA will not work.",
                        )
                        .with_remediation(
                            "Enable OIDC provider: eksctl utils associate-iam-oidc-provider --cluster CLUSTER_NAME --approve",
                        ),
                    );
                }

                // Check endpoint access
                if let Some(vpc_config) = &cluster.resources_vpc_config {
                    let public_access = vpc_config.endpoint_public_access;
                    let private_access = vpc_config.endpoint_private_access;
                    let public_cidrs = vpc_config.public_access_cidrs.as_ref();

                    if public_access {
                        let unrestricted = public_cidrs
                            .map(|cidrs| cidrs.iter().any(|c| c == "0.0.0.0/0"))
                            .unwrap_or(true);

                        if unrestricted {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Warning,
                                    DebugCategory::Security,
                                    "Cluster",
                                    cluster_name,
                                    "Public Endpoint Without Restrictions",
                                    "EKS cluster public endpoint is accessible from 0.0.0.0/0.",
                                )
                                .with_remediation(
                                    "Restrict public endpoint access via CIDR blocks or disable public endpoint",
                                ),
                            );
                        }
                    }

                    if !private_access {
                        issues.push(
                            DebugIssue::new(
                                Severity::Info,
                                DebugCategory::Security,
                                "Cluster",
                                cluster_name,
                                "Private Endpoint Disabled",
                                "EKS cluster private endpoint is disabled. All API access goes through public endpoint.",
                            )
                            .with_remediation(
                                "Enable private endpoint for secure access from within VPC",
                            ),
                        );
                    }
                }

                // Check logging
                if let Some(logging) = &cluster.logging {
                    if let Some(cluster_logging) = &logging.cluster_logging {
                        let enabled_logs: Vec<_> = cluster_logging
                            .iter()
                            .filter(|l| l.enabled.unwrap_or(false))
                            .flat_map(|l| l.types.clone().unwrap_or_default())
                            .collect();

                        if enabled_logs.is_empty() {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Info,
                                    DebugCategory::Cluster,
                                    "Cluster",
                                    cluster_name,
                                    "Control Plane Logging Disabled",
                                    "No control plane logs are being sent to CloudWatch.",
                                )
                                .with_remediation(
                                    "Enable logging for api, audit, authenticator, controllerManager, scheduler",
                                ),
                            );
                        }
                    }
                }

                // Check encryption
                if cluster.encryption_config.as_ref().map(|e| e.is_empty()).unwrap_or(true) {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Security,
                            "Cluster",
                            cluster_name,
                            "Secrets Encryption Not Configured",
                            "EKS cluster does not have envelope encryption for Kubernetes secrets.",
                        )
                        .with_remediation(
                            "Enable secrets encryption with a KMS key for compliance requirements",
                        ),
                    );
                }
            }
        }
        Err(e) => {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Cluster,
                    "AWS",
                    "eks",
                    "Could Not Describe Cluster",
                    format!("Unable to get EKS cluster details: {}", e),
                )
                .with_remediation("Verify IAM permissions include eks:DescribeCluster"),
            );
        }
    }

    Ok(issues)
}

/// Validate IRSA IAM roles via AWS API (requires AWS credentials)
#[cfg(feature = "aws")]
pub async fn check_irsa_iam_roles(
    client: &Client,
    namespace: Option<&str>,
    aws: &AwsClients,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

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

        if let Some(role_arn) = annotations.get("eks.amazonaws.com/role-arn") {
            // Extract role name from ARN
            let role_name = role_arn
                .split('/')
                .last()
                .unwrap_or(role_arn);

            // Try to get the role
            match aws.iam.get_role().role_name(role_name).send().await {
                Ok(response) => {
                    if let Some(role) = response.role {
                        // Check trust policy for OIDC provider
                        if let Some(policy_doc) = role.assume_role_policy_document {
                            let decoded = urlencoding::decode(&policy_doc).unwrap_or_default();

                            if !decoded.contains("oidc.eks") && !decoded.contains("sts:AssumeRoleWithWebIdentity") {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Security,
                                        "IAM Role",
                                        role_name,
                                        "Trust Policy Missing OIDC Provider",
                                        format!(
                                            "IAM role '{}' trust policy does not reference EKS OIDC provider",
                                            role_name
                                        ),
                                    )
                                    .with_remediation(
                                        "Update role trust policy to allow AssumeRoleWithWebIdentity from EKS OIDC provider",
                                    ),
                                );
                            }

                            // Check for overly permissive trust policy (allows all service accounts)
                            if decoded.contains("*") && decoded.contains("sub") {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Warning,
                                        DebugCategory::Security,
                                        "IAM Role",
                                        role_name,
                                        "Overly Permissive Trust Policy",
                                        format!(
                                            "IAM role '{}' trust policy may allow any service account to assume it",
                                            role_name
                                        ),
                                    )
                                    .with_remediation(
                                        "Restrict trust policy to specific namespace:serviceaccount",
                                    ),
                                );
                            }
                        }

                        // List attached policies
                        if let Ok(policies) = aws
                            .iam
                            .list_attached_role_policies()
                            .role_name(role_name)
                            .send()
                            .await
                        {
                            let attached = policies.attached_policies.unwrap_or_default();

                            // Check for overly permissive policies
                            for policy in attached {
                                let policy_name = policy.policy_name.unwrap_or_default();
                                if policy_name == "AdministratorAccess" || policy_name == "PowerUserAccess" {
                                    issues.push(
                                        DebugIssue::new(
                                            Severity::Warning,
                                            DebugCategory::Security,
                                            "IAM Role",
                                            role_name,
                                            "Overly Permissive Policy Attached",
                                            format!(
                                                "IAM role '{}' has '{}' attached. This grants excessive permissions.",
                                                role_name, policy_name
                                            ),
                                        )
                                        .with_remediation(
                                            "Use least-privilege policies scoped to required actions and resources",
                                        ),
                                    );
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    let error_str = e.to_string();
                    if error_str.contains("NoSuchEntity") {
                        issues.push(
                            DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Security,
                                "ServiceAccount",
                                &sa_name,
                                "IRSA Role Not Found",
                                format!("IAM role '{}' referenced by ServiceAccount does not exist", role_name),
                            )
                            .with_namespace(&sa_ns)
                            .with_remediation(
                                "Create the IAM role or update the ServiceAccount annotation with correct role ARN",
                            ),
                        );
                    } else if error_str.contains("AccessDenied") {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Security,
                                "IAM Role",
                                role_name,
                                "Cannot Verify IAM Role",
                                format!("Access denied when checking IAM role '{}'. Unable to validate.", role_name),
                            )
                            .with_remediation(
                                "Ensure credentials have iam:GetRole permission",
                            ),
                        );
                    }
                }
            }
        }
    }

    Ok(issues)
}
