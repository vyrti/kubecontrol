//! AWS EKS-specific diagnostics
//!
//! Checks for common issues specific to Amazon Elastic Kubernetes Service clusters.
//! Includes IAM Roles for Service Accounts (IRSA), VPC CNI, EKS add-ons, and Pod Identity.

use crate::debug::types::{DebugCategory, DebugIssue, DebugReport, Severity};
use crate::error::KcError;
use k8s_openapi::api::core::v1::{ConfigMap, Node, Pod, ServiceAccount};
use kube::{api::ListParams, Api, Client};

#[cfg(feature = "aws")]
use aws_config::BehaviorVersion;

/// AWS SDK clients wrapper for EKS debugging
/// Only available when compiled with the "aws" feature
#[cfg(feature = "aws")]
pub struct AwsClients {
    pub iam: aws_sdk_iam::Client,
    pub eks: aws_sdk_eks::Client,
    pub sts: aws_sdk_sts::Client,
    pub cluster_name: Option<String>,
    pub region: Option<String>,
}

#[cfg(feature = "aws")]
impl AwsClients {
    /// Try to create AWS clients from environment/config
    pub async fn try_new(region: Option<String>, cluster_name: Option<String>) -> Option<Self> {
        let config_loader = if let Some(ref region) = region {
            aws_config::defaults(BehaviorVersion::latest())
                .region(aws_config::Region::new(region.clone()))
        } else {
            aws_config::defaults(BehaviorVersion::latest())
        };

        match config_loader.load().await {
            config => {
                // Try to verify credentials are available
                let sts = aws_sdk_sts::Client::new(&config);
                match sts.get_caller_identity().send().await {
                    Ok(_) => Some(Self {
                        iam: aws_sdk_iam::Client::new(&config),
                        eks: aws_sdk_eks::Client::new(&config),
                        sts,
                        cluster_name,
                        region,
                    }),
                    Err(_) => None, // No valid AWS credentials
                }
            }
        }
    }
}

/// Run all EKS-specific diagnostics
pub async fn debug_eks(client: &Client, namespace: Option<&str>) -> Result<DebugReport, KcError> {
    let mut issues = Vec::new();

    // Get nodes for detection and region/cluster extraction
    let nodes: Api<Node> = Api::all(client.clone());
    let node_list = nodes
        .list(&ListParams::default())
        .await
        .map_err(|e| KcError::Config(e.to_string()))?;

    // Extract region and cluster name from nodes
    let region = extract_region(&node_list.items);
    let cluster_name = extract_cluster_name(&node_list.items);

    // Try to initialize AWS clients (only with "aws" feature)
    #[cfg(feature = "aws")]
    let aws_clients = AwsClients::try_new(region.clone(), cluster_name.clone()).await;
    #[cfg(not(feature = "aws"))]
    let aws_clients: Option<()> = None;

    // Run K8s-only checks in parallel
    let (irsa_issues, addon_issues, node_issues, pod_identity_issues, config_issues) = tokio::join!(
        check_irsa(client, namespace),
        check_eks_addons(client),
        check_eks_node_config(client),
        check_pod_identity(client, namespace),
        check_aws_auth_config(client),
    );

    if let Ok(i) = irsa_issues {
        issues.extend(i);
    }
    if let Ok(i) = addon_issues {
        issues.extend(i);
    }
    if let Ok(i) = node_issues {
        issues.extend(i);
    }
    if let Ok(i) = pod_identity_issues {
        issues.extend(i);
    }
    if let Ok(i) = config_issues {
        issues.extend(i);
    }

    // Run AWS API checks if credentials available
    #[cfg(feature = "aws")]
    if let Some(ref aws) = aws_clients {
        if let Ok(i) = check_eks_cluster_config(aws).await {
            issues.extend(i);
        }
        if let Ok(i) = check_irsa_iam_roles(client, namespace, aws).await {
            issues.extend(i);
        }
    }

    // Add info if AWS credentials not available
    #[cfg(feature = "aws")]
    if aws_clients.is_none() {
        issues.push(
            DebugIssue::new(
                Severity::Info,
                DebugCategory::Cluster,
                "AWS",
                "credentials",
                "AWS Credentials Not Available",
                "Unable to validate AWS-specific configuration. Some checks are skipped.",
            )
            .with_remediation(
                "Configure AWS credentials via environment variables, ~/.aws/credentials, or IAM role",
            ),
        );
    }

    #[cfg(not(feature = "aws"))]
    {
        issues.push(
            DebugIssue::new(
                Severity::Info,
                DebugCategory::Cluster,
                "AWS",
                "feature",
                "AWS SDK Not Enabled",
                "Build with --features aws to enable full AWS/IAM validation.",
            )
            .with_remediation("Rebuild with: cargo build --features aws"),
        );
    }

    Ok(DebugReport::new("eks", issues))
}

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

/// Check EKS add-ons health (VPC CNI, CoreDNS, kube-proxy, CSI drivers)
pub async fn check_eks_addons(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let pods: Api<Pod> = Api::namespaced(client.clone(), "kube-system");

    // Check aws-node (VPC CNI) DaemonSet pods
    let aws_node_pods = pods
        .list(&ListParams::default().labels("k8s-app=aws-node"))
        .await
        .map(|list| list.items)
        .unwrap_or_default();

    if aws_node_pods.is_empty() {
        issues.push(
            DebugIssue::new(
                Severity::Critical,
                DebugCategory::Network,
                "DaemonSet",
                "aws-node",
                "VPC CNI Not Found",
                "No aws-node pods found. The VPC CNI plugin is required for pod networking.",
            )
            .with_namespace("kube-system")
            .with_remediation("Install the VPC CNI add-on via AWS console or eksctl"),
        );
    } else {
        let unhealthy: Vec<_> = aws_node_pods
            .iter()
            .filter(|pod| {
                let phase = pod
                    .status
                    .as_ref()
                    .and_then(|s| s.phase.as_ref())
                    .map(|p| p.as_str())
                    .unwrap_or("");
                phase != "Running"
            })
            .collect();

        let crashlooping: Vec<_> = aws_node_pods
            .iter()
            .filter(|pod| {
                pod.status
                    .as_ref()
                    .and_then(|s| s.container_statuses.as_ref())
                    .map(|statuses| {
                        statuses.iter().any(|cs| {
                            cs.state
                                .as_ref()
                                .and_then(|s| s.waiting.as_ref())
                                .map(|w| w.reason.as_deref() == Some("CrashLoopBackOff"))
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false)
            })
            .collect();

        if !crashlooping.is_empty() {
            issues.push(
                DebugIssue::new(
                    Severity::Critical,
                    DebugCategory::Network,
                    "DaemonSet",
                    "aws-node",
                    "VPC CNI CrashLoopBackOff",
                    format!(
                        "{} aws-node pods are in CrashLoopBackOff. Pod networking is impaired.",
                        crashlooping.len()
                    ),
                )
                .with_namespace("kube-system")
                .with_remediation(
                    "Check aws-node logs for ENI allocation errors or IAM permission issues",
                ),
            );
        } else if !unhealthy.is_empty() {
            issues.push(
                DebugIssue::new(
                    Severity::Critical,
                    DebugCategory::Network,
                    "DaemonSet",
                    "aws-node",
                    "VPC CNI Unhealthy",
                    format!(
                        "{} of {} aws-node pods are not running",
                        unhealthy.len(),
                        aws_node_pods.len()
                    ),
                )
                .with_namespace("kube-system")
                .with_remediation("Check aws-node pod logs and events for errors"),
            );
        }

        // Check for IP address exhaustion warnings in aws-node env
        for pod in &aws_node_pods {
            if let Some(spec) = &pod.spec {
                for container in &spec.containers {
                    if container.name == "aws-node" {
                        let envs = container.env.as_ref();
                        let warm_ip_target = envs
                            .and_then(|e| e.iter().find(|v| v.name == "WARM_IP_TARGET"))
                            .and_then(|v| v.value.as_ref());
                        let prefix_delegation = envs
                            .and_then(|e| e.iter().find(|v| v.name == "ENABLE_PREFIX_DELEGATION"))
                            .and_then(|v| v.value.as_ref());

                        if warm_ip_target.is_none() && prefix_delegation != Some(&"true".to_string())
                        {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Info,
                                    DebugCategory::Network,
                                    "DaemonSet",
                                    "aws-node",
                                    "VPC CNI Default IP Mode",
                                    "VPC CNI using default IP allocation. Consider prefix delegation for larger clusters.",
                                )
                                .with_namespace("kube-system")
                                .with_remediation(
                                    "Enable ENABLE_PREFIX_DELEGATION=true for more efficient IP allocation",
                                ),
                            );
                        }
                        break;
                    }
                }
            }
        }
    }

    // Check CoreDNS
    let coredns_pods = pods
        .list(&ListParams::default().labels("k8s-app=kube-dns"))
        .await
        .map(|list| list.items)
        .unwrap_or_default();

    let coredns_unhealthy: Vec<_> = coredns_pods
        .iter()
        .filter(|pod| {
            pod.status
                .as_ref()
                .and_then(|s| s.phase.as_ref())
                .map(|p| p != "Running")
                .unwrap_or(true)
        })
        .collect();

    if !coredns_unhealthy.is_empty() && !coredns_pods.is_empty() {
        issues.push(
            DebugIssue::new(
                Severity::Critical,
                DebugCategory::Dns,
                "Deployment",
                "coredns",
                "CoreDNS Unhealthy",
                format!(
                    "{} of {} CoreDNS pods are not running. DNS resolution may fail.",
                    coredns_unhealthy.len(),
                    coredns_pods.len()
                ),
            )
            .with_namespace("kube-system")
            .with_remediation("Check CoreDNS pod logs and ensure coredns deployment is healthy"),
        );
    }

    // Check kube-proxy
    let kube_proxy_pods = pods
        .list(&ListParams::default().labels("k8s-app=kube-proxy"))
        .await
        .map(|list| list.items)
        .unwrap_or_default();

    let kube_proxy_unhealthy: Vec<_> = kube_proxy_pods
        .iter()
        .filter(|pod| {
            pod.status
                .as_ref()
                .and_then(|s| s.phase.as_ref())
                .map(|p| p != "Running")
                .unwrap_or(true)
        })
        .collect();

    if !kube_proxy_unhealthy.is_empty() && !kube_proxy_pods.is_empty() {
        issues.push(
            DebugIssue::new(
                Severity::Critical,
                DebugCategory::Network,
                "DaemonSet",
                "kube-proxy",
                "kube-proxy Unhealthy",
                format!(
                    "{} of {} kube-proxy pods are not running. Service networking may fail.",
                    kube_proxy_unhealthy.len(),
                    kube_proxy_pods.len()
                ),
            )
            .with_namespace("kube-system")
            .with_remediation("Check kube-proxy pod logs and DaemonSet status"),
        );
    }

    // Check EBS CSI driver
    let ebs_csi_pods = pods
        .list(&ListParams::default().labels("app.kubernetes.io/name=aws-ebs-csi-driver"))
        .await
        .map(|list| list.items)
        .unwrap_or_default();

    if ebs_csi_pods.is_empty() {
        // Check if there are any EBS-backed PVCs
        let pvcs: Api<k8s_openapi::api::core::v1::PersistentVolumeClaim> =
            Api::all(client.clone());
        let pvc_list = pvcs
            .list(&ListParams::default())
            .await
            .map(|list| list.items)
            .unwrap_or_default();

        let has_ebs_pvcs = pvc_list.iter().any(|pvc| {
            pvc.spec
                .as_ref()
                .and_then(|s| s.storage_class_name.as_ref())
                .map(|sc| sc.contains("ebs") || sc == "gp2" || sc == "gp3")
                .unwrap_or(false)
        });

        if has_ebs_pvcs {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Storage,
                    "Addon",
                    "aws-ebs-csi-driver",
                    "EBS CSI Driver Not Found",
                    "PVCs referencing EBS storage found but aws-ebs-csi-driver is not installed.",
                )
                .with_namespace("kube-system")
                .with_remediation(
                    "Install the EBS CSI driver add-on: aws eks create-addon --addon-name aws-ebs-csi-driver",
                ),
            );
        }
    }

    Ok(issues)
}

/// Check EKS node configuration
pub async fn check_eks_node_config(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let nodes: Api<Node> = Api::all(client.clone());
    let node_list = nodes
        .list(&ListParams::default())
        .await
        .map_err(|e| KcError::Config(e.to_string()))?;

    for node in node_list {
        let node_name = node.metadata.name.clone().unwrap_or_default();
        let labels = node.metadata.labels.clone().unwrap_or_default();

        // Check for NetworkUnavailable condition
        if let Some(status) = &node.status {
            if let Some(conditions) = &status.conditions {
                for condition in conditions {
                    if condition.type_ == "NetworkUnavailable" && condition.status == "True" {
                        issues.push(
                            DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Network,
                                "Node",
                                &node_name,
                                "Node Network Unavailable",
                                format!(
                                    "Node has NetworkUnavailable condition: {}",
                                    condition.message.as_deref().unwrap_or("unknown reason")
                                ),
                            )
                            .with_remediation(
                                "Check aws-node pod on this node and VPC CNI configuration",
                            ),
                        );
                    }
                }
            }
        }

        // Check if node is in a managed nodegroup
        let in_managed_ng = labels.contains_key("eks.amazonaws.com/nodegroup");
        let in_eksctl_ng = labels.contains_key("alpha.eksctl.io/nodegroup-name");

        if !in_managed_ng && !in_eksctl_ng {
            issues.push(
                DebugIssue::new(
                    Severity::Info,
                    DebugCategory::Cluster,
                    "Node",
                    &node_name,
                    "Self-Managed Node",
                    "Node is not part of an EKS managed nodegroup or eksctl nodegroup.",
                )
                .with_remediation(
                    "Consider using managed node groups for easier lifecycle management",
                ),
            );
        }

        // Check instance metadata version (IMDSv2)
        // This is visible in node annotations if configured
        let annotations = node.metadata.annotations.clone().unwrap_or_default();
        let imds_hop_limit = annotations.get("node.kubernetes.io/instance-metadata-hop-limit");

        // If hop limit is 1, IMDSv2 is required (good)
        // If not set or > 1, might be using IMDSv1
        if imds_hop_limit.map(|v| v != "1").unwrap_or(true) {
            // Only warn for nodes that appear to be EC2 instances
            if labels.contains_key("node.kubernetes.io/instance-type") {
                issues.push(
                    DebugIssue::new(
                        Severity::Info,
                        DebugCategory::Security,
                        "Node",
                        &node_name,
                        "IMDSv2 Not Enforced",
                        "Node may allow IMDSv1 access. IMDSv2 is recommended for security.",
                    )
                    .with_remediation(
                        "Configure launch template with HttpTokens=required and HttpPutResponseHopLimit=1",
                    ),
                );
            }
        }

        // Check for capacity issues
        if let Some(status) = &node.status {
            if let Some(allocatable) = &status.allocatable {
                // Check pods capacity
                if let Some(pods) = allocatable.get("pods") {
                    if let Ok(pod_count) = pods.0.parse::<i32>() {
                        if pod_count < 10 {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Warning,
                                    DebugCategory::Resources,
                                    "Node",
                                    &node_name,
                                    "Low Pod Capacity",
                                    format!(
                                        "Node can only allocate {} pods. Consider larger instance type.",
                                        pod_count
                                    ),
                                )
                                .with_remediation(
                                    "Use a larger instance type or enable VPC CNI prefix delegation",
                                ),
                            );
                        }
                    }
                }
            }
        }
    }

    Ok(issues)
}

/// Check for EKS Pod Identity configuration
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

/// Check aws-auth ConfigMap for IAM mappings
pub async fn check_aws_auth_config(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let configmaps: Api<ConfigMap> = Api::namespaced(client.clone(), "kube-system");

    match configmaps.get("aws-auth").await {
        Ok(cm) => {
            let data = cm.data.unwrap_or_default();

            // Check mapRoles
            if let Some(map_roles) = data.get("mapRoles") {
                if map_roles.trim().is_empty() {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Security,
                            "ConfigMap",
                            "aws-auth",
                            "Empty mapRoles",
                            "aws-auth ConfigMap has empty mapRoles. Node IAM roles may not have cluster access.",
                        )
                        .with_namespace("kube-system")
                        .with_remediation("Add node IAM role mapping to mapRoles"),
                    );
                }

                // Check for common misconfigurations
                if map_roles.contains("system:masters") {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Security,
                            "ConfigMap",
                            "aws-auth",
                            "system:masters Group Used",
                            "aws-auth mapRoles uses system:masters group. This grants full cluster admin access.",
                        )
                        .with_namespace("kube-system")
                        .with_remediation(
                            "Consider using more restrictive groups for non-admin roles",
                        ),
                    );
                }
            }

            // Check mapUsers
            if let Some(map_users) = data.get("mapUsers") {
                if map_users.contains("system:masters") {
                    issues.push(
                        DebugIssue::new(
                            Severity::Info,
                            DebugCategory::Security,
                            "ConfigMap",
                            "aws-auth",
                            "IAM Users with system:masters",
                            "aws-auth mapUsers has users in system:masters group.",
                        )
                        .with_namespace("kube-system")
                        .with_remediation(
                            "Review if all users need full admin access. Consider RBAC for fine-grained permissions.",
                        ),
                    );
                }
            }
        }
        Err(kube::Error::Api(e)) if e.code == 404 => {
            // aws-auth not found - this is unusual for EKS
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Security,
                    "ConfigMap",
                    "aws-auth",
                    "aws-auth ConfigMap Not Found",
                    "The aws-auth ConfigMap is missing from kube-system. IAM authentication may not work correctly.",
                )
                .with_namespace("kube-system")
                .with_remediation(
                    "Create the aws-auth ConfigMap with appropriate IAM role/user mappings",
                ),
            );
        }
        Err(_) => {
            // Other error - just skip this check
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

// ============================================================================
// Detection and utility functions
// ============================================================================

/// Check if cluster is running on EKS
pub fn is_eks(nodes: &[Node]) -> bool {
    nodes.iter().any(|node| {
        let labels = node.metadata.labels.as_ref();
        let provider_id = node
            .spec
            .as_ref()
            .and_then(|s| s.provider_id.as_ref());

        // Check for EKS-specific labels
        let has_eks_labels = labels
            .map(|l| {
                l.contains_key("eks.amazonaws.com/nodegroup")
                    || l.contains_key("eks.amazonaws.com/nodegroup-image")
                    || l.contains_key("alpha.eksctl.io/nodegroup-name")
            })
            .unwrap_or(false);

        // Check for AWS provider ID
        let has_aws_provider = provider_id
            .map(|p| p.starts_with("aws://"))
            .unwrap_or(false);

        has_eks_labels || has_aws_provider
    })
}

/// Extract AWS region from nodes
fn extract_region(nodes: &[Node]) -> Option<String> {
    for node in nodes {
        if let Some(labels) = &node.metadata.labels {
            // Try standard topology label
            if let Some(region) = labels.get("topology.kubernetes.io/region") {
                return Some(region.clone());
            }
            // Try legacy label
            if let Some(region) = labels.get("failure-domain.beta.kubernetes.io/region") {
                return Some(region.clone());
            }
        }
    }
    // Fall back to environment variable
    std::env::var("AWS_REGION")
        .or_else(|_| std::env::var("AWS_DEFAULT_REGION"))
        .ok()
}

/// Extract EKS cluster name from nodes
fn extract_cluster_name(nodes: &[Node]) -> Option<String> {
    for node in nodes {
        if let Some(labels) = &node.metadata.labels {
            // Try eksctl cluster name label
            if let Some(name) = labels.get("alpha.eksctl.io/cluster-name") {
                return Some(name.clone());
            }
            // Try EKS managed nodegroup cluster name
            if let Some(name) = labels.get("eks.amazonaws.com/cluster-name") {
                return Some(name.clone());
            }
        }
    }
    None
}
