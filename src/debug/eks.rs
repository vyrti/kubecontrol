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

    // Run core EKS checks in parallel (batch 1)
    let (irsa_issues, addon_issues, node_issues, pod_identity_issues, auth_config_issues) = tokio::join!(
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
    if let Ok(i) = auth_config_issues {
        issues.extend(i);
    }

    // Run Kubernetes workload checks in parallel (batch 2)
    let (pod_issues, deployment_issues, service_issues, config_issues_k8s) = tokio::join!(
        check_pod_issues(client, namespace),
        check_deployment_issues(client, namespace),
        check_service_issues(client, namespace),
        check_config_issues(client, namespace),
    );

    if let Ok(i) = pod_issues {
        issues.extend(i);
    }
    if let Ok(i) = deployment_issues {
        issues.extend(i);
    }
    if let Ok(i) = service_issues {
        issues.extend(i);
    }
    if let Ok(i) = config_issues_k8s {
        issues.extend(i);
    }

    // Run additional workload checks in parallel (batch 3)
    let (rbac_issues, scheduling_issues, statefulset_issues, job_issues) = tokio::join!(
        check_rbac_issues(client, namespace),
        check_scheduling_issues(client, namespace),
        check_statefulset_issues(client, namespace),
        check_job_issues(client, namespace),
    );

    if let Ok(i) = rbac_issues {
        issues.extend(i);
    }
    if let Ok(i) = scheduling_issues {
        issues.extend(i);
    }
    if let Ok(i) = statefulset_issues {
        issues.extend(i);
    }
    if let Ok(i) = job_issues {
        issues.extend(i);
    }

    // Run infrastructure checks in parallel (batch 4)
    let (ingress_issues, webhook_issues, quota_issues) = tokio::join!(
        check_ingress_issues(client, namespace),
        check_webhook_issues(client),
        check_quota_issues(client, namespace),
    );

    if let Ok(i) = ingress_issues {
        issues.extend(i);
    }
    if let Ok(i) = webhook_issues {
        issues.extend(i);
    }
    if let Ok(i) = quota_issues {
        issues.extend(i);
    }

    // Run AWS-specific checks in parallel (batch 5)
    let (lb_issues, ecr_issues, observability_issues, node_group_issues) = tokio::join!(
        check_load_balancer_issues(client),
        check_ecr_issues(client, namespace),
        check_observability_issues(client),
        check_node_group_issues(client),
    );

    if let Ok(i) = lb_issues {
        issues.extend(i);
    }
    if let Ok(i) = ecr_issues {
        issues.extend(i);
    }
    if let Ok(i) = observability_issues {
        issues.extend(i);
    }
    if let Ok(i) = node_group_issues {
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
// Kubernetes workload checks
// ============================================================================

/// Check for pod issues (CrashLoopBackOff, OOMKilled, ImagePullBackOff, etc.)
pub async fn check_pod_issues(
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

        // Skip completed pods (Jobs)
        let phase = pod
            .status
            .as_ref()
            .and_then(|s| s.phase.as_ref())
            .map(|p| p.as_str())
            .unwrap_or("");

        if phase == "Succeeded" {
            continue;
        }

        // Check pod phase
        if phase == "Failed" {
            let reason = pod
                .status
                .as_ref()
                .and_then(|s| s.reason.as_ref())
                .map(|r| r.as_str())
                .unwrap_or("unknown");

            issues.push(
                DebugIssue::new(
                    Severity::Critical,
                    DebugCategory::Pod,
                    "Pod",
                    &pod_name,
                    "Pod Failed",
                    format!("Pod is in Failed state: {}", reason),
                )
                .with_namespace(&pod_ns)
                .with_remediation("Check pod events and logs for failure reason"),
            );
            continue;
        }

        // Check for Pending pods
        if phase == "Pending" {
            let pending_duration = pod
                .metadata
                .creation_timestamp
                .as_ref()
                .map(|ts| {
                    let now = chrono::Utc::now();
                    let created: chrono::DateTime<chrono::Utc> = ts.0;
                    now.signed_duration_since(created).num_seconds()
                })
                .unwrap_or(0);

            // Only alert if pending for more than 5 minutes
            if pending_duration > 300 {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Pod,
                        "Pod",
                        &pod_name,
                        "Pod Stuck Pending",
                        format!(
                            "Pod has been pending for {} seconds. Check scheduling constraints.",
                            pending_duration
                        ),
                    )
                    .with_namespace(&pod_ns)
                    .with_remediation(
                        "Check pod events for scheduling errors: insufficient resources, taints, node selectors",
                    ),
                );
            }
            continue;
        }

        // Check container statuses for Running pods
        if let Some(status) = &pod.status {
            // Check init container statuses
            if let Some(init_statuses) = &status.init_container_statuses {
                for init_cs in init_statuses {
                    if let Some(state) = &init_cs.state {
                        if let Some(waiting) = &state.waiting {
                            let reason = waiting.reason.as_deref().unwrap_or("unknown");
                            let message = waiting.message.as_deref().unwrap_or("");

                            if reason == "CrashLoopBackOff" {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Pod,
                                        "Pod",
                                        &pod_name,
                                        "Init Container CrashLoopBackOff",
                                        format!(
                                            "Init container '{}' is in CrashLoopBackOff: {}",
                                            init_cs.name, message
                                        ),
                                    )
                                    .with_namespace(&pod_ns)
                                    .with_remediation(
                                        "Check init container logs: kubectl logs POD -c INIT_CONTAINER",
                                    ),
                                );
                            }
                        }
                    }
                }
            }

            // Check container statuses
            if let Some(container_statuses) = &status.container_statuses {
                for cs in container_statuses {
                    let restart_count = cs.restart_count;

                    // Check for high restart count
                    if restart_count > 5 {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Pod,
                                "Pod",
                                &pod_name,
                                "High Restart Count",
                                format!(
                                    "Container '{}' has restarted {} times",
                                    cs.name, restart_count
                                ),
                            )
                            .with_namespace(&pod_ns)
                            .with_remediation("Check container logs and previous logs: kubectl logs POD -c CONTAINER --previous"),
                        );
                    }

                    // Check current state
                    if let Some(state) = &cs.state {
                        if let Some(waiting) = &state.waiting {
                            let reason = waiting.reason.as_deref().unwrap_or("unknown");
                            let message = waiting.message.as_deref().unwrap_or("");

                            match reason {
                                "CrashLoopBackOff" => {
                                    issues.push(
                                        DebugIssue::new(
                                            Severity::Critical,
                                            DebugCategory::Pod,
                                            "Pod",
                                            &pod_name,
                                            "CrashLoopBackOff",
                                            format!(
                                                "Container '{}' is in CrashLoopBackOff: {}",
                                                cs.name, message
                                            ),
                                        )
                                        .with_namespace(&pod_ns)
                                        .with_remediation(
                                            "Check container logs: kubectl logs POD -c CONTAINER --previous",
                                        ),
                                    );
                                }
                                "ImagePullBackOff" | "ErrImagePull" => {
                                    let remediation = if message.contains("repository does not exist")
                                        || message.contains("not found")
                                    {
                                        "Verify image name and tag exist in the registry"
                                    } else if message.contains("unauthorized") || message.contains("denied") {
                                        "Check image pull secrets and ECR/registry authentication"
                                    } else {
                                        "Check image name, tag, and pull secrets configuration"
                                    };

                                    issues.push(
                                        DebugIssue::new(
                                            Severity::Critical,
                                            DebugCategory::Pod,
                                            "Pod",
                                            &pod_name,
                                            "Image Pull Failed",
                                            format!(
                                                "Container '{}' cannot pull image: {}",
                                                cs.name, message
                                            ),
                                        )
                                        .with_namespace(&pod_ns)
                                        .with_remediation(remediation),
                                    );
                                }
                                "CreateContainerConfigError" => {
                                    issues.push(
                                        DebugIssue::new(
                                            Severity::Critical,
                                            DebugCategory::Pod,
                                            "Pod",
                                            &pod_name,
                                            "Container Config Error",
                                            format!(
                                                "Container '{}' has configuration error: {}",
                                                cs.name, message
                                            ),
                                        )
                                        .with_namespace(&pod_ns)
                                        .with_remediation(
                                            "Check ConfigMaps, Secrets, and environment variable references",
                                        ),
                                    );
                                }
                                "ContainerCreating" => {
                                    // Check if stuck for too long
                                    let pending_duration = pod
                                        .metadata
                                        .creation_timestamp
                                        .as_ref()
                                        .map(|ts| {
                                            let now = chrono::Utc::now();
                                            let created: chrono::DateTime<chrono::Utc> = ts.0;
                                            now.signed_duration_since(created).num_seconds()
                                        })
                                        .unwrap_or(0);

                                    if pending_duration > 300 {
                                        issues.push(
                                            DebugIssue::new(
                                                Severity::Critical,
                                                DebugCategory::Pod,
                                                "Pod",
                                                &pod_name,
                                                "Stuck Creating Container",
                                                format!(
                                                    "Container '{}' stuck in ContainerCreating for {} seconds",
                                                    cs.name, pending_duration
                                                ),
                                            )
                                            .with_namespace(&pod_ns)
                                            .with_remediation(
                                                "Check pod events for volume mount or network issues",
                                            ),
                                        );
                                    }
                                }
                                _ => {}
                            }
                        }

                        if let Some(terminated) = &state.terminated {
                            let exit_code = terminated.exit_code;
                            let reason = terminated.reason.as_deref().unwrap_or("unknown");

                            if reason == "OOMKilled" || exit_code == 137 {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Pod,
                                        "Pod",
                                        &pod_name,
                                        "OOMKilled",
                                        format!(
                                            "Container '{}' was killed due to Out Of Memory",
                                            cs.name
                                        ),
                                    )
                                    .with_namespace(&pod_ns)
                                    .with_remediation(
                                        "Increase memory limits or optimize application memory usage",
                                    ),
                                );
                            } else if exit_code == 1 {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Warning,
                                        DebugCategory::Pod,
                                        "Pod",
                                        &pod_name,
                                        "Container Error Exit",
                                        format!(
                                            "Container '{}' exited with error code 1",
                                            cs.name
                                        ),
                                    )
                                    .with_namespace(&pod_ns)
                                    .with_remediation(
                                        "Check container logs for application errors",
                                    ),
                                );
                            }
                        }
                    }

                    // Check last termination state for OOMKilled
                    if let Some(last_state) = &cs.last_state {
                        if let Some(terminated) = &last_state.terminated {
                            if terminated.reason.as_deref() == Some("OOMKilled") {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Warning,
                                        DebugCategory::Pod,
                                        "Pod",
                                        &pod_name,
                                        "Previous OOMKill",
                                        format!(
                                            "Container '{}' was previously OOMKilled",
                                            cs.name
                                        ),
                                    )
                                    .with_namespace(&pod_ns)
                                    .with_remediation(
                                        "Increase memory limits or optimize application memory usage",
                                    ),
                                );
                            }
                        }
                    }
                }
            }

            // Check for Evicted pods
            if let Some(reason) = &status.reason {
                if reason == "Evicted" {
                    let message = status.message.as_deref().unwrap_or("unknown reason");
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Pod,
                            "Pod",
                            &pod_name,
                            "Pod Evicted",
                            format!("Pod was evicted: {}", message),
                        )
                        .with_namespace(&pod_ns)
                        .with_remediation(
                            "Check node resources (disk pressure, memory pressure) and pod priority",
                        ),
                    );
                }
            }
        }

        // Check for security concerns in pod spec
        if let Some(spec) = &pod.spec {
            for container in &spec.containers {
                // Check for privileged containers
                if let Some(sec_ctx) = &container.security_context {
                    if sec_ctx.privileged == Some(true) {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Security,
                                "Pod",
                                &pod_name,
                                "Privileged Container",
                                format!("Container '{}' is running as privileged", container.name),
                            )
                            .with_namespace(&pod_ns)
                            .with_remediation(
                                "Avoid privileged containers unless absolutely necessary",
                            ),
                        );
                    }

                    if sec_ctx.run_as_user == Some(0) {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Security,
                                "Pod",
                                &pod_name,
                                "Running as Root",
                                format!("Container '{}' is running as root (UID 0)", container.name),
                            )
                            .with_namespace(&pod_ns)
                            .with_remediation(
                                "Set runAsNonRoot: true and specify a non-root runAsUser",
                            ),
                        );
                    }
                }

                // Check for missing resource limits
                let has_limits = container
                    .resources
                    .as_ref()
                    .and_then(|r| r.limits.as_ref())
                    .map(|l| !l.is_empty())
                    .unwrap_or(false);

                if !has_limits {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Resources,
                            "Pod",
                            &pod_name,
                            "No Resource Limits",
                            format!(
                                "Container '{}' has no resource limits set",
                                container.name
                            ),
                        )
                        .with_namespace(&pod_ns)
                        .with_remediation("Set CPU and memory limits to prevent resource contention"),
                    );
                }
            }

            // Check for host networking
            if spec.host_network == Some(true) {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Security,
                        "Pod",
                        &pod_name,
                        "Host Network Enabled",
                        "Pod is using host network namespace",
                    )
                    .with_namespace(&pod_ns)
                    .with_remediation("Avoid hostNetwork unless required for network monitoring"),
                );
            }

            if spec.host_pid == Some(true) {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Security,
                        "Pod",
                        &pod_name,
                        "Host PID Enabled",
                        "Pod is using host PID namespace",
                    )
                    .with_namespace(&pod_ns)
                    .with_remediation("Avoid hostPID unless required for process monitoring"),
                );
            }
        }
    }

    Ok(issues)
}

/// Check for deployment issues (replicas, rollout, HPA)
pub async fn check_deployment_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    use k8s_openapi::api::apps::v1::Deployment;
    use k8s_openapi::api::autoscaling::v2::HorizontalPodAutoscaler;

    let mut issues = Vec::new();

    let deployments: Api<Deployment> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    let deploy_list = deployments
        .list(&ListParams::default())
        .await
        .map_err(|e| KcError::Config(e.to_string()))?;

    for deploy in deploy_list {
        let deploy_name = deploy.metadata.name.clone().unwrap_or_default();
        let deploy_ns = deploy.metadata.namespace.clone().unwrap_or_default();

        if let Some(status) = &deploy.status {
            let desired = deploy
                .spec
                .as_ref()
                .and_then(|s| s.replicas)
                .unwrap_or(1);
            let available = status.available_replicas.unwrap_or(0);
            let ready = status.ready_replicas.unwrap_or(0);
            let updated = status.updated_replicas.unwrap_or(0);

            // Check for unavailable replicas
            if available < desired {
                let unavailable = desired - available;
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Deployment,
                        "Deployment",
                        &deploy_name,
                        "Replicas Unavailable",
                        format!(
                            "{} of {} replicas unavailable",
                            unavailable, desired
                        ),
                    )
                    .with_namespace(&deploy_ns)
                    .with_remediation("Check pod status and events for the deployment"),
                );
            }

            // Check for rollout issues
            if let Some(conditions) = &status.conditions {
                for condition in conditions {
                    if condition.type_ == "Progressing"
                        && condition.status == "False"
                        && condition.reason.as_deref() == Some("ProgressDeadlineExceeded")
                    {
                        issues.push(
                            DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Deployment,
                                "Deployment",
                                &deploy_name,
                                "Rollout Deadline Exceeded",
                                "Deployment rollout has exceeded its progress deadline",
                            )
                            .with_namespace(&deploy_ns)
                            .with_remediation(
                                "Check pod events and consider increasing progressDeadlineSeconds",
                            ),
                        );
                    }

                    if condition.type_ == "Available" && condition.status == "False" {
                        issues.push(
                            DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Deployment,
                                "Deployment",
                                &deploy_name,
                                "Deployment Not Available",
                                format!(
                                    "Deployment is not available: {}",
                                    condition.message.as_deref().unwrap_or("unknown reason")
                                ),
                            )
                            .with_namespace(&deploy_ns)
                            .with_remediation("Check pod status and events for the deployment"),
                        );
                    }

                    if condition.type_ == "ReplicaFailure" && condition.status == "True" {
                        issues.push(
                            DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Deployment,
                                "Deployment",
                                &deploy_name,
                                "Replica Failure",
                                format!(
                                    "Deployment has replica failure: {}",
                                    condition.message.as_deref().unwrap_or("unknown reason")
                                ),
                            )
                            .with_namespace(&deploy_ns)
                            .with_remediation("Check pod status and events"),
                        );
                    }
                }
            }

            // Check for stuck rollout (updated != desired)
            if updated < desired && updated > 0 {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Deployment,
                        "Deployment",
                        &deploy_name,
                        "Rollout In Progress",
                        format!(
                            "Rollout in progress: {} of {} replicas updated",
                            updated, desired
                        ),
                    )
                    .with_namespace(&deploy_ns)
                    .with_remediation("Monitor rollout progress or check for stuck pods"),
                );
            }

            // Check if not ready
            if ready < desired && ready < available {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Deployment,
                        "Deployment",
                        &deploy_name,
                        "Replicas Not Ready",
                        format!(
                            "{} of {} replicas not ready",
                            desired - ready,
                            desired
                        ),
                    )
                    .with_namespace(&deploy_ns)
                    .with_remediation("Check readiness probes and pod status"),
                );
            }
        }
    }

    // Check HPAs
    let hpas: Api<HorizontalPodAutoscaler> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(hpa_list) = hpas.list(&ListParams::default()).await {
        for hpa in hpa_list {
            let hpa_name = hpa.metadata.name.clone().unwrap_or_default();
            let hpa_ns = hpa.metadata.namespace.clone().unwrap_or_default();

            if let Some(status) = &hpa.status {
                let current = status.current_replicas.unwrap_or(0);
                let desired = status.desired_replicas;
                let max = hpa
                    .spec
                    .as_ref()
                    .map(|s| s.max_replicas)
                    .unwrap_or(10);

                // Check if at max replicas
                if current >= max && desired > current {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Resources,
                            "HPA",
                            &hpa_name,
                            "HPA at Maximum Replicas",
                            format!(
                                "HPA is at maximum replicas ({}) but wants {}",
                                max, desired
                            ),
                        )
                        .with_namespace(&hpa_ns)
                        .with_remediation("Consider increasing maxReplicas or adding more nodes"),
                    );
                }

                // Check for scaling issues
                if let Some(conditions) = &status.conditions {
                    for condition in conditions {
                        if condition.type_ == "ScalingActive" && condition.status == "False" {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Critical,
                                    DebugCategory::Resources,
                                    "HPA",
                                    &hpa_name,
                                    "HPA Scaling Inactive",
                                    format!(
                                        "HPA cannot scale: {}",
                                        condition.message.as_deref().unwrap_or("unknown reason")
                                    ),
                                )
                                .with_namespace(&hpa_ns)
                                .with_remediation("Check metrics-server and HPA target reference"),
                            );
                        }

                        if condition.type_ == "AbleToScale" && condition.status == "False" {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Critical,
                                    DebugCategory::Resources,
                                    "HPA",
                                    &hpa_name,
                                    "HPA Unable to Scale",
                                    format!(
                                        "HPA unable to scale: {}",
                                        condition.message.as_deref().unwrap_or("unknown reason")
                                    ),
                                )
                                .with_namespace(&hpa_ns)
                                .with_remediation("Check HPA target and resource availability"),
                            );
                        }

                        if condition.type_ == "ScalingLimited" && condition.status == "True" {
                            let reason = condition.reason.as_deref().unwrap_or("");
                            if reason.contains("ReadyPodCount") || reason.contains("TooManyReplicas") {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Warning,
                                        DebugCategory::Resources,
                                        "HPA",
                                        &hpa_name,
                                        "HPA Scaling Limited",
                                        format!(
                                            "HPA scaling is limited: {}",
                                            condition.message.as_deref().unwrap_or(reason)
                                        ),
                                    )
                                    .with_namespace(&hpa_ns)
                                    .with_remediation("Review min/max replicas configuration"),
                                );
                            }
                        }
                    }
                }
            }
        }
    }

    // Check PodDisruptionBudgets
    let pdbs: Api<k8s_openapi::api::policy::v1::PodDisruptionBudget> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(pdb_list) = pdbs.list(&ListParams::default()).await {
        for pdb in pdb_list {
            let pdb_name = pdb.metadata.name.clone().unwrap_or_default();
            let pdb_ns = pdb.metadata.namespace.clone().unwrap_or_default();

            if let Some(status) = &pdb.status {
                let disruptions_allowed = status.disruptions_allowed;
                let current_healthy = status.current_healthy;
                let desired_healthy = status.desired_healthy;

                if disruptions_allowed == 0 && current_healthy < desired_healthy {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Resources,
                            "PDB",
                            &pdb_name,
                            "PDB Blocking Disruptions",
                            format!(
                                "PDB allows 0 disruptions (current: {}, desired: {}). May block node drains.",
                                current_healthy, desired_healthy
                            ),
                        )
                        .with_namespace(&pdb_ns)
                        .with_remediation("Review minAvailable/maxUnavailable settings"),
                    );
                }
            }
        }
    }

    Ok(issues)
}

/// Check for service issues (no endpoints, selector mismatch)
pub async fn check_service_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    use k8s_openapi::api::core::v1::{Endpoints, Service};
    use k8s_openapi::api::discovery::v1::EndpointSlice;

    let mut issues = Vec::new();

    let services: Api<Service> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    let svc_list = services
        .list(&ListParams::default())
        .await
        .map_err(|e| KcError::Config(e.to_string()))?;

    for svc in svc_list {
        let svc_name = svc.metadata.name.clone().unwrap_or_default();
        let svc_ns = svc.metadata.namespace.clone().unwrap_or_default();

        // Skip services without selectors (ExternalName, headless without selector)
        let selector = svc
            .spec
            .as_ref()
            .and_then(|s| s.selector.as_ref());

        if selector.is_none() || selector.map(|s| s.is_empty()).unwrap_or(true) {
            continue;
        }

        // Check for LoadBalancer services
        let svc_type = svc
            .spec
            .as_ref()
            .and_then(|s| s.type_.as_ref())
            .map(|t| t.as_str())
            .unwrap_or("ClusterIP");

        if svc_type == "LoadBalancer" {
            // Check if LoadBalancer has an external IP
            let has_external_ip = svc
                .status
                .as_ref()
                .and_then(|s| s.load_balancer.as_ref())
                .and_then(|lb| lb.ingress.as_ref())
                .map(|ing| !ing.is_empty())
                .unwrap_or(false);

            if !has_external_ip {
                // Check how long it's been pending
                let pending_duration = svc
                    .metadata
                    .creation_timestamp
                    .as_ref()
                    .map(|ts| {
                        let now = chrono::Utc::now();
                        let created: chrono::DateTime<chrono::Utc> = ts.0;
                        now.signed_duration_since(created).num_seconds()
                    })
                    .unwrap_or(0);

                if pending_duration > 300 {
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Service,
                            "Service",
                            &svc_name,
                            "LoadBalancer Pending",
                            format!(
                                "LoadBalancer service has no external IP after {} seconds",
                                pending_duration
                            ),
                        )
                        .with_namespace(&svc_ns)
                        .with_remediation(
                            "Check AWS Load Balancer Controller logs and service events",
                        ),
                    );
                }
            }
        }

        // Check endpoints
        let endpoints: Api<Endpoints> = Api::namespaced(client.clone(), &svc_ns);
        if let Ok(ep) = endpoints.get(&svc_name).await {
            let has_endpoints = ep
                .subsets
                .as_ref()
                .map(|subsets| {
                    subsets
                        .iter()
                        .any(|s| s.addresses.as_ref().map(|a| !a.is_empty()).unwrap_or(false))
                })
                .unwrap_or(false);

            if !has_endpoints {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Service,
                        "Service",
                        &svc_name,
                        "No Endpoints",
                        "Service has no ready endpoints. Traffic will fail.",
                    )
                    .with_namespace(&svc_ns)
                    .with_remediation(
                        "Check if pods match the service selector and are in Ready state",
                    ),
                );
            }
        }

        // Check EndpointSlices for unhealthy endpoints
        let endpoint_slices: Api<EndpointSlice> = Api::namespaced(client.clone(), &svc_ns);
        let label_selector = format!("kubernetes.io/service-name={}", svc_name);
        if let Ok(ep_slices) = endpoint_slices
            .list(&ListParams::default().labels(&label_selector))
            .await
        {
            for slice in ep_slices {
                let endpoints = &slice.endpoints;
                let unhealthy_count = endpoints
                    .iter()
                    .filter(|ep| {
                        ep.conditions
                            .as_ref()
                            .and_then(|c| c.ready)
                            .map(|r| !r)
                            .unwrap_or(false)
                    })
                    .count();

                if unhealthy_count > 0 && !endpoints.is_empty() {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Service,
                            "Service",
                            &svc_name,
                                "Unhealthy Endpoints",
                                format!(
                                    "{} of {} endpoints are not ready",
                                    unhealthy_count,
                                    endpoints.len()
                                ),
                            )
                            .with_namespace(&svc_ns)
                            .with_remediation("Check pod readiness probes and pod status"),
                        );
                    }
            }
        }
    }

    Ok(issues)
}

/// Check for ConfigMap and Secret issues
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
pub async fn check_statefulset_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    use k8s_openapi::api::apps::v1::StatefulSet;
    use k8s_openapi::api::core::v1::{PersistentVolumeClaim, Service};

    let mut issues = Vec::new();

    let statefulsets: Api<StatefulSet> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    let sts_list = statefulsets
        .list(&ListParams::default())
        .await
        .map_err(|e| KcError::Config(e.to_string()))?;

    for sts in sts_list {
        let sts_name = sts.metadata.name.clone().unwrap_or_default();
        let sts_ns = sts.metadata.namespace.clone().unwrap_or_default();

        if let Some(status) = &sts.status {
            let desired = sts
                .spec
                .as_ref()
                .and_then(|s| s.replicas)
                .unwrap_or(1);
            let ready = status.ready_replicas.unwrap_or(0);
            let current = status.current_replicas.unwrap_or(0);
            let updated = status.updated_replicas.unwrap_or(0);

            // Check for unavailable replicas
            if ready < desired {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Deployment,
                        "StatefulSet",
                        &sts_name,
                        "StatefulSet Not Ready",
                        format!(
                            "{} of {} replicas ready",
                            ready, desired
                        ),
                    )
                    .with_namespace(&sts_ns)
                    .with_remediation("Check pod status and PVC bindings"),
                );
            }

            // Check for update in progress
            if updated < desired && updated > 0 {
                let current_revision = status.current_revision.as_deref().unwrap_or("unknown");
                let update_revision = status.update_revision.as_deref().unwrap_or("unknown");

                if current_revision != update_revision {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Deployment,
                            "StatefulSet",
                            &sts_name,
                            "Rolling Update In Progress",
                            format!(
                                "Update in progress: {} of {} pods updated",
                                updated, desired
                            ),
                        )
                        .with_namespace(&sts_ns)
                        .with_remediation("Monitor rollout progress"),
                    );
                }
            }

            // Check for collision count (indicates naming conflicts)
            if let Some(collision_count) = status.collision_count {
                if collision_count > 0 {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Deployment,
                            "StatefulSet",
                            &sts_name,
                            "Pod Name Collision",
                            format!(
                                "StatefulSet has {} name collisions",
                                collision_count
                            ),
                        )
                        .with_namespace(&sts_ns)
                        .with_remediation("Check for orphaned pods with same name"),
                    );
                }
            }
        }

        // Check for headless service
        if let Some(spec) = &sts.spec {
            if let Some(service_name) = &spec.service_name {
                let services: Api<Service> = Api::namespaced(client.clone(), &sts_ns);

                if services.get(service_name).await.is_err() {
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Service,
                            "StatefulSet",
                            &sts_name,
                            "Headless Service Missing",
                            format!(
                                "StatefulSet references service '{}' which does not exist",
                                service_name
                            ),
                        )
                        .with_namespace(&sts_ns)
                        .with_remediation("Create the headless service for the StatefulSet"),
                    );
                }
            }

            // Check PVCs for the StatefulSet
            if let Some(vct) = &spec.volume_claim_templates {
                let pvcs: Api<PersistentVolumeClaim> = Api::namespaced(client.clone(), &sts_ns);
                let replicas = spec.replicas.unwrap_or(1);

                for template in vct {
                    let pvc_base_name = template.metadata.name.clone().unwrap_or_default();

                    for i in 0..replicas {
                        let pvc_name = format!("{}-{}-{}", pvc_base_name, sts_name, i);

                        if let Ok(pvc) = pvcs.get(&pvc_name).await {
                            let phase = pvc
                                .status
                                .as_ref()
                                .and_then(|s| s.phase.as_ref())
                                .map(|p| p.as_str())
                                .unwrap_or("Unknown");

                            if phase != "Bound" {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Storage,
                                        "PVC",
                                        &pvc_name,
                                        "PVC Not Bound",
                                        format!("PVC is in {} phase", phase),
                                    )
                                    .with_namespace(&sts_ns)
                                    .with_remediation(
                                        "Check PVC events and StorageClass provisioner",
                                    ),
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

/// Check for Job and CronJob issues
pub async fn check_job_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    use k8s_openapi::api::batch::v1::{CronJob, Job};

    let mut issues = Vec::new();

    // Check Jobs
    let jobs: Api<Job> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(job_list) = jobs.list(&ListParams::default()).await {
        for job in job_list {
            let job_name = job.metadata.name.clone().unwrap_or_default();
            let job_ns = job.metadata.namespace.clone().unwrap_or_default();

            if let Some(status) = &job.status {
                // Check for failed jobs
                if let Some(failed) = status.failed {
                    if failed > 0 {
                        let backoff_limit = job
                            .spec
                            .as_ref()
                            .and_then(|s| s.backoff_limit)
                            .unwrap_or(6);

                        if failed >= backoff_limit {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Critical,
                                    DebugCategory::Pod,
                                    "Job",
                                    &job_name,
                                    "Job Failed",
                                    format!(
                                        "Job has failed {} times, backoff limit reached",
                                        failed
                                    ),
                                )
                                .with_namespace(&job_ns)
                                .with_remediation("Check job pod logs for failure reason"),
                            );
                        } else {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Warning,
                                    DebugCategory::Pod,
                                    "Job",
                                    &job_name,
                                    "Job Failing",
                                    format!(
                                        "Job has failed {} of {} attempts",
                                        failed, backoff_limit
                                    ),
                                )
                                .with_namespace(&job_ns)
                                .with_remediation("Check job pod logs for failure reason"),
                            );
                        }
                    }
                }

                // Check for deadline exceeded
                if let Some(conditions) = &status.conditions {
                    for condition in conditions {
                        if condition.type_ == "Failed"
                            && condition.status == "True"
                            && condition.reason.as_deref() == Some("DeadlineExceeded")
                        {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Warning,
                                    DebugCategory::Pod,
                                    "Job",
                                    &job_name,
                                    "Job Deadline Exceeded",
                                    "Job exceeded its activeDeadlineSeconds",
                                )
                                .with_namespace(&job_ns)
                                .with_remediation(
                                    "Increase activeDeadlineSeconds or optimize job performance",
                                ),
                            );
                        }
                    }
                }
            }
        }
    }

    // Check CronJobs
    let cronjobs: Api<CronJob> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    if let Ok(cj_list) = cronjobs.list(&ListParams::default()).await {
        for cj in cj_list {
            let cj_name = cj.metadata.name.clone().unwrap_or_default();
            let cj_ns = cj.metadata.namespace.clone().unwrap_or_default();

            if let Some(spec) = &cj.spec {
                // Check if suspended
                if spec.suspend == Some(true) {
                    issues.push(
                        DebugIssue::new(
                            Severity::Info,
                            DebugCategory::Pod,
                            "CronJob",
                            &cj_name,
                            "CronJob Suspended",
                            "CronJob is currently suspended",
                        )
                        .with_namespace(&cj_ns)
                        .with_remediation("Set suspend: false to enable scheduling"),
                    );
                }
            }

            if let Some(status) = &cj.status {
                // Check for missed schedules
                if let Some(last_schedule) = &status.last_schedule_time {
                    let now = chrono::Utc::now();
                    let last: chrono::DateTime<chrono::Utc> = last_schedule.0;
                    let since_last = now.signed_duration_since(last).num_hours();

                    // Alert if no runs in 24+ hours (may indicate issues)
                    if since_last > 24 {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Pod,
                                "CronJob",
                                &cj_name,
                                "CronJob Not Running",
                                format!(
                                    "No jobs scheduled in {} hours",
                                    since_last
                                ),
                            )
                            .with_namespace(&cj_ns)
                            .with_remediation("Check cron schedule and job history"),
                        );
                    }
                }

                // Check for too many active jobs (concurrency issue)
                let active_count = status.active.as_ref().map(|a| a.len()).unwrap_or(0);
                if active_count > 3 {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Pod,
                            "CronJob",
                            &cj_name,
                            "Many Active Jobs",
                            format!(
                                "CronJob has {} active jobs, may indicate job overlap",
                                active_count
                            ),
                        )
                        .with_namespace(&cj_ns)
                        .with_remediation(
                            "Review concurrencyPolicy and job completion time",
                        ),
                    );
                }
            }
        }
    }

    Ok(issues)
}

/// Check for Ingress issues
pub async fn check_ingress_issues(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    use k8s_openapi::api::networking::v1::Ingress;
    use k8s_openapi::api::core::v1::{Secret, Service};

    let mut issues = Vec::new();

    let ingresses: Api<Ingress> = if let Some(ns) = namespace {
        Api::namespaced(client.clone(), ns)
    } else {
        Api::all(client.clone())
    };

    let ing_list = ingresses
        .list(&ListParams::default())
        .await
        .map_err(|e| KcError::Config(e.to_string()))?;

    // Track hosts for conflict detection
    let mut host_ingresses: std::collections::HashMap<String, Vec<String>> =
        std::collections::HashMap::new();

    for ing in &ing_list {
        let ing_name = ing.metadata.name.clone().unwrap_or_default();
        let ing_ns = ing.metadata.namespace.clone().unwrap_or_default();

        // Check for missing address
        let has_address = ing
            .status
            .as_ref()
            .and_then(|s| s.load_balancer.as_ref())
            .and_then(|lb| lb.ingress.as_ref())
            .map(|i| !i.is_empty())
            .unwrap_or(false);

        if !has_address {
            // Check how long ingress has existed
            let age = ing
                .metadata
                .creation_timestamp
                .as_ref()
                .map(|ts| {
                    let now = chrono::Utc::now();
                    let created: chrono::DateTime<chrono::Utc> = ts.0;
                    now.signed_duration_since(created).num_seconds()
                })
                .unwrap_or(0);

            if age > 300 {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Ingress,
                        "Ingress",
                        &ing_name,
                        "Ingress No Address",
                        "Ingress has no load balancer address after 5+ minutes",
                    )
                    .with_namespace(&ing_ns)
                    .with_remediation(
                        "Check ingress controller logs and AWS Load Balancer Controller status",
                    ),
                );
            }
        }

        if let Some(spec) = &ing.spec {
            // Check TLS secrets
            if let Some(tls_configs) = &spec.tls {
                let secrets: Api<Secret> = Api::namespaced(client.clone(), &ing_ns);

                for tls in tls_configs {
                    if let Some(secret_name) = &tls.secret_name {
                        if secrets.get(secret_name).await.is_err() {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Critical,
                                    DebugCategory::Ingress,
                                    "Ingress",
                                    &ing_name,
                                    "TLS Secret Missing",
                                    format!("TLS secret '{}' not found", secret_name),
                                )
                                .with_namespace(&ing_ns)
                                .with_remediation(
                                    "Create the TLS secret or use cert-manager for auto-provisioning",
                                ),
                            );
                        }
                    }

                    // Track hosts for conflict detection
                    if let Some(hosts) = &tls.hosts {
                        for host in hosts {
                            host_ingresses
                                .entry(host.clone())
                                .or_default()
                                .push(format!("{}/{}", ing_ns, ing_name));
                        }
                    }
                }
            }

            // Check backend services
            if let Some(rules) = &spec.rules {
                let services: Api<Service> = Api::namespaced(client.clone(), &ing_ns);

                for rule in rules {
                    if let Some(host) = &rule.host {
                        host_ingresses
                            .entry(host.clone())
                            .or_default()
                            .push(format!("{}/{}", ing_ns, ing_name));
                    }

                    if let Some(http) = &rule.http {
                        for path in &http.paths {
                            if let Some(backend) = &path.backend.service {
                                let svc_name = &backend.name;

                                if services.get(svc_name).await.is_err() {
                                    issues.push(
                                        DebugIssue::new(
                                            Severity::Critical,
                                            DebugCategory::Ingress,
                                            "Ingress",
                                            &ing_name,
                                            "Backend Service Missing",
                                            format!(
                                                "Backend service '{}' not found",
                                                svc_name
                                            ),
                                        )
                                        .with_namespace(&ing_ns)
                                        .with_remediation("Create the backend service"),
                                    );
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // Check for host conflicts
    for (host, ingresses) in host_ingresses {
        if ingresses.len() > 1 {
            // Deduplicate
            let unique: std::collections::HashSet<_> = ingresses.into_iter().collect();
            if unique.len() > 1 {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Ingress,
                        "Ingress",
                        &host,
                        "Host Conflict",
                        format!(
                            "Host '{}' is defined in multiple Ingresses: {:?}",
                            host,
                            unique.iter().collect::<Vec<_>>()
                        ),
                    )
                    .with_remediation("Consolidate rules or use different hosts"),
                );
            }
        }
    }

    Ok(issues)
}

/// Check for webhook issues (validation, mutation timeouts)
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

// ============================================================================
// AWS-specific checks
// ============================================================================

/// Check for AWS Load Balancer Controller issues
pub async fn check_load_balancer_issues(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    use k8s_openapi::api::apps::v1::Deployment;
    use k8s_openapi::api::core::v1::Service;
    use k8s_openapi::api::networking::v1::Ingress;

    let mut issues = Vec::new();

    let pods: Api<Pod> = Api::namespaced(client.clone(), "kube-system");

    // Check for AWS Load Balancer Controller
    let lb_controller = pods
        .list(&ListParams::default().labels("app.kubernetes.io/name=aws-load-balancer-controller"))
        .await
        .map(|list| list.items)
        .unwrap_or_default();

    if lb_controller.is_empty() {
        // Check if there are any LoadBalancer services or Ingresses
        let services: Api<Service> = Api::all(client.clone());
        let has_lb_services = services
            .list(&ListParams::default())
            .await
            .map(|list| {
                list.items.iter().any(|svc| {
                    svc.spec
                        .as_ref()
                        .and_then(|s| s.type_.as_ref())
                        .map(|t| t == "LoadBalancer")
                        .unwrap_or(false)
                })
            })
            .unwrap_or(false);

        let ingresses: Api<Ingress> = Api::all(client.clone());
        let has_ingresses = ingresses
            .list(&ListParams::default())
            .await
            .map(|list| !list.items.is_empty())
            .unwrap_or(false);

        if has_lb_services || has_ingresses {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Network,
                    "Deployment",
                    "aws-load-balancer-controller",
                    "AWS LB Controller Not Found",
                    "AWS Load Balancer Controller not found but LoadBalancer services/Ingresses exist",
                )
                .with_namespace("kube-system")
                .with_remediation(
                    "Install AWS Load Balancer Controller: https://kubernetes-sigs.github.io/aws-load-balancer-controller",
                ),
            );
        }
    } else {
        // Check if controller is healthy
        let unhealthy: Vec<_> = lb_controller
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
                    DebugCategory::Network,
                    "Deployment",
                    "aws-load-balancer-controller",
                    "AWS LB Controller Unhealthy",
                    format!(
                        "{} of {} AWS LB Controller pods are not running",
                        unhealthy.len(),
                        lb_controller.len()
                    ),
                )
                .with_namespace("kube-system")
                .with_remediation("Check aws-load-balancer-controller pod logs"),
            );
        }
    }

    // Check for stuck LoadBalancer services
    let services: Api<Service> = Api::all(client.clone());
    if let Ok(svc_list) = services.list(&ListParams::default()).await {
        for svc in svc_list {
            let svc_name = svc.metadata.name.clone().unwrap_or_default();
            let svc_ns = svc.metadata.namespace.clone().unwrap_or_default();

            let is_lb = svc
                .spec
                .as_ref()
                .and_then(|s| s.type_.as_ref())
                .map(|t| t == "LoadBalancer")
                .unwrap_or(false);

            if is_lb {
                let has_ip = svc
                    .status
                    .as_ref()
                    .and_then(|s| s.load_balancer.as_ref())
                    .and_then(|lb| lb.ingress.as_ref())
                    .map(|i| !i.is_empty())
                    .unwrap_or(false);

                if !has_ip {
                    let age = svc
                        .metadata
                        .creation_timestamp
                        .as_ref()
                        .map(|ts| {
                            let now = chrono::Utc::now();
                            let created: chrono::DateTime<chrono::Utc> = ts.0;
                            now.signed_duration_since(created).num_minutes()
                        })
                        .unwrap_or(0);

                    if age > 5 {
                        // Check annotations for errors
                        let annotations = svc.metadata.annotations.clone().unwrap_or_default();
                        let has_lb_annotations = annotations
                            .keys()
                            .any(|k| k.contains("service.beta.kubernetes.io") || k.contains("alb.ingress"));

                        let remediation = if !has_lb_annotations {
                            "Add service.beta.kubernetes.io/aws-load-balancer-* annotations"
                        } else {
                            "Check AWS Load Balancer Controller logs for provisioning errors"
                        };

                        issues.push(
                            DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Network,
                                "Service",
                                &svc_name,
                                "LoadBalancer Not Provisioned",
                                format!(
                                    "LoadBalancer service pending for {} minutes without external IP",
                                    age
                                ),
                            )
                            .with_namespace(&svc_ns)
                            .with_remediation(remediation),
                        );
                    }
                }
            }
        }
    }

    Ok(issues)
}

/// Check for ECR image pull issues
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

/// Check for observability (CloudWatch, Fluent Bit) issues
pub async fn check_observability_issues(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    use k8s_openapi::api::apps::v1::DaemonSet;

    let mut issues = Vec::new();

    let pods: Api<Pod> = Api::namespaced(client.clone(), "kube-system");
    let daemonsets: Api<DaemonSet> = Api::namespaced(client.clone(), "kube-system");

    // Check for CloudWatch agent
    let cloudwatch_pods = pods
        .list(&ListParams::default().labels("name=cloudwatch-agent"))
        .await
        .map(|list| list.items)
        .unwrap_or_default();

    // Check for Fluent Bit
    let fluentbit_pods = pods
        .list(&ListParams::default().labels("app.kubernetes.io/name=fluent-bit"))
        .await
        .map(|list| list.items)
        .unwrap_or_default();

    // Also check for aws-for-fluent-bit
    let aws_fluentbit_pods = pods
        .list(&ListParams::default().labels("app.kubernetes.io/name=aws-for-fluent-bit"))
        .await
        .map(|list| list.items)
        .unwrap_or_default();

    // Check for ADOT collector
    let adot_pods = pods
        .list(&ListParams::default().labels("app.kubernetes.io/name=aws-otel-collector"))
        .await
        .map(|list| list.items)
        .unwrap_or_default();

    // Report if CloudWatch agent is unhealthy
    if !cloudwatch_pods.is_empty() {
        let unhealthy: Vec<_> = cloudwatch_pods
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
                    Severity::Warning,
                    DebugCategory::Cluster,
                    "DaemonSet",
                    "cloudwatch-agent",
                    "CloudWatch Agent Unhealthy",
                    format!(
                        "{} of {} CloudWatch agent pods are not running",
                        unhealthy.len(),
                        cloudwatch_pods.len()
                    ),
                )
                .with_namespace("kube-system")
                .with_remediation("Check cloudwatch-agent pod logs and ConfigMap"),
            );
        }
    }

    // Check Fluent Bit health
    let all_fluentbit: Vec<_> = fluentbit_pods
        .iter()
        .chain(aws_fluentbit_pods.iter())
        .collect();

    if !all_fluentbit.is_empty() {
        let unhealthy: Vec<_> = all_fluentbit
            .iter()
            .filter(|pod| {
                pod.status
                    .as_ref()
                    .and_then(|s| s.phase.as_ref())
                    .map(|p| *p != "Running")
                    .unwrap_or(true)
            })
            .collect();

        if !unhealthy.is_empty() {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Cluster,
                    "DaemonSet",
                    "fluent-bit",
                    "Fluent Bit Unhealthy",
                    format!(
                        "{} of {} Fluent Bit pods are not running",
                        unhealthy.len(),
                        all_fluentbit.len()
                    ),
                )
                .with_namespace("kube-system")
                .with_remediation("Check fluent-bit pod logs and ConfigMap"),
            );
        }
    }

    // Check ADOT collector health
    if !adot_pods.is_empty() {
        let unhealthy: Vec<_> = adot_pods
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
                    Severity::Warning,
                    DebugCategory::Cluster,
                    "Deployment",
                    "aws-otel-collector",
                    "ADOT Collector Unhealthy",
                    format!(
                        "{} of {} ADOT collector pods are not running",
                        unhealthy.len(),
                        adot_pods.len()
                    ),
                )
                .with_namespace("kube-system")
                .with_remediation("Check aws-otel-collector pod logs"),
            );
        }
    }

    // Info: No logging solution detected
    if cloudwatch_pods.is_empty() && all_fluentbit.is_empty() {
        issues.push(
            DebugIssue::new(
                Severity::Info,
                DebugCategory::Cluster,
                "Cluster",
                "observability",
                "No Log Aggregation",
                "No CloudWatch agent or Fluent Bit detected for log aggregation",
            )
            .with_remediation(
                "Consider installing CloudWatch Container Insights or Fluent Bit for log aggregation",
            ),
        );
    }

    Ok(issues)
}

/// Check for node group and autoscaling issues
pub async fn check_node_group_issues(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    use k8s_openapi::api::apps::v1::Deployment;

    let mut issues = Vec::new();

    let nodes: Api<Node> = Api::all(client.clone());
    let node_list = nodes
        .list(&ListParams::default())
        .await
        .map_err(|e| KcError::Config(e.to_string()))?;

    // Check node conditions
    for node in &node_list {
        let node_name = node.metadata.name.clone().unwrap_or_default();
        let labels = node.metadata.labels.clone().unwrap_or_default();

        if let Some(status) = &node.status {
            if let Some(conditions) = &status.conditions {
                for condition in conditions {
                    match condition.type_.as_str() {
                        "Ready" => {
                            if condition.status != "True" {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Node,
                                        "Node",
                                        &node_name,
                                        "Node Not Ready",
                                        format!(
                                            "Node is not ready: {}",
                                            condition.message.as_deref().unwrap_or("unknown")
                                        ),
                                    )
                                    .with_remediation("Check node status and kubelet logs"),
                                );
                            }
                        }
                        "MemoryPressure" => {
                            if condition.status == "True" {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Warning,
                                        DebugCategory::Node,
                                        "Node",
                                        &node_name,
                                        "Memory Pressure",
                                        "Node is experiencing memory pressure",
                                    )
                                    .with_remediation(
                                        "Scale up the cluster or evict memory-heavy workloads",
                                    ),
                                );
                            }
                        }
                        "DiskPressure" => {
                            if condition.status == "True" {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Warning,
                                        DebugCategory::Node,
                                        "Node",
                                        &node_name,
                                        "Disk Pressure",
                                        "Node is experiencing disk pressure",
                                    )
                                    .with_remediation(
                                        "Clean up unused images/containers or increase disk size",
                                    ),
                                );
                            }
                        }
                        "PIDPressure" => {
                            if condition.status == "True" {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Warning,
                                        DebugCategory::Node,
                                        "Node",
                                        &node_name,
                                        "PID Pressure",
                                        "Node is running low on PIDs",
                                    )
                                    .with_remediation(
                                        "Reduce number of pods or increase PID limits",
                                    ),
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }

            // Check node capacity vs allocatable
            if let (Some(capacity), Some(allocatable)) =
                (&status.capacity, &status.allocatable)
            {
                // Check if node is almost full
                if let (Some(cap_pods), Some(alloc_pods)) =
                    (capacity.get("pods"), allocatable.get("pods"))
                {
                    let cap: i32 = cap_pods.0.parse().unwrap_or(0);
                    let alloc: i32 = alloc_pods.0.parse().unwrap_or(0);

                    // Count running pods on this node
                    let pods: Api<Pod> = Api::all(client.clone());
                    let node_pods = pods
                        .list(
                            &ListParams::default()
                                .fields(&format!("spec.nodeName={}", node_name)),
                        )
                        .await
                        .map(|list| list.items.len())
                        .unwrap_or(0);

                    if alloc > 0 && node_pods as i32 >= alloc - 2 {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Node,
                                "Node",
                                &node_name,
                                "Near Pod Capacity",
                                format!(
                                    "Node has {} pods, near capacity of {}",
                                    node_pods, alloc
                                ),
                            )
                            .with_remediation(
                                "Enable Cluster Autoscaler or manually add more nodes",
                            ),
                        );
                    }
                }
            }
        }

        // Check for Spot instance
        if labels.get("node.kubernetes.io/lifecycle").map(|v| v.as_str()) == Some("spot")
            || labels.get("eks.amazonaws.com/capacityType").map(|v| v.as_str()) == Some("SPOT")
        {
            // Check if Spot interruption handler is installed
            let pods: Api<Pod> = Api::namespaced(client.clone(), "kube-system");
            let spot_handlers = pods
                .list(&ListParams::default().labels("app=aws-node-termination-handler"))
                .await
                .map(|list| list.items)
                .unwrap_or_default();

            if spot_handlers.is_empty() {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Node,
                        "Node",
                        &node_name,
                        "Spot Without Handler",
                        "Spot instance detected without AWS Node Termination Handler",
                    )
                    .with_remediation(
                        "Install AWS Node Termination Handler for graceful Spot interruption handling",
                    ),
                );
                // Only report once
                break;
            }
        }
    }

    // Check for Cluster Autoscaler
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), "kube-system");
    let cluster_autoscaler = deployments
        .get("cluster-autoscaler")
        .await
        .ok();

    // Check for Karpenter
    let karpenter = deployments
        .get("karpenter")
        .await
        .ok();

    if cluster_autoscaler.is_none() && karpenter.is_none() {
        issues.push(
            DebugIssue::new(
                Severity::Info,
                DebugCategory::Cluster,
                "Cluster",
                "autoscaling",
                "No Cluster Autoscaler",
                "Neither Cluster Autoscaler nor Karpenter detected",
            )
            .with_remediation(
                "Consider enabling Cluster Autoscaler or Karpenter for automatic node scaling",
            ),
        );
    } else if let Some(ca) = cluster_autoscaler {
        // Check CA health
        if let Some(status) = &ca.status {
            let available = status.available_replicas.unwrap_or(0);
            let desired = ca.spec.as_ref().and_then(|s| s.replicas).unwrap_or(1);

            if available < desired {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Cluster,
                        "Deployment",
                        "cluster-autoscaler",
                        "Cluster Autoscaler Unavailable",
                        format!(
                            "{} of {} Cluster Autoscaler replicas available",
                            available, desired
                        ),
                    )
                    .with_namespace("kube-system")
                    .with_remediation("Check cluster-autoscaler pod logs"),
                );
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
