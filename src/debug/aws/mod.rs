//! AWS EKS-specific diagnostics
//!
//! Checks for common issues specific to Amazon Elastic Kubernetes Service clusters.
//! Includes IAM Roles for Service Accounts (IRSA), VPC CNI, EKS add-ons, and Pod Identity.

pub mod cluster;
pub mod config;
pub mod identity;
pub mod network;
pub mod nodes;
pub mod observability;
pub mod registry;
pub mod workloads;

// Re-export all check functions
pub use cluster::*;
pub use config::*;
pub use identity::*;
pub use network::*;
pub use nodes::*;
pub use observability::*;
pub use registry::*;
pub use workloads::*;

use crate::debug::types::{DebugCategory, DebugIssue, DebugReport, Severity};
use crate::error::KcError;
use k8s_openapi::api::core::v1::Node;
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
        let _ = aws_clients; // suppress unused warning
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
