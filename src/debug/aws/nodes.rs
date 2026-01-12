//! EKS node and node group checks
//!
//! Checks for node configuration, health, and managed node group issues.

use crate::debug::types::{DebugCategory, DebugIssue, Severity};
use crate::error::KcError;
use k8s_openapi::api::apps::v1::DaemonSet;
use k8s_openapi::api::core::v1::{Node, Pod};
use kube::{api::ListParams, Api, Client};

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

