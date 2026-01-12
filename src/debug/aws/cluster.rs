//! EKS add-ons and cluster configuration checks
//!
//! Checks for VPC CNI, CoreDNS, kube-proxy, EBS CSI driver, and aws-auth ConfigMap.

use crate::debug::types::{DebugCategory, DebugIssue, Severity};
use crate::error::KcError;
use k8s_openapi::api::core::v1::{ConfigMap, Pod};
use kube::{api::ListParams, Api, Client};

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
