//! Network connectivity debugging
//!
//! Checks for network issues including:
//! - CNI plugin health
//! - NetworkPolicy analysis
//! - Service mesh sidecar health
//! - Pod network connectivity

use super::types::*;
use crate::error::KcError;
use k8s_openapi::api::core::v1::{Pod, Namespace};
use k8s_openapi::api::networking::v1::NetworkPolicy;
use k8s_openapi::api::apps::v1::DaemonSet;
use kube::{Api, Client, api::ListParams};
use std::collections::HashSet;

/// Debug network configuration and connectivity
pub async fn debug_network(client: &Client) -> Result<DebugReport, KcError> {
    let mut issues = Vec::new();
    let mut total_checks = 0;

    // Check CNI plugin
    total_checks += 1;
    let cni_issues = check_cni_health(client).await?;
    issues.extend(cni_issues);

    // Check kube-proxy
    total_checks += 1;
    let proxy_issues = check_kube_proxy(client).await?;
    issues.extend(proxy_issues);

    // Analyze NetworkPolicies
    total_checks += 1;
    let policy_issues = analyze_network_policies(client).await?;
    issues.extend(policy_issues);

    // Check service mesh
    total_checks += 1;
    let mesh_issues = check_service_mesh(client).await?;
    issues.extend(mesh_issues);

    Ok(DebugReport::with_check_count("network", issues, total_checks))
}

/// Check CNI plugin health
async fn check_cni_health(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let ds_api: Api<DaemonSet> = Api::namespaced(client.clone(), "kube-system");
    let lp = ListParams::default();
    let daemonsets = ds_api.list(&lp).await?;

    // Common CNI daemonsets
    let cni_patterns = [
        ("calico-node", "Calico"),
        ("weave-net", "Weave"),
        ("cilium", "Cilium"),
        ("aws-node", "AWS VPC CNI"),
        ("azure-cni", "Azure CNI"),
        ("flannel", "Flannel"),
        ("kube-flannel", "Flannel"),
    ];

    let mut found_cni = false;

    for ds in &daemonsets.items {
        let name = ds.metadata.name.as_deref().unwrap_or("");

        for (pattern, cni_name) in &cni_patterns {
            if name.contains(pattern) {
                found_cni = true;

                if let Some(status) = &ds.status {
                    let desired = status.desired_number_scheduled;
                    let ready = status.number_ready;

                    if ready < desired {
                        issues.push(
                            DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Network,
                                "DaemonSet",
                                name,
                                format!("{} CNI not fully ready ({}/{})", cni_name, ready, desired),
                                format!(
                                    "{} CNI plugin has {} pods ready out of {} desired",
                                    cni_name, ready, desired
                                ),
                            )
                            .with_namespace("kube-system")
                            .with_remediation("Check CNI pod logs and node status")
                        );
                    } else if ready == 0 {
                        issues.push(
                            DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Network,
                                "DaemonSet",
                                name,
                                format!("{} CNI has no ready pods", cni_name),
                                format!("{} CNI plugin is not running. Network connectivity will fail.", cni_name),
                            )
                            .with_namespace("kube-system")
                        );
                    }
                }
                break;
            }
        }
    }

    if !found_cni {
        issues.push(
            DebugIssue::new(
                Severity::Warning,
                DebugCategory::Network,
                "Cluster",
                "cni",
                "CNI plugin not detected",
                "Could not detect a known CNI plugin. Network may use a custom or managed solution.",
            )
            .with_details(serde_json::json!({
                "searched_patterns": cni_patterns.iter().map(|(p, _)| *p).collect::<Vec<_>>(),
            }))
        );
    }

    Ok(issues)
}

/// Check kube-proxy health
async fn check_kube_proxy(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let ds_api: Api<DaemonSet> = Api::namespaced(client.clone(), "kube-system");

    match ds_api.get("kube-proxy").await {
        Err(_) => {
            issues.push(
                DebugIssue::new(
                    Severity::Info,
                    DebugCategory::Network,
                    "DaemonSet",
                    "kube-proxy",
                    "kube-proxy not found",
                    "kube-proxy DaemonSet not found. May be using alternative (e.g., Cilium kube-proxy replacement).",
                )
                .with_namespace("kube-system")
            );
        }
        Ok(ds) => {
            if let Some(status) = &ds.status {
                let desired = status.desired_number_scheduled;
                let ready = status.number_ready;

                if ready < desired {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Network,
                            "DaemonSet",
                            "kube-proxy",
                            format!("kube-proxy not fully ready ({}/{})", ready, desired),
                            format!("kube-proxy has {} pods ready out of {} desired", ready, desired),
                        )
                        .with_namespace("kube-system")
                        .with_remediation("Check kube-proxy pod logs")
                    );
                }
            }
        }
    }

    Ok(issues)
}

/// Analyze NetworkPolicies for potential issues
async fn analyze_network_policies(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let np_api: Api<NetworkPolicy> = Api::all(client.clone());
    let policies = np_api.list(&ListParams::default()).await?;

    if policies.items.is_empty() {
        issues.push(
            DebugIssue::new(
                Severity::Info,
                DebugCategory::Network,
                "Cluster",
                "network-policies",
                "No NetworkPolicies configured",
                "Cluster has no NetworkPolicies. All pod-to-pod traffic is allowed by default.",
            )
            .with_remediation("Consider implementing NetworkPolicies for network segmentation")
        );
        return Ok(issues);
    }

    // Get all namespaces with policies
    let mut namespaces_with_policies: HashSet<String> = HashSet::new();

    for policy in &policies.items {
        let namespace = policy.metadata.namespace.as_deref().unwrap_or("default");
        namespaces_with_policies.insert(namespace.to_string());

        // Check for deny-all policies
        if let Some(spec) = &policy.spec {
            let is_deny_all_ingress = spec.ingress.as_ref()
                .map(|i| i.is_empty())
                .unwrap_or(false);

            let is_deny_all_egress = spec.egress.as_ref()
                .map(|e| e.is_empty())
                .unwrap_or(false);

            if is_deny_all_ingress && spec.policy_types.as_ref().map(|t| t.contains(&"Ingress".to_string())).unwrap_or(false) {
                issues.push(
                    DebugIssue::new(
                        Severity::Info,
                        DebugCategory::Network,
                        "NetworkPolicy",
                        policy.metadata.name.as_deref().unwrap_or("unknown"),
                        "Deny-all ingress policy",
                        format!(
                            "NetworkPolicy {} denies all ingress traffic for matching pods in namespace {}",
                            policy.metadata.name.as_deref().unwrap_or("unknown"),
                            namespace
                        ),
                    )
                    .with_namespace(namespace)
                );
            }

            if is_deny_all_egress && spec.policy_types.as_ref().map(|t| t.contains(&"Egress".to_string())).unwrap_or(false) {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Network,
                        "NetworkPolicy",
                        policy.metadata.name.as_deref().unwrap_or("unknown"),
                        "Deny-all egress policy",
                        format!(
                            "NetworkPolicy {} denies all egress traffic. This may block DNS resolution.",
                            policy.metadata.name.as_deref().unwrap_or("unknown")
                        ),
                    )
                    .with_namespace(namespace)
                    .with_remediation("Ensure DNS egress is allowed (port 53 to kube-dns)")
                );
            }
        }
    }

    // Check for namespaces without policies
    let ns_api: Api<Namespace> = Api::all(client.clone());
    let namespaces = ns_api.list(&ListParams::default()).await?;

    for ns in &namespaces.items {
        let name = ns.metadata.name.as_deref().unwrap_or("");
        if !namespaces_with_policies.contains(name) && name != "kube-system" && name != "kube-public" && name != "kube-node-lease" {
            issues.push(
                DebugIssue::new(
                    Severity::Info,
                    DebugCategory::Network,
                    "Namespace",
                    name,
                    "Namespace without NetworkPolicy",
                    format!("Namespace {} has no NetworkPolicies. All traffic is allowed.", name),
                )
            );
        }
    }

    Ok(issues)
}

/// Check for service mesh and sidecar health
async fn check_service_mesh(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Check for Istio
    let istio_issues = check_istio(client).await?;
    issues.extend(istio_issues);

    // Check for Linkerd
    let linkerd_issues = check_linkerd(client).await?;
    issues.extend(linkerd_issues);

    Ok(issues)
}

/// Check Istio service mesh
async fn check_istio(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let ns_api: Api<Namespace> = Api::all(client.clone());

    // Check for istio-system namespace
    if ns_api.get("istio-system").await.is_ok() {
        // Check istiod
        let pod_api: Api<Pod> = Api::namespaced(client.clone(), "istio-system");
        let lp = ListParams::default().labels("app=istiod");

        let istiod_pods = pod_api.list(&lp).await?;

        if istiod_pods.items.is_empty() {
            issues.push(
                DebugIssue::new(
                    Severity::Critical,
                    DebugCategory::Network,
                    "Deployment",
                    "istiod",
                    "Istio control plane not running",
                    "istiod pods not found in istio-system namespace.",
                )
                .with_namespace("istio-system")
            );
        } else {
            let running = istiod_pods.items.iter()
                .filter(|p| p.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Running"))
                .count();

            if running == 0 {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Network,
                        "Deployment",
                        "istiod",
                        "No running istiod pods",
                        "Istio control plane pods are not running.",
                    )
                    .with_namespace("istio-system")
                );
            }
        }

        // Check for sidecars with issues
        let all_pods: Api<Pod> = Api::all(client.clone());
        let pods = all_pods.list(&ListParams::default()).await?;

        for pod in &pods.items {
            if let Some(spec) = &pod.spec {
                let has_sidecar = spec.containers.iter().any(|c| c.name == "istio-proxy");

                if has_sidecar {
                    if let Some(status) = &pod.status {
                        if let Some(container_statuses) = &status.container_statuses {
                            for cs in container_statuses {
                                if cs.name == "istio-proxy" && !cs.ready {
                                    let name = pod.metadata.name.as_deref().unwrap_or("unknown");
                                    let namespace = pod.metadata.namespace.as_deref().unwrap_or("default");

                                    issues.push(
                                        DebugIssue::new(
                                            Severity::Warning,
                                            DebugCategory::Network,
                                            "Pod",
                                            name,
                                            "Istio sidecar not ready",
                                            format!("Pod {} has istio-proxy sidecar that is not ready", name),
                                        )
                                        .with_namespace(namespace)
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

/// Check Linkerd service mesh
async fn check_linkerd(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let ns_api: Api<Namespace> = Api::all(client.clone());

    // Check for linkerd namespace
    if ns_api.get("linkerd").await.is_ok() {
        let pod_api: Api<Pod> = Api::namespaced(client.clone(), "linkerd");
        let lp = ListParams::default();

        let pods = pod_api.list(&lp).await?;

        let not_running: Vec<_> = pods.items.iter()
            .filter(|p| p.status.as_ref().and_then(|s| s.phase.as_deref()) != Some("Running"))
            .collect();

        if !not_running.is_empty() {
            for pod in not_running {
                let name = pod.metadata.name.as_deref().unwrap_or("unknown");
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Network,
                        "Pod",
                        name,
                        "Linkerd component not running",
                        format!("Linkerd pod {} is not in Running state", name),
                    )
                    .with_namespace("linkerd")
                );
            }
        }
    }

    Ok(issues)
}
