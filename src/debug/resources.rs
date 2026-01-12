//! Resource analysis
//!
//! Checks for resource issues including:
//! - Over-provisioned resources
//! - Under-provisioned resources
//! - Missing resource limits
//! - ResourceQuota usage

use super::types::*;
use crate::error::KcError;
use k8s_openapi::api::core::v1::{Pod, ResourceQuota, LimitRange};
use kube::{Api, Client, api::ListParams};

/// Debug resource allocation
pub async fn debug_resources(
    client: &Client,
    namespace: Option<&str>,
) -> Result<DebugReport, KcError> {
    let mut issues = Vec::new();
    let mut total_checks = 0;

    // Check pod resources
    total_checks += 1;
    let pod_issues = check_pod_resources(client, namespace).await?;
    issues.extend(pod_issues);

    // Check ResourceQuotas
    total_checks += 1;
    let quota_issues = check_resource_quotas(client, namespace).await?;
    issues.extend(quota_issues);

    // Check LimitRanges
    total_checks += 1;
    let limit_issues = check_limit_ranges(client, namespace).await?;
    issues.extend(limit_issues);

    Ok(DebugReport::with_check_count("resources", issues, total_checks))
}

/// Check pod resource configurations
async fn check_pod_resources(
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

    let mut pods_without_limits = 0;
    let mut pods_without_requests = 0;

    for pod in &pods {
        let name = pod.metadata.name.as_deref().unwrap_or("unknown");
        let ns = pod.metadata.namespace.as_deref().unwrap_or("default");

        // Skip system pods for some checks
        if ns == "kube-system" {
            continue;
        }

        let spec = match &pod.spec {
            Some(s) => s,
            None => continue,
        };

        for container in &spec.containers {
            let container_name = &container.name;

            let has_limits = container.resources.as_ref()
                .and_then(|r| r.limits.as_ref())
                .map(|l| !l.is_empty())
                .unwrap_or(false);

            let has_requests = container.resources.as_ref()
                .and_then(|r| r.requests.as_ref())
                .map(|r| !r.is_empty())
                .unwrap_or(false);

            if !has_limits {
                pods_without_limits += 1;
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Resources,
                        "Container",
                        container_name,
                        "No resource limits",
                        format!(
                            "Container {} in pod {} has no resource limits defined",
                            container_name, name
                        ),
                    )
                    .with_namespace(ns)
                    .with_remediation("Define CPU and memory limits")
                    .with_details(serde_json::json!({
                        "pod": name,
                        "container": container_name,
                    }))
                );
            }

            if !has_requests {
                pods_without_requests += 1;
                issues.push(
                    DebugIssue::new(
                        Severity::Info,
                        DebugCategory::Resources,
                        "Container",
                        container_name,
                        "No resource requests",
                        format!(
                            "Container {} in pod {} has no resource requests defined",
                            container_name, name
                        ),
                    )
                    .with_namespace(ns)
                    .with_remediation("Define CPU and memory requests for better scheduling")
                );
            }

            // Check for very high limits
            if let Some(resources) = &container.resources {
                if let Some(limits) = &resources.limits {
                    // Check CPU limits
                    if let Some(cpu) = limits.get("cpu") {
                        let cpu_str = &cpu.0;
                        let cores: f64 = if cpu_str.ends_with('m') {
                            cpu_str.trim_end_matches('m').parse::<f64>().unwrap_or(0.0) / 1000.0
                        } else {
                            cpu_str.parse().unwrap_or(0.0)
                        };

                        if cores > 8.0 {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Info,
                                    DebugCategory::Resources,
                                    "Container",
                                    container_name,
                                    format!("High CPU limit ({:.1} cores)", cores),
                                    format!(
                                        "Container {} in pod {} has {:.1} CPU cores limit",
                                        container_name, name, cores
                                    ),
                                )
                                .with_namespace(ns)
                            );
                        }
                    }

                    // Check memory limits
                    if let Some(mem) = limits.get("memory") {
                        let mem_str = &mem.0;
                        let gb = parse_memory_to_gb(mem_str);

                        if gb > 16.0 {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Info,
                                    DebugCategory::Resources,
                                    "Container",
                                    container_name,
                                    format!("High memory limit ({:.1}Gi)", gb),
                                    format!(
                                        "Container {} in pod {} has {:.1}Gi memory limit",
                                        container_name, name, gb
                                    ),
                                )
                                .with_namespace(ns)
                            );
                        }
                    }
                }

                // Check for requests > limits (invalid)
                if let (Some(requests), Some(limits)) = (&resources.requests, &resources.limits) {
                    if let (Some(req_cpu), Some(lim_cpu)) = (requests.get("cpu"), limits.get("cpu")) {
                        let req_val = parse_cpu(&req_cpu.0);
                        let lim_val = parse_cpu(&lim_cpu.0);

                        if req_val > lim_val {
                            issues.push(
                                DebugIssue::new(
                                    Severity::Critical,
                                    DebugCategory::Resources,
                                    "Container",
                                    container_name,
                                    "CPU request exceeds limit",
                                    format!(
                                        "Container {} in pod {}: CPU request ({}) > limit ({})",
                                        container_name, name, req_cpu.0, lim_cpu.0
                                    ),
                                )
                                .with_namespace(ns)
                                .with_remediation("Set request <= limit")
                            );
                        }
                    }
                }
            }
        }
    }

    // Summary issues
    if pods_without_limits > 5 {
        issues.push(
            DebugIssue::new(
                Severity::Warning,
                DebugCategory::Resources,
                "Cluster",
                "resource-limits",
                format!("{} containers without resource limits", pods_without_limits),
                format!("Found {} containers without resource limits across the cluster", pods_without_limits),
            )
            .with_remediation("Implement LimitRange to enforce defaults, or add limits to pod specs")
        );
    }

    Ok(issues)
}

/// Check ResourceQuota usage
async fn check_resource_quotas(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let quotas: Vec<ResourceQuota> = if let Some(ns) = namespace {
        let api: Api<ResourceQuota> = Api::namespaced(client.clone(), ns);
        api.list(&ListParams::default()).await?.items
    } else {
        let api: Api<ResourceQuota> = Api::all(client.clone());
        api.list(&ListParams::default()).await?.items
    };

    for quota in &quotas {
        let name = quota.metadata.name.as_deref().unwrap_or("unknown");
        let ns = quota.metadata.namespace.as_deref().unwrap_or("default");

        if let Some(status) = &quota.status {
            if let (Some(hard), Some(used)) = (&status.hard, &status.used) {
                for (resource, hard_value) in hard {
                    if let Some(used_value) = used.get(resource) {
                        let hard_num = parse_quantity(&hard_value.0);
                        let used_num = parse_quantity(&used_value.0);

                        if hard_num > 0.0 {
                            let usage_percent = (used_num / hard_num) * 100.0;

                            if usage_percent >= 100.0 {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Resources,
                                        "ResourceQuota",
                                        name,
                                        format!("{} quota exhausted", resource),
                                        format!(
                                            "ResourceQuota {} in {} has exhausted {} (used: {}, limit: {})",
                                            name, ns, resource, used_value.0, hard_value.0
                                        ),
                                    )
                                    .with_namespace(ns)
                                    .with_remediation("Increase quota or reduce resource usage")
                                );
                            } else if usage_percent >= 90.0 {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Warning,
                                        DebugCategory::Resources,
                                        "ResourceQuota",
                                        name,
                                        format!("{} quota near limit ({:.1}%)", resource, usage_percent),
                                        format!(
                                            "ResourceQuota {} in {} is at {:.1}% of {} limit",
                                            name, ns, usage_percent, resource
                                        ),
                                    )
                                    .with_namespace(ns)
                                );
                            } else if usage_percent >= 80.0 {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Info,
                                        DebugCategory::Resources,
                                        "ResourceQuota",
                                        name,
                                        format!("{} quota at {:.1}%", resource, usage_percent),
                                        format!(
                                            "ResourceQuota {} in {} is at {:.1}% of {} limit",
                                            name, ns, usage_percent, resource
                                        ),
                                    )
                                    .with_namespace(ns)
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

/// Check LimitRanges
async fn check_limit_ranges(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Get all namespaces or just the specified one
    let namespaces: Vec<String> = if let Some(ns) = namespace {
        vec![ns.to_string()]
    } else {
        let ns_api: Api<k8s_openapi::api::core::v1::Namespace> = Api::all(client.clone());
        ns_api.list(&ListParams::default())
            .await?
            .items
            .iter()
            .filter_map(|n| n.metadata.name.clone())
            .filter(|n| n != "kube-system" && n != "kube-public" && n != "kube-node-lease")
            .collect()
    };

    for ns in namespaces {
        let api: Api<LimitRange> = Api::namespaced(client.clone(), &ns);
        let limit_ranges = api.list(&ListParams::default()).await?;

        if limit_ranges.items.is_empty() {
            issues.push(
                DebugIssue::new(
                    Severity::Info,
                    DebugCategory::Resources,
                    "Namespace",
                    &ns,
                    "No LimitRange configured",
                    format!(
                        "Namespace {} has no LimitRange. Pods can use unlimited resources.",
                        ns
                    ),
                )
                .with_namespace(&ns)
                .with_remediation("Consider adding a LimitRange to set default limits")
            );
        }
    }

    Ok(issues)
}

/// Parse memory string to GB
fn parse_memory_to_gb(s: &str) -> f64 {
    if s.ends_with("Gi") {
        s.trim_end_matches("Gi").parse().unwrap_or(0.0)
    } else if s.ends_with("Mi") {
        s.trim_end_matches("Mi").parse::<f64>().unwrap_or(0.0) / 1024.0
    } else if s.ends_with("Ki") {
        s.trim_end_matches("Ki").parse::<f64>().unwrap_or(0.0) / (1024.0 * 1024.0)
    } else if s.ends_with('G') {
        s.trim_end_matches('G').parse::<f64>().unwrap_or(0.0) * 0.931  // decimal to binary
    } else if s.ends_with('M') {
        s.trim_end_matches('M').parse::<f64>().unwrap_or(0.0) / 1000.0 * 0.931
    } else {
        s.parse::<f64>().unwrap_or(0.0) / (1024.0 * 1024.0 * 1024.0)
    }
}

/// Parse CPU string to millicores
fn parse_cpu(s: &str) -> f64 {
    if s.ends_with('m') {
        s.trim_end_matches('m').parse().unwrap_or(0.0)
    } else {
        s.parse::<f64>().unwrap_or(0.0) * 1000.0
    }
}

/// Parse generic quantity
fn parse_quantity(s: &str) -> f64 {
    // Try to parse as number first
    if let Ok(n) = s.parse::<f64>() {
        return n;
    }

    // Handle memory/storage suffixes
    if s.ends_with("Gi") {
        return s.trim_end_matches("Gi").parse::<f64>().unwrap_or(0.0) * 1024.0 * 1024.0 * 1024.0;
    }
    if s.ends_with("Mi") {
        return s.trim_end_matches("Mi").parse::<f64>().unwrap_or(0.0) * 1024.0 * 1024.0;
    }
    if s.ends_with("Ki") {
        return s.trim_end_matches("Ki").parse::<f64>().unwrap_or(0.0) * 1024.0;
    }
    if s.ends_with('m') {
        return s.trim_end_matches('m').parse::<f64>().unwrap_or(0.0) / 1000.0;
    }

    0.0
}
