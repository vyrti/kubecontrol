//! DNS debugging
//!
//! Checks for DNS issues including:
//! - CoreDNS pod health
//! - CoreDNS ConfigMap validation
//! - DNS service endpoints
//! - DNS resolution tests

use super::types::*;
use crate::error::KcError;
use k8s_openapi::api::core::v1::{Pod, Service, ConfigMap, Endpoints};
use kube::{Api, Client, api::ListParams};

/// Debug DNS configuration and health
pub async fn debug_dns(client: &Client) -> Result<DebugReport, KcError> {
    let mut issues = Vec::new();
    let mut total_checks = 0;

    // Check CoreDNS pods
    total_checks += 1;
    let coredns_issues = check_coredns_pods(client).await?;
    issues.extend(coredns_issues);

    // Check kube-dns service
    total_checks += 1;
    let service_issues = check_dns_service(client).await?;
    issues.extend(service_issues);

    // Check CoreDNS ConfigMap
    total_checks += 1;
    let config_issues = check_coredns_config(client).await?;
    issues.extend(config_issues);

    // Check DNS endpoints
    total_checks += 1;
    let endpoint_issues = check_dns_endpoints(client).await?;
    issues.extend(endpoint_issues);

    Ok(DebugReport::with_check_count("dns", issues, total_checks))
}

/// Check CoreDNS pod health
async fn check_coredns_pods(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let api: Api<Pod> = Api::namespaced(client.clone(), "kube-system");
    let lp = ListParams::default().labels("k8s-app=kube-dns");

    let pods = api.list(&lp).await?;

    if pods.items.is_empty() {
        issues.push(
            DebugIssue::new(
                Severity::Critical,
                DebugCategory::Dns,
                "DaemonSet",
                "coredns",
                "No CoreDNS pods found",
                "CoreDNS pods are not running. DNS resolution will not work.",
            )
            .with_namespace("kube-system")
            .with_remediation("Check if CoreDNS is deployed. Run 'kubectl get pods -n kube-system -l k8s-app=kube-dns'")
        );
        return Ok(issues);
    }

    let mut running_count = 0;
    let mut not_ready_count = 0;

    for pod in &pods.items {
        let name = pod.metadata.name.as_deref().unwrap_or("unknown");

        if let Some(status) = &pod.status {
            // Check phase
            let phase = status.phase.as_deref().unwrap_or("Unknown");
            if phase != "Running" {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Dns,
                        "Pod",
                        name,
                        format!("CoreDNS pod not running ({})", phase),
                        format!("CoreDNS pod {} is in {} state", name, phase),
                    )
                    .with_namespace("kube-system")
                );
                continue;
            }

            running_count += 1;

            // Check ready condition
            if let Some(conditions) = &status.conditions {
                let ready = conditions.iter().find(|c| c.type_ == "Ready");
                if ready.map(|r| r.status.as_str()) != Some("True") {
                    not_ready_count += 1;
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Dns,
                            "Pod",
                            name,
                            "CoreDNS pod not ready",
                            format!("CoreDNS pod {} is running but not ready", name),
                        )
                        .with_namespace("kube-system")
                    );
                }
            }

            // Check restarts
            if let Some(container_statuses) = &status.container_statuses {
                for cs in container_statuses {
                    if cs.restart_count > 5 {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Dns,
                                "Pod",
                                name,
                                format!("CoreDNS high restart count ({})", cs.restart_count),
                                format!("CoreDNS pod {} has restarted {} times", name, cs.restart_count),
                            )
                            .with_namespace("kube-system")
                            .with_remediation("Check CoreDNS logs for errors")
                        );
                    }
                }
            }
        }
    }

    // Check if we have enough healthy pods
    if running_count == 0 {
        issues.push(
            DebugIssue::new(
                Severity::Critical,
                DebugCategory::Dns,
                "Deployment",
                "coredns",
                "No running CoreDNS pods",
                "All CoreDNS pods are not running. DNS will not work.",
            )
            .with_namespace("kube-system")
        );
    } else if running_count == not_ready_count {
        issues.push(
            DebugIssue::new(
                Severity::Critical,
                DebugCategory::Dns,
                "Deployment",
                "coredns",
                "All CoreDNS pods not ready",
                "All CoreDNS pods are running but not ready.",
            )
            .with_namespace("kube-system")
        );
    } else if running_count == 1 {
        issues.push(
            DebugIssue::new(
                Severity::Warning,
                DebugCategory::Dns,
                "Deployment",
                "coredns",
                "Only one CoreDNS pod running",
                "Single CoreDNS pod provides no redundancy.",
            )
            .with_namespace("kube-system")
            .with_remediation("Consider scaling CoreDNS for high availability")
        );
    }

    Ok(issues)
}

/// Check DNS service configuration
async fn check_dns_service(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let api: Api<Service> = Api::namespaced(client.clone(), "kube-system");

    // Try kube-dns first, then coredns
    let svc = match api.get("kube-dns").await {
        Ok(s) => Some(s),
        Err(_) => api.get("coredns").await.ok(),
    };

    match svc {
        None => {
            issues.push(
                DebugIssue::new(
                    Severity::Critical,
                    DebugCategory::Dns,
                    "Service",
                    "kube-dns",
                    "DNS service not found",
                    "Neither kube-dns nor coredns service found in kube-system namespace.",
                )
                .with_namespace("kube-system")
                .with_remediation("Check if DNS addon is installed correctly")
            );
        }
        Some(service) => {
            // Check ClusterIP is set
            if let Some(spec) = &service.spec {
                if spec.cluster_ip.as_deref() == Some("None") {
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Dns,
                            "Service",
                            service.metadata.name.as_deref().unwrap_or("dns"),
                            "DNS service has no ClusterIP",
                            "DNS service is headless (ClusterIP: None). This will not work for DNS resolution.",
                        )
                        .with_namespace("kube-system")
                    );
                }

                // Check ports
                if let Some(ports) = &spec.ports {
                    let has_dns_port = ports.iter().any(|p| p.port == 53);
                    if !has_dns_port {
                        issues.push(
                            DebugIssue::new(
                                Severity::Critical,
                                DebugCategory::Dns,
                                "Service",
                                service.metadata.name.as_deref().unwrap_or("dns"),
                                "DNS service missing port 53",
                                "DNS service does not expose port 53.",
                            )
                            .with_namespace("kube-system")
                        );
                    }
                }
            }
        }
    }

    Ok(issues)
}

/// Check CoreDNS ConfigMap
async fn check_coredns_config(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let api: Api<ConfigMap> = Api::namespaced(client.clone(), "kube-system");

    match api.get("coredns").await {
        Err(_) => {
            // Try legacy configmap name
            if api.get("kube-dns").await.is_err() {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Dns,
                        "ConfigMap",
                        "coredns",
                        "CoreDNS ConfigMap not found",
                        "Could not find CoreDNS configuration.",
                    )
                    .with_namespace("kube-system")
                );
            }
        }
        Ok(cm) => {
            if let Some(data) = &cm.data {
                if let Some(corefile) = data.get("Corefile") {
                    // Basic Corefile validation
                    if !corefile.contains("kubernetes") {
                        issues.push(
                            DebugIssue::new(
                                Severity::Warning,
                                DebugCategory::Dns,
                                "ConfigMap",
                                "coredns",
                                "Corefile missing kubernetes plugin",
                                "The Corefile does not contain the kubernetes plugin configuration.",
                            )
                            .with_namespace("kube-system")
                        );
                    }

                    // Check for common misconfigurations
                    if corefile.contains("loop") && !corefile.contains("# loop") {
                        issues.push(
                            DebugIssue::new(
                                Severity::Info,
                                DebugCategory::Dns,
                                "ConfigMap",
                                "coredns",
                                "Loop detection enabled",
                                "CoreDNS loop detection is enabled, which is good practice.",
                            )
                            .with_namespace("kube-system")
                        );
                    }

                    // Check forward configuration
                    if !corefile.contains("forward") {
                        issues.push(
                            DebugIssue::new(
                                Severity::Info,
                                DebugCategory::Dns,
                                "ConfigMap",
                                "coredns",
                                "No forward plugin configured",
                                "External DNS resolution may not work without forward plugin.",
                            )
                            .with_namespace("kube-system")
                        );
                    }
                } else {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Dns,
                            "ConfigMap",
                            "coredns",
                            "Missing Corefile in ConfigMap",
                            "The coredns ConfigMap does not contain a Corefile.",
                        )
                        .with_namespace("kube-system")
                    );
                }
            }
        }
    }

    Ok(issues)
}

/// Check DNS endpoints
async fn check_dns_endpoints(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let api: Api<Endpoints> = Api::namespaced(client.clone(), "kube-system");

    // Try kube-dns first
    let endpoints = match api.get("kube-dns").await {
        Ok(e) => Some(e),
        Err(_) => api.get("coredns").await.ok(),
    };

    match endpoints {
        None => {
            issues.push(
                DebugIssue::new(
                    Severity::Critical,
                    DebugCategory::Dns,
                    "Endpoints",
                    "kube-dns",
                    "DNS endpoints not found",
                    "No endpoints object for DNS service.",
                )
                .with_namespace("kube-system")
            );
        }
        Some(ep) => {
            let endpoint_count = ep.subsets
                .as_ref()
                .map(|subsets| {
                    subsets.iter()
                        .filter_map(|s| s.addresses.as_ref())
                        .map(|a| a.len())
                        .sum::<usize>()
                })
                .unwrap_or(0);

            if endpoint_count == 0 {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Dns,
                        "Endpoints",
                        ep.metadata.name.as_deref().unwrap_or("dns"),
                        "DNS service has no endpoints",
                        "No healthy endpoints for DNS service. DNS resolution will fail.",
                    )
                    .with_namespace("kube-system")
                    .with_remediation("Check if CoreDNS pods are running and ready")
                );
            } else if endpoint_count == 1 {
                issues.push(
                    DebugIssue::new(
                        Severity::Info,
                        DebugCategory::Dns,
                        "Endpoints",
                        ep.metadata.name.as_deref().unwrap_or("dns"),
                        "Single DNS endpoint",
                        "Only one DNS endpoint available. Consider scaling for redundancy.",
                    )
                    .with_namespace("kube-system")
                );
            }
        }
    }

    Ok(issues)
}
