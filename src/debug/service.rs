//! Service connectivity debugging
//!
//! Checks for service issues including:
//! - Endpoint availability
//! - Selector matching
//! - Port configuration
//! - LoadBalancer status

use super::types::*;
use crate::error::KcError;
use k8s_openapi::api::core::v1::{Service, Endpoints, Pod};
use kube::{Api, Client, api::ListParams};

/// Debug all services
pub async fn debug_services(
    client: &Client,
    namespace: Option<&str>,
) -> Result<DebugReport, KcError> {
    let services: Vec<Service> = if let Some(ns) = namespace {
        let api: Api<Service> = Api::namespaced(client.clone(), ns);
        api.list(&ListParams::default()).await?.items
    } else {
        let api: Api<Service> = Api::all(client.clone());
        api.list(&ListParams::default()).await?.items
    };

    let mut issues = Vec::new();
    let mut total_checks = 0;

    for svc in &services {
        total_checks += 1;
        let svc_issues = analyze_service(client, svc).await?;
        issues.extend(svc_issues);
    }

    Ok(DebugReport::with_check_count("service", issues, total_checks))
}

/// Debug a specific service
pub async fn debug_service(
    client: &Client,
    namespace: &str,
    name: &str,
) -> Result<DebugReport, KcError> {
    let api: Api<Service> = Api::namespaced(client.clone(), namespace);
    let svc = api.get(name).await?;

    let issues = analyze_service(client, &svc).await?;
    Ok(DebugReport::new("service", issues))
}

/// Analyze a single service
async fn analyze_service(client: &Client, svc: &Service) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let name = svc.metadata.name.as_deref().unwrap_or("unknown");
    let namespace = svc.metadata.namespace.as_deref().unwrap_or("default");

    let spec = match &svc.spec {
        Some(s) => s,
        None => return Ok(issues),
    };

    // Skip headless services for some checks
    let is_headless = spec.cluster_ip.as_deref() == Some("None");

    // Check endpoints
    let endpoint_issues = check_endpoints(client, namespace, name, spec, is_headless).await?;
    issues.extend(endpoint_issues);

    // Check selector matches pods
    if let Some(selector) = &spec.selector {
        if !selector.is_empty() {
            let selector_issues = check_selector(client, namespace, name, selector).await?;
            issues.extend(selector_issues);
        }
    } else if !is_headless {
        issues.push(
            DebugIssue::new(
                Severity::Warning,
                DebugCategory::Service,
                "Service",
                name,
                "Service has no selector",
                format!("Service {} has no selector. You must manually manage endpoints.", name),
            )
            .with_namespace(namespace)
        );
    }

    // Check service type specific issues
    if let Some(svc_type) = &spec.type_ {
        match svc_type.as_str() {
            "LoadBalancer" => {
                let lb_issues = check_loadbalancer(svc, name, namespace);
                issues.extend(lb_issues);
            }
            "NodePort" => {
                if let Some(ports) = &spec.ports {
                    for port in ports {
                        if let Some(node_port) = port.node_port {
                            if node_port < 30000 || node_port > 32767 {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Info,
                                        DebugCategory::Service,
                                        "Service",
                                        name,
                                        format!("Custom NodePort range ({})", node_port),
                                        format!(
                                            "Service {} uses NodePort {} outside default range 30000-32767",
                                            name, node_port
                                        ),
                                    )
                                    .with_namespace(namespace)
                                );
                            }
                        }
                    }
                }
            }
            "ExternalName" => {
                if spec.external_name.is_none() {
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Service,
                            "Service",
                            name,
                            "ExternalName service without external name",
                            format!("Service {} is type ExternalName but has no externalName set", name),
                        )
                        .with_namespace(namespace)
                    );
                }
            }
            _ => {}
        }
    }

    // Check for port configuration issues
    if let Some(ports) = &spec.ports {
        if ports.is_empty() {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Service,
                    "Service",
                    name,
                    "Service has no ports defined",
                    format!("Service {} has no port mappings configured", name),
                )
                .with_namespace(namespace)
            );
        }

        for port in ports {
            if port.port <= 0 {
                issues.push(
                    DebugIssue::new(
                        Severity::Critical,
                        DebugCategory::Service,
                        "Service",
                        name,
                        "Invalid port number",
                        format!("Service {} has invalid port: {}", name, port.port),
                    )
                    .with_namespace(namespace)
                );
            }
        }
    }

    Ok(issues)
}

/// Check service endpoints
async fn check_endpoints(
    client: &Client,
    namespace: &str,
    name: &str,
    spec: &k8s_openapi::api::core::v1::ServiceSpec,
    is_headless: bool,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let api: Api<Endpoints> = Api::namespaced(client.clone(), namespace);

    match api.get(name).await {
        Err(_) => {
            if !is_headless {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Service,
                        "Endpoints",
                        name,
                        "No endpoints object found",
                        format!("Service {} has no endpoints object. This may indicate no matching pods.", name),
                    )
                    .with_namespace(namespace)
                );
            }
        }
        Ok(endpoints) => {
            let endpoint_count = endpoints.subsets
                .as_ref()
                .map(|subsets| {
                    subsets.iter()
                        .filter_map(|s| s.addresses.as_ref())
                        .map(|a| a.len())
                        .sum::<usize>()
                })
                .unwrap_or(0);

            let not_ready_count = endpoints.subsets
                .as_ref()
                .map(|subsets| {
                    subsets.iter()
                        .filter_map(|s| s.not_ready_addresses.as_ref())
                        .map(|a| a.len())
                        .sum::<usize>()
                })
                .unwrap_or(0);

            if endpoint_count == 0 {
                let severity = if is_headless { Severity::Info } else { Severity::Critical };
                issues.push(
                    DebugIssue::new(
                        severity,
                        DebugCategory::Service,
                        "Service",
                        name,
                        "Service has no ready endpoints",
                        format!(
                            "Service {} has 0 ready endpoints. Traffic will fail. {} not-ready endpoints.",
                            name, not_ready_count
                        ),
                    )
                    .with_namespace(namespace)
                    .with_remediation("Check if pods matching the selector exist and are ready")
                );
            } else if not_ready_count > 0 {
                issues.push(
                    DebugIssue::new(
                        Severity::Info,
                        DebugCategory::Service,
                        "Service",
                        name,
                        format!("Service has not-ready endpoints ({})", not_ready_count),
                        format!(
                            "Service {} has {} ready and {} not-ready endpoints",
                            name, endpoint_count, not_ready_count
                        ),
                    )
                    .with_namespace(namespace)
                );
            }

            // Check port mismatches
            if let Some(svc_ports) = &spec.ports {
                if let Some(subsets) = &endpoints.subsets {
                    for subset in subsets {
                        if let Some(ep_ports) = &subset.ports {
                            for svc_port in svc_ports {
                                let target_port = svc_port.target_port.as_ref()
                                    .and_then(|tp| match tp {
                                        k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(i) => Some(*i),
                                        _ => None,
                                    });

                                if let Some(tp) = target_port {
                                    let has_matching_port = ep_ports.iter().any(|p| p.port == tp);
                                    if !has_matching_port {
                                        issues.push(
                                            DebugIssue::new(
                                                Severity::Warning,
                                                DebugCategory::Service,
                                                "Service",
                                                name,
                                                format!("Target port {} not found in endpoints", tp),
                                                format!(
                                                    "Service {} targets port {} but endpoints don't expose it",
                                                    name, tp
                                                ),
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
    }

    Ok(issues)
}

/// Check if selector matches existing pods
async fn check_selector(
    client: &Client,
    namespace: &str,
    name: &str,
    selector: &std::collections::BTreeMap<String, String>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let label_selector = selector
        .iter()
        .map(|(k, v)| format!("{}={}", k, v))
        .collect::<Vec<_>>()
        .join(",");

    let api: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let lp = ListParams::default().labels(&label_selector);
    let pods = api.list(&lp).await?;

    if pods.items.is_empty() {
        issues.push(
            DebugIssue::new(
                Severity::Critical,
                DebugCategory::Service,
                "Service",
                name,
                "No pods match selector",
                format!(
                    "Service {} selector {} matches no pods in namespace {}",
                    name, label_selector, namespace
                ),
            )
            .with_namespace(namespace)
            .with_remediation("Verify the selector labels match your pod labels")
        );
    } else {
        // Count running/ready pods
        let running_count = pods.items.iter()
            .filter(|p| p.status.as_ref().and_then(|s| s.phase.as_deref()) == Some("Running"))
            .count();

        let ready_count = pods.items.iter()
            .filter(|p| {
                p.status.as_ref()
                    .and_then(|s| s.conditions.as_ref())
                    .map(|c| c.iter().any(|cond| cond.type_ == "Ready" && cond.status == "True"))
                    .unwrap_or(false)
            })
            .count();

        if ready_count == 0 && !pods.items.is_empty() {
            issues.push(
                DebugIssue::new(
                    Severity::Warning,
                    DebugCategory::Service,
                    "Service",
                    name,
                    format!("No ready pods ({} matching)", pods.items.len()),
                    format!(
                        "Service {} matches {} pods but none are ready",
                        name, pods.items.len()
                    ),
                )
                .with_namespace(namespace)
            );
        }
    }

    Ok(issues)
}

/// Check LoadBalancer service status
fn check_loadbalancer(svc: &Service, name: &str, namespace: &str) -> Vec<DebugIssue> {
    let mut issues = Vec::new();

    if let Some(status) = &svc.status {
        if let Some(lb) = &status.load_balancer {
            if let Some(ingress) = &lb.ingress {
                if ingress.is_empty() {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Service,
                            "Service",
                            name,
                            "LoadBalancer pending external IP",
                            format!(
                                "Service {} is type LoadBalancer but has no external IP yet",
                                name
                            ),
                        )
                        .with_namespace(namespace)
                        .with_remediation("Check cloud provider load balancer provisioning")
                    );
                }
            } else {
                issues.push(
                    DebugIssue::new(
                        Severity::Warning,
                        DebugCategory::Service,
                        "Service",
                        name,
                        "LoadBalancer not provisioned",
                        format!("Service {} LoadBalancer ingress not provisioned", name),
                    )
                    .with_namespace(namespace)
                );
            }
        }
    }

    issues
}
