//! Ingress debugging
//!
//! Checks for ingress issues including:
//! - Ingress controller health
//! - TLS certificate validity
//! - Backend service availability

use super::types::*;
use crate::error::KcError;
use k8s_openapi::api::networking::v1::Ingress;
use k8s_openapi::api::core::v1::{Service, Secret};
use k8s_openapi::api::apps::v1::Deployment;
use kube::{Api, Client, api::ListParams};

/// Debug ingress configuration
pub async fn debug_ingress(
    client: &Client,
    namespace: Option<&str>,
) -> Result<DebugReport, KcError> {
    let mut issues = Vec::new();
    let mut total_checks = 0;

    // Check ingress controller
    total_checks += 1;
    let controller_issues = check_ingress_controller(client).await?;
    issues.extend(controller_issues);

    // Check ingress resources
    total_checks += 1;
    let ingress_issues = check_ingresses(client, namespace).await?;
    issues.extend(ingress_issues);

    Ok(DebugReport::with_check_count("ingress", issues, total_checks))
}

/// Check ingress controller health
async fn check_ingress_controller(client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    // Common ingress controller namespaces and deployments
    let controllers = [
        ("ingress-nginx", "ingress-nginx-controller", "NGINX"),
        ("ingress-nginx", "nginx-ingress-controller", "NGINX"),
        ("traefik", "traefik", "Traefik"),
        ("traefik-system", "traefik", "Traefik"),
        ("kong", "kong", "Kong"),
        ("contour", "contour", "Contour"),
        ("ambassador", "ambassador", "Ambassador"),
    ];

    let mut found_controller = false;

    for (namespace, name, controller_type) in controllers {
        let deploy_api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
        if let Ok(deploy) = deploy_api.get(name).await {
            found_controller = true;

            if let Some(status) = &deploy.status {
                let desired = deploy.spec.as_ref()
                    .and_then(|s| s.replicas)
                    .unwrap_or(1);
                let ready = status.ready_replicas.unwrap_or(0);

                if ready == 0 {
                    issues.push(
                        DebugIssue::new(
                            Severity::Critical,
                            DebugCategory::Ingress,
                            "Deployment",
                            name,
                            format!("{} ingress controller not ready", controller_type),
                            format!(
                                "{} ingress controller has 0/{} replicas ready. Ingress routing is down.",
                                controller_type, desired
                            ),
                        )
                        .with_namespace(namespace)
                        .with_remediation("Check ingress controller pod logs")
                    );
                } else if ready < desired {
                    issues.push(
                        DebugIssue::new(
                            Severity::Warning,
                            DebugCategory::Ingress,
                            "Deployment",
                            name,
                            format!("{} ingress controller degraded ({}/{})", controller_type, ready, desired),
                            format!(
                                "{} ingress controller has only {}/{} replicas ready",
                                controller_type, ready, desired
                            ),
                        )
                        .with_namespace(namespace)
                    );
                }
            }
            break;
        }
    }

    if !found_controller {
        issues.push(
            DebugIssue::new(
                Severity::Warning,
                DebugCategory::Ingress,
                "Cluster",
                "ingress-controller",
                "No known ingress controller found",
                "Could not detect a common ingress controller (NGINX, Traefik, Kong, etc.)",
            )
            .with_remediation("Install an ingress controller or check if using a custom solution")
        );
    }

    Ok(issues)
}

/// Check ingress resources
async fn check_ingresses(
    client: &Client,
    namespace: Option<&str>,
) -> Result<Vec<DebugIssue>, KcError> {
    let mut issues = Vec::new();

    let ingresses: Vec<Ingress> = if let Some(ns) = namespace {
        let api: Api<Ingress> = Api::namespaced(client.clone(), ns);
        api.list(&ListParams::default()).await?.items
    } else {
        let api: Api<Ingress> = Api::all(client.clone());
        api.list(&ListParams::default()).await?.items
    };

    for ingress in &ingresses {
        let name = ingress.metadata.name.as_deref().unwrap_or("unknown");
        let ns = ingress.metadata.namespace.as_deref().unwrap_or("default");

        if let Some(spec) = &ingress.spec {
            // Check TLS configuration
            if let Some(tls_list) = &spec.tls {
                for tls in tls_list {
                    if let Some(secret_name) = &tls.secret_name {
                        // Check if secret exists
                        let secret_api: Api<Secret> = Api::namespaced(client.clone(), ns);
                        match secret_api.get(secret_name).await {
                            Err(_) => {
                                issues.push(
                                    DebugIssue::new(
                                        Severity::Critical,
                                        DebugCategory::Ingress,
                                        "Ingress",
                                        name,
                                        format!("TLS secret '{}' not found", secret_name),
                                        format!(
                                            "Ingress {} references TLS secret '{}' which does not exist",
                                            name, secret_name
                                        ),
                                    )
                                    .with_namespace(ns)
                                    .with_remediation("Create the TLS secret or fix the secret name reference")
                                );
                            }
                            Ok(secret) => {
                                // Check if it's a valid TLS secret
                                if secret.type_.as_deref() != Some("kubernetes.io/tls") {
                                    issues.push(
                                        DebugIssue::new(
                                            Severity::Warning,
                                            DebugCategory::Ingress,
                                            "Ingress",
                                            name,
                                            format!("Secret '{}' is not TLS type", secret_name),
                                            format!(
                                                "Secret '{}' is type '{}', not 'kubernetes.io/tls'",
                                                secret_name,
                                                secret.type_.as_deref().unwrap_or("unknown")
                                            ),
                                        )
                                        .with_namespace(ns)
                                    );
                                }

                                // Check for required keys
                                if let Some(data) = &secret.data {
                                    if !data.contains_key("tls.crt") || !data.contains_key("tls.key") {
                                        issues.push(
                                            DebugIssue::new(
                                                Severity::Critical,
                                                DebugCategory::Ingress,
                                                "Secret",
                                                secret_name,
                                                "TLS secret missing required keys",
                                                format!(
                                                    "TLS secret '{}' is missing tls.crt and/or tls.key",
                                                    secret_name
                                                ),
                                            )
                                            .with_namespace(ns)
                                        );
                                    }
                                }
                            }
                        }
                    } else {
                        // No secret specified - may use default cert or annotation
                        issues.push(
                            DebugIssue::new(
                                Severity::Info,
                                DebugCategory::Ingress,
                                "Ingress",
                                name,
                                "TLS without secret specified",
                                format!(
                                    "Ingress {} has TLS hosts but no secret. May use default certificate.",
                                    name
                                ),
                            )
                            .with_namespace(ns)
                        );
                    }
                }
            }

            // Check rules and backends
            if let Some(rules) = &spec.rules {
                for rule in rules {
                    let host = rule.host.as_deref().unwrap_or("*");

                    if let Some(http) = &rule.http {
                        for path in &http.paths {
                            let backend = &path.backend;
                            // Check service backend
                            if let Some(svc) = &backend.service {
                                let svc_name = &svc.name;
                                let svc_api: Api<Service> = Api::namespaced(client.clone(), ns);

                                match svc_api.get(svc_name).await {
                                    Err(_) => {
                                        issues.push(
                                            DebugIssue::new(
                                                Severity::Critical,
                                                DebugCategory::Ingress,
                                                "Ingress",
                                                name,
                                                format!("Backend service '{}' not found", svc_name),
                                                format!(
                                                    "Ingress {} references service '{}' for host '{}' which does not exist",
                                                    name, svc_name, host
                                                ),
                                            )
                                            .with_namespace(ns)
                                            .with_remediation("Create the service or fix the service name")
                                        );
                                    }
                                    Ok(svc_obj) => {
                                        // Check if service has endpoints
                                        if let Some(svc_spec) = &svc_obj.spec {
                                            if svc_spec.selector.is_none() || svc_spec.selector.as_ref().map(|s| s.is_empty()).unwrap_or(true) {
                                                issues.push(
                                                    DebugIssue::new(
                                                        Severity::Warning,
                                                        DebugCategory::Ingress,
                                                        "Service",
                                                        svc_name,
                                                        "Backend service has no selector",
                                                        format!(
                                                            "Service '{}' used by ingress '{}' has no selector",
                                                            svc_name, name
                                                        ),
                                                    )
                                                    .with_namespace(ns)
                                                );
                                            }
                                        }

                                        // Check port
                                        if let Some(port) = &svc.port {
                                            if let Some(port_num) = port.number {
                                                let has_port = svc_obj.spec.as_ref()
                                                    .and_then(|s| s.ports.as_ref())
                                                    .map(|ports| ports.iter().any(|p| p.port == port_num))
                                                    .unwrap_or(false);

                                                if !has_port {
                                                    issues.push(
                                                        DebugIssue::new(
                                                            Severity::Warning,
                                                            DebugCategory::Ingress,
                                                            "Ingress",
                                                            name,
                                                            format!("Service port {} not found", port_num),
                                                            format!(
                                                                "Ingress {} references port {} on service '{}' which doesn't exist",
                                                                name, port_num, svc_name
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
                    }
                }
            }

            // Check for ingress class
            if spec.ingress_class_name.is_none() {
                // Check annotations for legacy ingress class
                let has_class_annotation = ingress.metadata.annotations.as_ref()
                    .map(|a| a.contains_key("kubernetes.io/ingress.class"))
                    .unwrap_or(false);

                if !has_class_annotation {
                    issues.push(
                        DebugIssue::new(
                            Severity::Info,
                            DebugCategory::Ingress,
                            "Ingress",
                            name,
                            "No ingress class specified",
                            format!(
                                "Ingress {} has no ingressClassName. May use default class.",
                                name
                            ),
                        )
                        .with_namespace(ns)
                    );
                }
            }
        }
    }

    Ok(issues)
}
