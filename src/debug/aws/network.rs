//! EKS network and load balancer checks
//!
//! Checks for AWS Load Balancer Controller, NLB/ALB, and service networking issues.

use crate::debug::types::{DebugCategory, DebugIssue, Severity};
use crate::error::KcError;
use k8s_openapi::api::core::v1::{Pod, Service};
use kube::{api::ListParams, Api, Client};

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
