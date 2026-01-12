//! EKS observability checks
//!
//! Checks for CloudWatch, FluentBit, and monitoring components.

use crate::debug::types::{DebugCategory, DebugIssue, Severity};
use crate::error::KcError;
use k8s_openapi::api::apps::v1::DaemonSet;
use k8s_openapi::api::core::v1::Pod;
use kube::{api::ListParams, Api, Client};

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
