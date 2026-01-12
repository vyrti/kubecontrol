//! Debug command implementation

use crate::cli::{DebugArgs, DebugCommand, DebugSeverityFilter, OutputFormat};
use crate::client::create_client;
use crate::debug::{self, types::{DebugReport, Severity}};
use crate::error::Result;
use owo_colors::OwoColorize;

/// Execute debug command
pub async fn run_debug(
    context: Option<&str>,
    namespace: Option<&str>,
    args: &DebugArgs,
    output: OutputFormat,
) -> Result<()> {
    let client = create_client(context).await?;

    let report = match &args.command {
        DebugCommand::Dns => {
            debug::dns::debug_dns(&client).await?
        }
        DebugCommand::Network => {
            debug::network::debug_network(&client).await?
        }
        DebugCommand::Pod(pod_args) => {
            let ns = namespace.unwrap_or("default");
            debug::pod::debug_pod(&client, ns, &pod_args.name).await?
        }
        DebugCommand::Node(node_args) => {
            if node_args.deep {
                debug::node::debug_node_deep(&client, &node_args.name).await?
            } else {
                debug::node::debug_node(&client, &node_args.name).await?
            }
        }
        DebugCommand::Deployment(deploy_args) => {
            let ns = namespace.unwrap_or("default");
            debug::deployment::debug_deployment(&client, ns, &deploy_args.name).await?
        }
        DebugCommand::Service(svc_args) => {
            let ns = namespace.unwrap_or("default");
            debug::service::debug_service(&client, ns, &svc_args.name).await?
        }
        DebugCommand::Storage => {
            debug::storage::debug_storage(&client, namespace).await?
        }
        DebugCommand::Security => {
            debug::security::debug_security(&client, namespace).await?
        }
        DebugCommand::Resources => {
            debug::resources::debug_resources(&client, namespace).await?
        }
        DebugCommand::Events(_events_args) => {
            debug::events::debug_events(&client, namespace).await?
        }
        DebugCommand::Ingress(_ingress_args) => {
            debug::ingress::debug_ingress(&client, namespace).await?
        }
        DebugCommand::Cluster => {
            debug::cluster::debug_cluster(&client).await?
        }
        DebugCommand::Eks => {
            debug::eks::debug_eks(&client, namespace).await?
        }
        DebugCommand::Gke => {
            debug::gcp::debug_gke(&client, namespace).await?
        }
        DebugCommand::Aks => {
            debug::azure::debug_aks(&client, namespace).await?
        }
        DebugCommand::All => {
            debug::debug_all(&client, namespace).await?
        }
    };

    // Filter by severity if specified
    let filtered_report = filter_by_severity(report, args.severity);

    // Output the report
    match output {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&filtered_report)?;
            println!("{}", json);
        }
        OutputFormat::Yaml => {
            let yaml = serde_yaml::to_string(&filtered_report)?;
            println!("{}", yaml);
        }
        _ => {
            print_report(&filtered_report);
        }
    }

    Ok(())
}

/// Filter report by severity
fn filter_by_severity(mut report: DebugReport, filter: Option<DebugSeverityFilter>) -> DebugReport {
    if let Some(filter) = filter {
        let min_severity = match filter {
            DebugSeverityFilter::Critical => Some(Severity::Critical),
            DebugSeverityFilter::Warning => Some(Severity::Warning),
            DebugSeverityFilter::Info => Some(Severity::Info),
            DebugSeverityFilter::All => None,
        };

        if let Some(min) = min_severity {
            report.issues.retain(|issue| {
                match (&issue.severity, &min) {
                    (Severity::Critical, _) => true,
                    (Severity::Warning, Severity::Critical) => false,
                    (Severity::Warning, _) => true,
                    (Severity::Info, Severity::Info) => true,
                    (Severity::Info, _) => false,
                }
            });
            // Update summary
            report.summary.critical_count = report.issues.iter()
                .filter(|i| i.severity == Severity::Critical).count();
            report.summary.warning_count = report.issues.iter()
                .filter(|i| i.severity == Severity::Warning).count();
            report.summary.info_count = report.issues.iter()
                .filter(|i| i.severity == Severity::Info).count();
        }
    }
    report
}

/// Print report in human-readable format
fn print_report(report: &DebugReport) {
    println!();
    println!("{}", format!("Debug Report: {}", report.category).bold());
    println!("{}", "=".repeat(50));

    // Print summary
    let summary = &report.summary;
    print!("Summary: ");
    if summary.critical_count > 0 {
        print!("{} ", format!("{} critical", summary.critical_count).red().bold());
    }
    if summary.warning_count > 0 {
        print!("{} ", format!("{} warnings", summary.warning_count).yellow());
    }
    if summary.info_count > 0 {
        print!("{} ", format!("{} info", summary.info_count).blue());
    }
    if summary.critical_count == 0 && summary.warning_count == 0 && summary.info_count == 0 {
        print!("{}", "No issues found".green());
    }
    println!();

    if summary.total_checks > 0 {
        println!("Checks performed: {}", summary.total_checks);
    }
    println!();

    // Group issues by severity
    let critical: Vec<_> = report.issues.iter()
        .filter(|i| i.severity == Severity::Critical).collect();
    let warnings: Vec<_> = report.issues.iter()
        .filter(|i| i.severity == Severity::Warning).collect();
    let info: Vec<_> = report.issues.iter()
        .filter(|i| i.severity == Severity::Info).collect();

    if !critical.is_empty() {
        println!("{}", "CRITICAL ISSUES".red().bold());
        println!("{}", "-".repeat(40));
        for issue in critical {
            print_issue(issue);
        }
        println!();
    }

    if !warnings.is_empty() {
        println!("{}", "WARNINGS".yellow().bold());
        println!("{}", "-".repeat(40));
        for issue in warnings {
            print_issue(issue);
        }
        println!();
    }

    if !info.is_empty() {
        println!("{}", "INFO".blue().bold());
        println!("{}", "-".repeat(40));
        for issue in info {
            print_issue(issue);
        }
        println!();
    }
}

/// Print a single issue
fn print_issue(issue: &debug::types::DebugIssue) {
    let severity_icon = match issue.severity {
        Severity::Critical => "".red().to_string(),
        Severity::Warning => "".yellow().to_string(),
        Severity::Info => "".blue().to_string(),
    };

    let location = if let Some(ns) = &issue.namespace {
        format!("{}/{}/{}", ns, issue.resource_type, issue.resource_name)
    } else {
        format!("{}/{}", issue.resource_type, issue.resource_name)
    };

    println!("{} {} {}", severity_icon, issue.title.bold(), location.dimmed());
    println!("  {}", issue.description);

    if let Some(remediation) = &issue.remediation {
        println!("  {} {}", "Fix:".cyan(), remediation);
    }
    println!();
}
