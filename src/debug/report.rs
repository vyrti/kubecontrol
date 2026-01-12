//! Debug report generation and formatting

use super::types::{DebugReport, Severity};
use serde_json;

/// Format report as JSON
pub fn format_json(report: &DebugReport, pretty: bool) -> Result<String, serde_json::Error> {
    if pretty {
        serde_json::to_string_pretty(report)
    } else {
        serde_json::to_string(report)
    }
}

/// Format report as YAML
pub fn format_yaml(report: &DebugReport) -> Result<String, serde_yaml::Error> {
    serde_yaml::to_string(report)
}

/// Format report as table for terminal
pub fn format_table(report: &DebugReport) -> String {
    use std::fmt::Write;

    let mut output = String::new();

    // Header
    writeln!(output, "{:10} {:12} {:30} {:50}", "SEVERITY", "CATEGORY", "RESOURCE", "ISSUE").unwrap();
    writeln!(output, "{}", "-".repeat(106)).unwrap();

    // Sort by severity
    let mut issues: Vec<_> = report.issues.iter().collect();
    issues.sort_by(|a, b| a.severity.cmp(&b.severity));

    for issue in issues {
        let resource = if let Some(ns) = &issue.namespace {
            format!("{}/{}", ns, issue.resource_name)
        } else {
            issue.resource_name.clone()
        };

        // Truncate long strings
        let resource_display = if resource.len() > 28 {
            format!("{}...", &resource[..25])
        } else {
            resource
        };

        let title_display = if issue.title.len() > 48 {
            format!("{}...", &issue.title[..45])
        } else {
            issue.title.clone()
        };

        writeln!(
            output,
            "{:10} {:12} {:30} {:50}",
            format!("{}", issue.severity),
            format!("{}", issue.category),
            resource_display,
            title_display
        ).unwrap();
    }

    // Summary
    writeln!(output).unwrap();
    writeln!(
        output,
        "Summary: {} critical, {} warnings, {} info",
        report.summary.critical_count,
        report.summary.warning_count,
        report.summary.info_count
    ).unwrap();

    output
}

/// Generate markdown report
pub fn format_markdown(report: &DebugReport) -> String {
    use std::fmt::Write;

    let mut output = String::new();

    writeln!(output, "# Kubernetes Debug Report").unwrap();
    writeln!(output).unwrap();
    writeln!(output, "**Category:** {}", report.category).unwrap();
    writeln!(output, "**Generated:** {}", report.timestamp.format("%Y-%m-%d %H:%M:%S UTC")).unwrap();
    writeln!(output, "**Status:** {}", report.summary.health_status()).unwrap();
    writeln!(output).unwrap();

    // Summary table
    writeln!(output, "## Summary").unwrap();
    writeln!(output).unwrap();
    writeln!(output, "| Metric | Count |").unwrap();
    writeln!(output, "|--------|-------|").unwrap();
    writeln!(output, "| Critical | {} |", report.summary.critical_count).unwrap();
    writeln!(output, "| Warnings | {} |", report.summary.warning_count).unwrap();
    writeln!(output, "| Info | {} |", report.summary.info_count).unwrap();
    writeln!(output, "| Total Checks | {} |", report.summary.total_checks).unwrap();
    writeln!(output).unwrap();

    // Issues by severity
    for severity in [Severity::Critical, Severity::Warning, Severity::Info] {
        let issues: Vec<_> = report.issues.iter().filter(|i| i.severity == severity).collect();
        if issues.is_empty() {
            continue;
        }

        writeln!(output, "## {} Issues", severity).unwrap();
        writeln!(output).unwrap();

        for issue in issues {
            let resource = if let Some(ns) = &issue.namespace {
                format!("{}/{}", ns, issue.resource_name)
            } else {
                issue.resource_name.clone()
            };

            writeln!(output, "### {} ({})", issue.title, issue.resource_type).unwrap();
            writeln!(output).unwrap();
            writeln!(output, "**Resource:** `{}`", resource).unwrap();
            writeln!(output).unwrap();
            writeln!(output, "{}", issue.description).unwrap();
            writeln!(output).unwrap();

            if let Some(remediation) = &issue.remediation {
                writeln!(output, "**Remediation:** {}", remediation).unwrap();
                writeln!(output).unwrap();
            }
        }
    }

    output
}

/// Export options
#[derive(Debug, Clone, Default)]
pub struct ExportOptions {
    /// Filter by minimum severity
    pub min_severity: Option<Severity>,
    /// Include details in output
    pub include_details: bool,
    /// Namespace filter
    pub namespace: Option<String>,
}
