//! Debug types and structures

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fmt;

/// Severity level for debug issues
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Requires immediate attention - system is broken or at risk
    Critical,
    /// Should be addressed soon - potential problems
    Warning,
    /// Informational - best practices or optimization suggestions
    Info,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Severity::Critical => write!(f, "CRITICAL"),
            Severity::Warning => write!(f, "WARNING"),
            Severity::Info => write!(f, "INFO"),
        }
    }
}

impl Severity {
    /// ANSI color code for terminal output
    pub fn color_code(&self) -> &'static str {
        match self {
            Severity::Critical => "\x1b[31m", // Red
            Severity::Warning => "\x1b[33m",  // Yellow
            Severity::Info => "\x1b[36m",     // Cyan
        }
    }

    /// CSS class for web UI
    pub fn css_class(&self) -> &'static str {
        match self {
            Severity::Critical => "severity-critical",
            Severity::Warning => "severity-warning",
            Severity::Info => "severity-info",
        }
    }
}

/// Debug issue category
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DebugCategory {
    Dns,
    Network,
    Pod,
    Node,
    Deployment,
    Service,
    Storage,
    Security,
    Resources,
    Events,
    Ingress,
    Cluster,
}

impl fmt::Display for DebugCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DebugCategory::Dns => write!(f, "DNS"),
            DebugCategory::Network => write!(f, "Network"),
            DebugCategory::Pod => write!(f, "Pod"),
            DebugCategory::Node => write!(f, "Node"),
            DebugCategory::Deployment => write!(f, "Deployment"),
            DebugCategory::Service => write!(f, "Service"),
            DebugCategory::Storage => write!(f, "Storage"),
            DebugCategory::Security => write!(f, "Security"),
            DebugCategory::Resources => write!(f, "Resources"),
            DebugCategory::Events => write!(f, "Events"),
            DebugCategory::Ingress => write!(f, "Ingress"),
            DebugCategory::Cluster => write!(f, "Cluster"),
        }
    }
}

/// A single debug issue/finding
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugIssue {
    /// Severity level
    pub severity: Severity,
    /// Category of the issue
    pub category: DebugCategory,
    /// Type of resource affected (Pod, Deployment, Service, etc.)
    pub resource_type: String,
    /// Name of the affected resource
    pub resource_name: String,
    /// Namespace of the resource (if applicable)
    pub namespace: Option<String>,
    /// Short title describing the issue
    pub title: String,
    /// Detailed description of the issue
    pub description: String,
    /// Suggested remediation steps
    pub remediation: Option<String>,
    /// Additional details as JSON for programmatic access
    #[serde(default)]
    pub details: serde_json::Value,
    /// Timestamp when issue was detected
    pub detected_at: DateTime<Utc>,
}

impl DebugIssue {
    /// Create a new debug issue
    pub fn new(
        severity: Severity,
        category: DebugCategory,
        resource_type: impl Into<String>,
        resource_name: impl Into<String>,
        title: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            severity,
            category,
            resource_type: resource_type.into(),
            resource_name: resource_name.into(),
            namespace: None,
            title: title.into(),
            description: description.into(),
            remediation: None,
            details: serde_json::Value::Null,
            detected_at: Utc::now(),
        }
    }

    /// Set namespace
    pub fn with_namespace(mut self, namespace: impl Into<String>) -> Self {
        self.namespace = Some(namespace.into());
        self
    }

    /// Set remediation suggestion
    pub fn with_remediation(mut self, remediation: impl Into<String>) -> Self {
        self.remediation = Some(remediation.into());
        self
    }

    /// Set additional details
    pub fn with_details(mut self, details: serde_json::Value) -> Self {
        self.details = details;
        self
    }

    /// Format for terminal output
    pub fn format_terminal(&self) -> String {
        let reset = "\x1b[0m";
        let bold = "\x1b[1m";
        let color = self.severity.color_code();

        let mut output = format!(
            "{color}{bold}[{}]{reset} {bold}{}{reset}\n",
            self.severity, self.title
        );

        if let Some(ns) = &self.namespace {
            output.push_str(&format!("  Resource: {}/{} ({})\n", ns, self.resource_name, self.resource_type));
        } else {
            output.push_str(&format!("  Resource: {} ({})\n", self.resource_name, self.resource_type));
        }

        output.push_str(&format!("  {}\n", self.description));

        if let Some(remediation) = &self.remediation {
            output.push_str(&format!("  Remediation: {}\n", remediation));
        }

        output
    }
}

/// Summary of debug findings
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DebugSummary {
    pub critical_count: usize,
    pub warning_count: usize,
    pub info_count: usize,
    pub total_checks: usize,
    pub passed_checks: usize,
    pub failed_checks: usize,
}

impl DebugSummary {
    /// Create summary from issues
    pub fn from_issues(issues: &[DebugIssue], total_checks: usize) -> Self {
        let critical_count = issues.iter().filter(|i| i.severity == Severity::Critical).count();
        let warning_count = issues.iter().filter(|i| i.severity == Severity::Warning).count();
        let info_count = issues.iter().filter(|i| i.severity == Severity::Info).count();

        Self {
            critical_count,
            warning_count,
            info_count,
            total_checks,
            passed_checks: total_checks.saturating_sub(critical_count + warning_count),
            failed_checks: critical_count + warning_count,
        }
    }

    /// Overall health status
    pub fn health_status(&self) -> &'static str {
        if self.critical_count > 0 {
            "Critical"
        } else if self.warning_count > 0 {
            "Warning"
        } else {
            "Healthy"
        }
    }
}

/// Debug report for a category or all checks
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugReport {
    /// Timestamp when report was generated
    pub timestamp: DateTime<Utc>,
    /// Category of the report (or "all" for comprehensive)
    pub category: String,
    /// List of issues found
    pub issues: Vec<DebugIssue>,
    /// Summary statistics
    pub summary: DebugSummary,
}

impl DebugReport {
    /// Create a new debug report
    pub fn new(category: impl Into<String>, issues: Vec<DebugIssue>) -> Self {
        let summary = DebugSummary::from_issues(&issues, issues.len());
        Self {
            timestamp: Utc::now(),
            category: category.into(),
            issues,
            summary,
        }
    }

    /// Create with explicit check count
    pub fn with_check_count(category: impl Into<String>, issues: Vec<DebugIssue>, total_checks: usize) -> Self {
        let summary = DebugSummary::from_issues(&issues, total_checks);
        Self {
            timestamp: Utc::now(),
            category: category.into(),
            issues,
            summary,
        }
    }

    /// Filter issues by severity
    pub fn filter_by_severity(&self, min_severity: Severity) -> Vec<&DebugIssue> {
        self.issues
            .iter()
            .filter(|i| i.severity <= min_severity)
            .collect()
    }

    /// Group issues by resource
    pub fn group_by_resource(&self) -> std::collections::HashMap<String, Vec<&DebugIssue>> {
        let mut groups = std::collections::HashMap::new();
        for issue in &self.issues {
            let key = if let Some(ns) = &issue.namespace {
                format!("{}/{}", ns, issue.resource_name)
            } else {
                issue.resource_name.clone()
            };
            groups.entry(key).or_insert_with(Vec::new).push(issue);
        }
        groups
    }

    /// Format for terminal output
    pub fn format_terminal(&self) -> String {
        let mut output = String::new();
        let reset = "\x1b[0m";
        let bold = "\x1b[1m";

        output.push_str(&format!(
            "\n{bold}Debug Report: {}{reset}\n",
            self.category.to_uppercase()
        ));
        output.push_str(&format!(
            "Generated: {}\n\n",
            self.timestamp.format("%Y-%m-%d %H:%M:%S UTC")
        ));

        // Summary
        let status_color = match self.summary.health_status() {
            "Critical" => "\x1b[31m",
            "Warning" => "\x1b[33m",
            _ => "\x1b[32m",
        };
        output.push_str(&format!(
            "Status: {status_color}{bold}{}{reset}\n",
            self.summary.health_status()
        ));
        output.push_str(&format!(
            "Critical: {} | Warnings: {} | Info: {}\n\n",
            self.summary.critical_count,
            self.summary.warning_count,
            self.summary.info_count
        ));

        // Issues grouped by severity
        let mut critical: Vec<_> = self.issues.iter().filter(|i| i.severity == Severity::Critical).collect();
        let mut warnings: Vec<_> = self.issues.iter().filter(|i| i.severity == Severity::Warning).collect();
        let mut info: Vec<_> = self.issues.iter().filter(|i| i.severity == Severity::Info).collect();

        critical.sort_by(|a, b| a.resource_name.cmp(&b.resource_name));
        warnings.sort_by(|a, b| a.resource_name.cmp(&b.resource_name));
        info.sort_by(|a, b| a.resource_name.cmp(&b.resource_name));

        if !critical.is_empty() {
            output.push_str(&format!("{bold}Critical Issues:{reset}\n"));
            for issue in critical {
                output.push_str(&issue.format_terminal());
            }
            output.push('\n');
        }

        if !warnings.is_empty() {
            output.push_str(&format!("{bold}Warnings:{reset}\n"));
            for issue in warnings {
                output.push_str(&issue.format_terminal());
            }
            output.push('\n');
        }

        if !info.is_empty() {
            output.push_str(&format!("{bold}Informational:{reset}\n"));
            for issue in info {
                output.push_str(&issue.format_terminal());
            }
        }

        if self.issues.is_empty() {
            output.push_str("\x1b[32mNo issues found!\x1b[0m\n");
        }

        output
    }
}

/// Exit code analysis result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExitCodeInfo {
    pub code: i32,
    pub signal: Option<String>,
    pub meaning: String,
    pub common_causes: Vec<String>,
}

impl ExitCodeInfo {
    /// Analyze exit code
    pub fn analyze(code: i32) -> Self {
        let (meaning, common_causes) = match code {
            0 => ("Success", vec!["Normal termination"]),
            1 => ("General error", vec![
                "Application error",
                "Uncaught exception",
                "Missing configuration",
            ]),
            2 => ("Misuse of shell command", vec![
                "Invalid arguments",
                "Missing required arguments",
            ]),
            // Application-specific exit codes (3-8)
            3 => ("Invalid usage", vec![
                "Missing required environment variable",
                "Configuration parsing error",
            ]),
            4 => ("Permission denied", vec![
                "Insufficient privileges",
                "Security context violation",
            ]),
            5 => ("I/O error", vec![
                "Disk full",
                "Read/write failure",
                "NFS mount stale",
            ]),
            6 => ("No such device", vec![
                "Missing mount point",
                "Volume detached",
            ]),
            7 => ("Argument list too long", vec![
                "Too many environment variables",
                "ConfigMap too large",
            ]),
            8 => ("Exec format error", vec![
                "Wrong architecture binary",
                "Corrupted executable",
            ]),
            126 => ("Command not executable", vec![
                "Permission denied",
                "Script not executable",
            ]),
            127 => ("Command not found", vec![
                "Binary not in PATH",
                "Missing dependency",
                "Wrong image",
            ]),
            128 => ("Invalid exit argument", vec!["Exit code out of range"]),
            // 128 + N = killed by signal N
            129 => ("SIGHUP", vec!["Hangup detected"]),
            130 => ("SIGINT (Ctrl+C)", vec!["Interrupted by user"]),
            131 => ("SIGQUIT", vec!["Quit signal"]),
            132 => ("SIGILL", vec!["Illegal instruction"]),
            133 => ("SIGTRAP", vec!["Trace/breakpoint trap"]),
            134 => ("SIGABRT", vec!["Abort signal", "Assertion failure"]),
            137 => ("SIGKILL (OOMKilled)", vec![
                "Out of memory",
                "Killed by kubelet",
                "Memory limit exceeded",
            ]),
            139 => ("SIGSEGV", vec![
                "Segmentation fault",
                "Invalid memory access",
            ]),
            143 => ("SIGTERM", vec![
                "Graceful termination requested",
                "Pod eviction",
                "Deployment rollout",
            ]),
            // Additional signals
            135 => ("SIGBUS", vec![
                "Bus error",
                "Invalid memory alignment",
                "Memory mapped file error",
            ]),
            136 => ("SIGFPE", vec![
                "Floating point exception",
                "Division by zero",
            ]),
            138 => ("SIGUSR1", vec![
                "Custom signal 1",
                "Application-specific shutdown",
            ]),
            140 => ("SIGUSR2", vec![
                "Custom signal 2",
                "Application-specific reload",
            ]),
            141 => ("SIGPIPE", vec![
                "Broken pipe",
                "Connection closed by remote end",
            ]),
            142 => ("SIGALRM", vec![
                "Alarm clock signal",
                "Timeout exceeded",
            ]),
            152 => ("SIGXCPU", vec![
                "CPU time limit exceeded",
                "Process ran too long",
            ]),
            153 => ("SIGXFSZ", vec![
                "File size limit exceeded",
                "Log rotation needed",
            ]),
            159 => ("SIGSYS", vec![
                "Bad system call",
                "Seccomp violation",
            ]),
            255 => ("Exit status out of range", vec![
                "Fatal error",
                "Script error",
            ]),
            _ => ("Unknown exit code", vec![]),
        };

        let signal = if code > 128 && code < 165 {
            Some(format!("Signal {}", code - 128))
        } else {
            None
        };

        Self {
            code,
            signal,
            meaning: meaning.to_string(),
            common_causes: common_causes.iter().map(|s| s.to_string()).collect(),
        }
    }
}

/// Container state analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContainerStateAnalysis {
    Running {
        started_at: Option<DateTime<Utc>>,
    },
    Waiting {
        reason: String,
        message: Option<String>,
        is_recoverable: bool,
        suggested_actions: Vec<String>,
    },
    Terminated {
        exit_code: i32,
        reason: String,
        message: Option<String>,
        exit_info: ExitCodeInfo,
    },
}

impl ContainerStateAnalysis {
    /// Analyze waiting state reason
    pub fn analyze_waiting_reason(reason: &str, _message: Option<&str>) -> (bool, Vec<String>) {
        match reason {
            "ContainerCreating" => (true, vec![
                "Wait for container to be created".to_string(),
                "If slow, run `kc describe pod <name>` to check node resources".to_string(),
            ]),
            "PodInitializing" => (true, vec![
                "Wait for init containers to complete".to_string(),
                "Run `kc logs <pod> -c <init-container>` to check progress".to_string(),
            ]),
            "ImagePullBackOff" | "ErrImagePull" => (true, vec![
                "Verify image name and tag exist in registry".to_string(),
                "Check imagePullSecrets: `kc describe pod <name>`".to_string(),
                "View detailed error in events: `kc describe pod <name>`".to_string(),
            ]),
            "CrashLoopBackOff" => (false, vec![
                "Run `kc logs <pod> --previous` to see crash logs".to_string(),
                "Check exit code in `kc describe pod <name>` under 'Last State'".to_string(),
                "Verify config and resources in pod spec".to_string(),
                "Test probe endpoint: `kc exec <pod> -- curl localhost:<port><path>`".to_string(),
            ]),
            "CreateContainerConfigError" => (false, vec![
                "Check ConfigMap exists: `kc get cm <name>`".to_string(),
                "Check Secret exists: `kc get secret <name>`".to_string(),
                "Verify key names: `kc describe pod <name>` shows error details".to_string(),
            ]),
            "CreateContainerError" => (false, vec![
                "Run `kc describe pod <name>` for detailed error".to_string(),
                "Verify security context settings are compatible".to_string(),
                "Check container runtime logs on the node".to_string(),
            ]),
            "InvalidImageName" => (false, vec![
                "Fix the image name in pod spec".to_string(),
                "Verify image reference format: registry/repo:tag".to_string(),
            ]),
            // New waiting reasons
            "RunContainerError" => (false, vec![
                "Run `kc describe pod <name>` to see detailed error".to_string(),
                "Check container runtime logs on the node".to_string(),
                "Verify security context settings are compatible".to_string(),
            ]),
            "PostStartHookError" => (false, vec![
                "Run `kc logs <pod> -c <container> --previous` to see logs before failure".to_string(),
                "Check postStart lifecycle hook command and dependencies".to_string(),
                "Verify required services/files are available at container start".to_string(),
            ]),
            "PreStopHookError" => (false, vec![
                "Check preStop hook command in pod spec".to_string(),
                "Verify hook timeout settings".to_string(),
            ]),
            "StartError" => (false, vec![
                "Run `kc describe pod <name>` for detailed error".to_string(),
                "Check if command/entrypoint exists in the image".to_string(),
                "Verify working directory and file permissions".to_string(),
            ]),
            "DeadlineExceeded" => (false, vec![
                "Container startup exceeded activeDeadlineSeconds".to_string(),
                "Consider increasing the deadline or optimizing startup time".to_string(),
            ]),
            "Evicted" => (false, vec![
                "Pod was evicted - run `kc describe pod <name>` for reason".to_string(),
                "Common causes: node memory/disk/PID pressure, preemption".to_string(),
                "Check node: `kc debug node <node-name>`".to_string(),
            ]),
            "NodeAffinity" => (true, vec![
                "Waiting for node matching affinity requirements".to_string(),
                "Run `kc nodes` to see available nodes".to_string(),
                "Review nodeAffinity and nodeSelector in pod spec".to_string(),
            ]),
            "ImageInspectError" => (false, vec![
                "Cannot inspect container image".to_string(),
                "Verify image exists and is accessible from node".to_string(),
                "Check container runtime status on the node".to_string(),
            ]),
            "ContainerStatusUnknown" => (true, vec![
                "Container status cannot be determined - transient state".to_string(),
                "If persistent, check node and kubelet health".to_string(),
            ]),
            "Blocked" => (false, vec![
                "Container is blocked from starting - check PodSecurityPolicy/PSA".to_string(),
                "Review security context and capabilities requirements".to_string(),
            ]),
            "ExceededGracePeriod" => (false, vec![
                "Container failed to terminate within grace period".to_string(),
                "Consider increasing terminationGracePeriodSeconds".to_string(),
            ]),
            "NodeLost" => (true, vec![
                "Node hosting this pod is unreachable".to_string(),
                "Pod may be rescheduled automatically once detected".to_string(),
                "Check node status and network connectivity".to_string(),
            ]),
            _ => (true, vec![
                "Run `kc describe pod <name>` for detailed status".to_string(),
                "Run `kc debug pod <name>` for full diagnostics".to_string(),
            ]),
        }
    }
}

/// Restart pattern detection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RestartPattern {
    pub restart_count: i32,
    pub pattern_type: RestartPatternType,
    pub avg_interval_seconds: Option<f64>,
    pub is_crash_loop: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RestartPatternType {
    /// Container is stable, no restarts
    Stable,
    /// Occasional restarts, likely transient issues
    Occasional,
    /// Frequent restarts, potential configuration issue
    Frequent,
    /// CrashLoopBackOff pattern detected
    CrashLoop,
    /// Regular interval restarts, possible liveness probe issue
    Periodic,
}

impl RestartPattern {
    /// Analyze restart pattern from count
    pub fn analyze(restart_count: i32) -> Self {
        let (pattern_type, is_crash_loop) = match restart_count {
            0 => (RestartPatternType::Stable, false),
            1..=3 => (RestartPatternType::Occasional, false),
            4..=10 => (RestartPatternType::Frequent, false),
            _ => (RestartPatternType::CrashLoop, true),
        };

        Self {
            restart_count,
            pattern_type,
            avg_interval_seconds: None,
            is_crash_loop,
        }
    }
}
