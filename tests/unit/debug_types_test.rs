//! Debug types unit tests
//!
//! Tests for Severity, DebugCategory, DebugIssue, DebugSummary, DebugReport,
//! ExitCodeInfo, ContainerStateAnalysis, and RestartPattern.

use kubecontrol::debug::types::*;
use serde_json::json;

// ============================================================================
// Severity enum tests
// ============================================================================

#[test]
fn test_severity_display_critical() {
    assert_eq!(format!("{}", Severity::Critical), "CRITICAL");
}

#[test]
fn test_severity_display_warning() {
    assert_eq!(format!("{}", Severity::Warning), "WARNING");
}

#[test]
fn test_severity_display_info() {
    assert_eq!(format!("{}", Severity::Info), "INFO");
}

#[test]
fn test_severity_color_code_critical() {
    assert_eq!(Severity::Critical.color_code(), "\x1b[31m");
}

#[test]
fn test_severity_color_code_warning() {
    assert_eq!(Severity::Warning.color_code(), "\x1b[33m");
}

#[test]
fn test_severity_color_code_info() {
    assert_eq!(Severity::Info.color_code(), "\x1b[36m");
}

#[test]
fn test_severity_css_class_critical() {
    assert_eq!(Severity::Critical.css_class(), "severity-critical");
}

#[test]
fn test_severity_css_class_warning() {
    assert_eq!(Severity::Warning.css_class(), "severity-warning");
}

#[test]
fn test_severity_css_class_info() {
    assert_eq!(Severity::Info.css_class(), "severity-info");
}

#[test]
fn test_severity_ordering() {
    // Critical < Warning < Info (most severe first)
    assert!(Severity::Critical < Severity::Warning);
    assert!(Severity::Warning < Severity::Info);
    assert!(Severity::Critical < Severity::Info);
}

#[test]
fn test_severity_equality() {
    assert_eq!(Severity::Critical, Severity::Critical);
    assert_ne!(Severity::Critical, Severity::Warning);
}

#[test]
fn test_severity_clone() {
    let severity = Severity::Warning;
    let cloned = severity.clone();
    assert_eq!(severity, cloned);
}

#[test]
fn test_severity_json_serialization_critical() {
    let json = serde_json::to_string(&Severity::Critical).unwrap();
    assert_eq!(json, "\"critical\"");
}

#[test]
fn test_severity_json_serialization_warning() {
    let json = serde_json::to_string(&Severity::Warning).unwrap();
    assert_eq!(json, "\"warning\"");
}

#[test]
fn test_severity_json_serialization_info() {
    let json = serde_json::to_string(&Severity::Info).unwrap();
    assert_eq!(json, "\"info\"");
}

#[test]
fn test_severity_json_deserialization() {
    let critical: Severity = serde_json::from_str("\"critical\"").unwrap();
    let warning: Severity = serde_json::from_str("\"warning\"").unwrap();
    let info: Severity = serde_json::from_str("\"info\"").unwrap();

    assert_eq!(critical, Severity::Critical);
    assert_eq!(warning, Severity::Warning);
    assert_eq!(info, Severity::Info);
}

// ============================================================================
// DebugCategory enum tests
// ============================================================================

#[test]
fn test_debug_category_display_dns() {
    assert_eq!(format!("{}", DebugCategory::Dns), "DNS");
}

#[test]
fn test_debug_category_display_network() {
    assert_eq!(format!("{}", DebugCategory::Network), "Network");
}

#[test]
fn test_debug_category_display_pod() {
    assert_eq!(format!("{}", DebugCategory::Pod), "Pod");
}

#[test]
fn test_debug_category_display_node() {
    assert_eq!(format!("{}", DebugCategory::Node), "Node");
}

#[test]
fn test_debug_category_display_deployment() {
    assert_eq!(format!("{}", DebugCategory::Deployment), "Deployment");
}

#[test]
fn test_debug_category_display_service() {
    assert_eq!(format!("{}", DebugCategory::Service), "Service");
}

#[test]
fn test_debug_category_display_storage() {
    assert_eq!(format!("{}", DebugCategory::Storage), "Storage");
}

#[test]
fn test_debug_category_display_security() {
    assert_eq!(format!("{}", DebugCategory::Security), "Security");
}

#[test]
fn test_debug_category_display_resources() {
    assert_eq!(format!("{}", DebugCategory::Resources), "Resources");
}

#[test]
fn test_debug_category_display_events() {
    assert_eq!(format!("{}", DebugCategory::Events), "Events");
}

#[test]
fn test_debug_category_display_ingress() {
    assert_eq!(format!("{}", DebugCategory::Ingress), "Ingress");
}

#[test]
fn test_debug_category_display_cluster() {
    assert_eq!(format!("{}", DebugCategory::Cluster), "Cluster");
}

#[test]
fn test_debug_category_equality() {
    assert_eq!(DebugCategory::Pod, DebugCategory::Pod);
    assert_ne!(DebugCategory::Pod, DebugCategory::Node);
}

#[test]
fn test_debug_category_clone() {
    let category = DebugCategory::Network;
    let cloned = category.clone();
    assert_eq!(category, cloned);
}

#[test]
fn test_debug_category_json_serialization() {
    assert_eq!(serde_json::to_string(&DebugCategory::Dns).unwrap(), "\"dns\"");
    assert_eq!(serde_json::to_string(&DebugCategory::Network).unwrap(), "\"network\"");
    assert_eq!(serde_json::to_string(&DebugCategory::Pod).unwrap(), "\"pod\"");
}

#[test]
fn test_debug_category_json_deserialization() {
    let dns: DebugCategory = serde_json::from_str("\"dns\"").unwrap();
    let network: DebugCategory = serde_json::from_str("\"network\"").unwrap();

    assert_eq!(dns, DebugCategory::Dns);
    assert_eq!(network, DebugCategory::Network);
}

// ============================================================================
// DebugIssue tests
// ============================================================================

#[test]
fn test_debug_issue_new() {
    let issue = DebugIssue::new(
        Severity::Warning,
        DebugCategory::Pod,
        "Pod",
        "my-pod",
        "Pod is unhealthy",
        "Readiness probe failed",
    );

    assert_eq!(issue.severity, Severity::Warning);
    assert_eq!(issue.category, DebugCategory::Pod);
    assert_eq!(issue.resource_type, "Pod");
    assert_eq!(issue.resource_name, "my-pod");
    assert_eq!(issue.title, "Pod is unhealthy");
    assert_eq!(issue.description, "Readiness probe failed");
    assert!(issue.namespace.is_none());
    assert!(issue.remediation.is_none());
    assert_eq!(issue.details, serde_json::Value::Null);
}

#[test]
fn test_debug_issue_with_namespace() {
    let issue = DebugIssue::new(
        Severity::Critical,
        DebugCategory::Pod,
        "Pod",
        "nginx",
        "CrashLoopBackOff",
        "Container keeps crashing",
    )
    .with_namespace("production");

    assert_eq!(issue.namespace, Some("production".to_string()));
}

#[test]
fn test_debug_issue_with_remediation() {
    let issue = DebugIssue::new(
        Severity::Warning,
        DebugCategory::Service,
        "Service",
        "my-svc",
        "No endpoints",
        "Service has no backend pods",
    )
    .with_remediation("Check pod selector labels match service selector");

    assert_eq!(
        issue.remediation,
        Some("Check pod selector labels match service selector".to_string())
    );
}

#[test]
fn test_debug_issue_with_details() {
    let details = json!({
        "exit_code": 137,
        "signal": "SIGKILL"
    });

    let issue = DebugIssue::new(
        Severity::Critical,
        DebugCategory::Pod,
        "Pod",
        "worker",
        "OOMKilled",
        "Container was killed due to OOM",
    )
    .with_details(details.clone());

    assert_eq!(issue.details, details);
}

#[test]
fn test_debug_issue_builder_chain() {
    let issue = DebugIssue::new(
        Severity::Critical,
        DebugCategory::Deployment,
        "Deployment",
        "api-server",
        "Rollout stuck",
        "Deployment is not progressing",
    )
    .with_namespace("default")
    .with_remediation("Check pod events and logs")
    .with_details(json!({"replicas": 3, "ready": 0}));

    assert_eq!(issue.namespace, Some("default".to_string()));
    assert_eq!(issue.remediation, Some("Check pod events and logs".to_string()));
    assert_eq!(issue.details["replicas"], 3);
    assert_eq!(issue.details["ready"], 0);
}

#[test]
fn test_debug_issue_format_terminal_without_namespace() {
    let issue = DebugIssue::new(
        Severity::Warning,
        DebugCategory::Node,
        "Node",
        "worker-1",
        "Disk pressure",
        "Node is experiencing disk pressure",
    );

    let output = issue.format_terminal();

    assert!(output.contains("WARNING"));
    assert!(output.contains("Disk pressure"));
    assert!(output.contains("worker-1 (Node)"));
    assert!(output.contains("Node is experiencing disk pressure"));
}

#[test]
fn test_debug_issue_format_terminal_with_namespace() {
    let issue = DebugIssue::new(
        Severity::Critical,
        DebugCategory::Pod,
        "Pod",
        "nginx-abc123",
        "CrashLoopBackOff",
        "Container repeatedly failing",
    )
    .with_namespace("web");

    let output = issue.format_terminal();

    assert!(output.contains("CRITICAL"));
    assert!(output.contains("web/nginx-abc123 (Pod)"));
}

#[test]
fn test_debug_issue_format_terminal_with_remediation() {
    let issue = DebugIssue::new(
        Severity::Info,
        DebugCategory::Security,
        "Pod",
        "test-pod",
        "No resource limits",
        "Container has no resource limits defined",
    )
    .with_remediation("Add resource limits to container spec");

    let output = issue.format_terminal();

    assert!(output.contains("Remediation: Add resource limits to container spec"));
}

#[test]
fn test_debug_issue_json_serialization() {
    let issue = DebugIssue::new(
        Severity::Warning,
        DebugCategory::Pod,
        "Pod",
        "test",
        "Test issue",
        "Test description",
    );

    let json = serde_json::to_string(&issue).unwrap();

    assert!(json.contains("\"severity\":\"warning\""));
    assert!(json.contains("\"category\":\"pod\""));
    assert!(json.contains("\"resource_name\":\"test\""));
}

// ============================================================================
// DebugSummary tests
// ============================================================================

#[test]
fn test_debug_summary_from_empty_issues() {
    let issues: Vec<DebugIssue> = vec![];
    let summary = DebugSummary::from_issues(&issues, 10);

    assert_eq!(summary.critical_count, 0);
    assert_eq!(summary.warning_count, 0);
    assert_eq!(summary.info_count, 0);
    assert_eq!(summary.total_checks, 10);
    assert_eq!(summary.passed_checks, 10);
    assert_eq!(summary.failed_checks, 0);
}

#[test]
fn test_debug_summary_from_critical_issues() {
    let issues = vec![
        DebugIssue::new(Severity::Critical, DebugCategory::Pod, "Pod", "p1", "t1", "d1"),
        DebugIssue::new(Severity::Critical, DebugCategory::Pod, "Pod", "p2", "t2", "d2"),
    ];
    let summary = DebugSummary::from_issues(&issues, 5);

    assert_eq!(summary.critical_count, 2);
    assert_eq!(summary.warning_count, 0);
    assert_eq!(summary.info_count, 0);
    assert_eq!(summary.total_checks, 5);
    assert_eq!(summary.passed_checks, 3);
    assert_eq!(summary.failed_checks, 2);
}

#[test]
fn test_debug_summary_from_mixed_issues() {
    let issues = vec![
        DebugIssue::new(Severity::Critical, DebugCategory::Pod, "Pod", "p1", "t1", "d1"),
        DebugIssue::new(Severity::Warning, DebugCategory::Pod, "Pod", "p2", "t2", "d2"),
        DebugIssue::new(Severity::Warning, DebugCategory::Pod, "Pod", "p3", "t3", "d3"),
        DebugIssue::new(Severity::Info, DebugCategory::Pod, "Pod", "p4", "t4", "d4"),
    ];
    let summary = DebugSummary::from_issues(&issues, 10);

    assert_eq!(summary.critical_count, 1);
    assert_eq!(summary.warning_count, 2);
    assert_eq!(summary.info_count, 1);
    assert_eq!(summary.total_checks, 10);
    assert_eq!(summary.passed_checks, 7); // 10 - (1 critical + 2 warnings)
    assert_eq!(summary.failed_checks, 3); // 1 critical + 2 warnings
}

#[test]
fn test_debug_summary_health_status_healthy() {
    let issues: Vec<DebugIssue> = vec![
        DebugIssue::new(Severity::Info, DebugCategory::Pod, "Pod", "p1", "t1", "d1"),
    ];
    let summary = DebugSummary::from_issues(&issues, 5);

    assert_eq!(summary.health_status(), "Healthy");
}

#[test]
fn test_debug_summary_health_status_warning() {
    let issues = vec![
        DebugIssue::new(Severity::Warning, DebugCategory::Pod, "Pod", "p1", "t1", "d1"),
        DebugIssue::new(Severity::Info, DebugCategory::Pod, "Pod", "p2", "t2", "d2"),
    ];
    let summary = DebugSummary::from_issues(&issues, 5);

    assert_eq!(summary.health_status(), "Warning");
}

#[test]
fn test_debug_summary_health_status_critical() {
    let issues = vec![
        DebugIssue::new(Severity::Critical, DebugCategory::Pod, "Pod", "p1", "t1", "d1"),
        DebugIssue::new(Severity::Warning, DebugCategory::Pod, "Pod", "p2", "t2", "d2"),
    ];
    let summary = DebugSummary::from_issues(&issues, 5);

    assert_eq!(summary.health_status(), "Critical");
}

#[test]
fn test_debug_summary_default() {
    let summary = DebugSummary::default();

    assert_eq!(summary.critical_count, 0);
    assert_eq!(summary.warning_count, 0);
    assert_eq!(summary.info_count, 0);
    assert_eq!(summary.total_checks, 0);
    assert_eq!(summary.passed_checks, 0);
    assert_eq!(summary.failed_checks, 0);
}

// ============================================================================
// DebugReport tests
// ============================================================================

#[test]
fn test_debug_report_new() {
    let issues = vec![
        DebugIssue::new(Severity::Warning, DebugCategory::Pod, "Pod", "p1", "t1", "d1"),
    ];
    let report = DebugReport::new("pod", issues);

    assert_eq!(report.category, "pod");
    assert_eq!(report.issues.len(), 1);
    assert_eq!(report.summary.warning_count, 1);
}

#[test]
fn test_debug_report_with_check_count() {
    let issues = vec![
        DebugIssue::new(Severity::Warning, DebugCategory::Pod, "Pod", "p1", "t1", "d1"),
    ];
    let report = DebugReport::with_check_count("pod", issues, 10);

    assert_eq!(report.summary.total_checks, 10);
    assert_eq!(report.summary.passed_checks, 9);
    assert_eq!(report.summary.failed_checks, 1);
}

#[test]
fn test_debug_report_filter_by_severity_critical() {
    let issues = vec![
        DebugIssue::new(Severity::Critical, DebugCategory::Pod, "Pod", "p1", "t1", "d1"),
        DebugIssue::new(Severity::Warning, DebugCategory::Pod, "Pod", "p2", "t2", "d2"),
        DebugIssue::new(Severity::Info, DebugCategory::Pod, "Pod", "p3", "t3", "d3"),
    ];
    let report = DebugReport::new("pod", issues);

    // Filter to Critical only (min_severity = Critical)
    let critical_only = report.filter_by_severity(Severity::Critical);
    assert_eq!(critical_only.len(), 1);
    assert_eq!(critical_only[0].severity, Severity::Critical);
}

#[test]
fn test_debug_report_filter_by_severity_warning() {
    let issues = vec![
        DebugIssue::new(Severity::Critical, DebugCategory::Pod, "Pod", "p1", "t1", "d1"),
        DebugIssue::new(Severity::Warning, DebugCategory::Pod, "Pod", "p2", "t2", "d2"),
        DebugIssue::new(Severity::Info, DebugCategory::Pod, "Pod", "p3", "t3", "d3"),
    ];
    let report = DebugReport::new("pod", issues);

    // Filter to Warning or higher (Critical and Warning)
    let warnings_and_above = report.filter_by_severity(Severity::Warning);
    assert_eq!(warnings_and_above.len(), 2);
}

#[test]
fn test_debug_report_group_by_resource() {
    let issues = vec![
        DebugIssue::new(Severity::Critical, DebugCategory::Pod, "Pod", "pod-1", "t1", "d1")
            .with_namespace("ns1"),
        DebugIssue::new(Severity::Warning, DebugCategory::Pod, "Pod", "pod-1", "t2", "d2")
            .with_namespace("ns1"),
        DebugIssue::new(Severity::Info, DebugCategory::Pod, "Pod", "pod-2", "t3", "d3")
            .with_namespace("ns2"),
    ];
    let report = DebugReport::new("pod", issues);

    let groups = report.group_by_resource();

    assert_eq!(groups.len(), 2);
    assert_eq!(groups.get("ns1/pod-1").unwrap().len(), 2);
    assert_eq!(groups.get("ns2/pod-2").unwrap().len(), 1);
}

#[test]
fn test_debug_report_group_by_resource_without_namespace() {
    let issues = vec![
        DebugIssue::new(Severity::Warning, DebugCategory::Node, "Node", "node-1", "t1", "d1"),
        DebugIssue::new(Severity::Warning, DebugCategory::Node, "Node", "node-1", "t2", "d2"),
    ];
    let report = DebugReport::new("node", issues);

    let groups = report.group_by_resource();

    assert_eq!(groups.len(), 1);
    assert_eq!(groups.get("node-1").unwrap().len(), 2);
}

#[test]
fn test_debug_report_format_terminal_no_issues() {
    let report = DebugReport::new("cluster", vec![]);
    let output = report.format_terminal();

    assert!(output.contains("CLUSTER"));
    assert!(output.contains("No issues found!"));
    assert!(output.contains("Critical: 0"));
}

#[test]
fn test_debug_report_format_terminal_with_issues() {
    let issues = vec![
        DebugIssue::new(Severity::Critical, DebugCategory::Pod, "Pod", "crash", "OOMKilled", "d1"),
        DebugIssue::new(Severity::Warning, DebugCategory::Pod, "Pod", "warn", "High CPU", "d2"),
    ];
    let report = DebugReport::new("pod", issues);
    let output = report.format_terminal();

    assert!(output.contains("POD"));
    assert!(output.contains("Critical Issues:"));
    assert!(output.contains("Warnings:"));
    assert!(output.contains("Critical: 1"));
    assert!(output.contains("Warnings: 1"));
}

#[test]
fn test_debug_report_json_serialization() {
    let issues = vec![
        DebugIssue::new(Severity::Warning, DebugCategory::Pod, "Pod", "test", "t1", "d1"),
    ];
    let report = DebugReport::new("test", issues);

    let json = serde_json::to_string(&report).unwrap();

    assert!(json.contains("\"category\":\"test\""));
    assert!(json.contains("\"warning_count\":1"));
}

// ============================================================================
// ExitCodeInfo tests
// ============================================================================

#[test]
fn test_exit_code_info_analyze_success() {
    let info = ExitCodeInfo::analyze(0);

    assert_eq!(info.code, 0);
    assert_eq!(info.meaning, "Success");
    assert!(info.signal.is_none());
    assert!(info.common_causes.contains(&"Normal termination".to_string()));
}

#[test]
fn test_exit_code_info_analyze_general_error() {
    let info = ExitCodeInfo::analyze(1);

    assert_eq!(info.code, 1);
    assert_eq!(info.meaning, "General error");
    assert!(info.signal.is_none());
    assert!(info.common_causes.contains(&"Application error".to_string()));
}

#[test]
fn test_exit_code_info_analyze_command_not_found() {
    let info = ExitCodeInfo::analyze(127);

    assert_eq!(info.code, 127);
    assert_eq!(info.meaning, "Command not found");
    assert!(info.common_causes.contains(&"Binary not in PATH".to_string()));
}

#[test]
fn test_exit_code_info_analyze_sigkill() {
    let info = ExitCodeInfo::analyze(137);

    assert_eq!(info.code, 137);
    assert_eq!(info.meaning, "SIGKILL (OOMKilled)");
    assert_eq!(info.signal, Some("Signal 9".to_string()));
    assert!(info.common_causes.contains(&"Out of memory".to_string()));
}

#[test]
fn test_exit_code_info_analyze_sigterm() {
    let info = ExitCodeInfo::analyze(143);

    assert_eq!(info.code, 143);
    assert_eq!(info.meaning, "SIGTERM");
    assert_eq!(info.signal, Some("Signal 15".to_string()));
    assert!(info.common_causes.contains(&"Graceful termination requested".to_string()));
}

#[test]
fn test_exit_code_info_analyze_sigsegv() {
    let info = ExitCodeInfo::analyze(139);

    assert_eq!(info.code, 139);
    assert_eq!(info.meaning, "SIGSEGV");
    assert_eq!(info.signal, Some("Signal 11".to_string()));
    assert!(info.common_causes.contains(&"Segmentation fault".to_string()));
}

#[test]
fn test_exit_code_info_analyze_sigint() {
    let info = ExitCodeInfo::analyze(130);

    assert_eq!(info.code, 130);
    assert_eq!(info.meaning, "SIGINT (Ctrl+C)");
    assert_eq!(info.signal, Some("Signal 2".to_string()));
}

#[test]
fn test_exit_code_info_analyze_sigabrt() {
    let info = ExitCodeInfo::analyze(134);

    assert_eq!(info.code, 134);
    assert_eq!(info.meaning, "SIGABRT");
    assert_eq!(info.signal, Some("Signal 6".to_string()));
    assert!(info.common_causes.contains(&"Assertion failure".to_string()));
}

#[test]
fn test_exit_code_info_analyze_unknown() {
    let info = ExitCodeInfo::analyze(42);

    assert_eq!(info.code, 42);
    assert_eq!(info.meaning, "Unknown exit code");
    assert!(info.signal.is_none());
    assert!(info.common_causes.is_empty());
}

#[test]
fn test_exit_code_info_analyze_out_of_range() {
    let info = ExitCodeInfo::analyze(255);

    assert_eq!(info.code, 255);
    assert_eq!(info.meaning, "Exit status out of range");
}

#[test]
fn test_exit_code_info_json_serialization() {
    let info = ExitCodeInfo::analyze(137);
    let json = serde_json::to_string(&info).unwrap();

    assert!(json.contains("\"code\":137"));
    assert!(json.contains("\"signal\":\"Signal 9\""));
}

// ============================================================================
// ContainerStateAnalysis tests
// ============================================================================

#[test]
fn test_analyze_waiting_reason_container_creating() {
    let (is_recoverable, actions) = ContainerStateAnalysis::analyze_waiting_reason("ContainerCreating", None);

    assert!(is_recoverable);
    assert!(!actions.is_empty());
    assert!(actions.iter().any(|a| a.contains("Wait for container")));
}

#[test]
fn test_analyze_waiting_reason_pod_initializing() {
    let (is_recoverable, actions) = ContainerStateAnalysis::analyze_waiting_reason("PodInitializing", None);

    assert!(is_recoverable);
    assert!(actions.iter().any(|a| a.contains("init containers")));
}

#[test]
fn test_analyze_waiting_reason_image_pull_backoff() {
    let (is_recoverable, actions) = ContainerStateAnalysis::analyze_waiting_reason("ImagePullBackOff", None);

    assert!(is_recoverable);
    assert!(actions.iter().any(|a| a.contains("image name")));
    assert!(actions.iter().any(|a| a.contains("imagePullSecrets")));
}

#[test]
fn test_analyze_waiting_reason_err_image_pull() {
    let (is_recoverable, actions) = ContainerStateAnalysis::analyze_waiting_reason("ErrImagePull", None);

    assert!(is_recoverable);
    assert!(actions.iter().any(|a| a.contains("image name")));
}

#[test]
fn test_analyze_waiting_reason_crash_loop_backoff() {
    let (is_recoverable, actions) = ContainerStateAnalysis::analyze_waiting_reason("CrashLoopBackOff", None);

    assert!(!is_recoverable);
    assert!(actions.iter().any(|a| a.contains("crash logs")));
    assert!(actions.iter().any(|a| a.contains("exit code")));
}

#[test]
fn test_analyze_waiting_reason_create_container_config_error() {
    let (is_recoverable, actions) = ContainerStateAnalysis::analyze_waiting_reason("CreateContainerConfigError", None);

    assert!(!is_recoverable);
    assert!(actions.iter().any(|a| a.contains("ConfigMap")));
}

#[test]
fn test_analyze_waiting_reason_create_container_error() {
    let (is_recoverable, actions) = ContainerStateAnalysis::analyze_waiting_reason("CreateContainerError", None);

    assert!(!is_recoverable);
    assert!(actions.iter().any(|a| a.contains("container runtime")));
}

#[test]
fn test_analyze_waiting_reason_invalid_image_name() {
    let (is_recoverable, actions) = ContainerStateAnalysis::analyze_waiting_reason("InvalidImageName", None);

    assert!(!is_recoverable);
    assert!(actions.iter().any(|a| a.contains("Fix the image name")));
}

#[test]
fn test_analyze_waiting_reason_unknown() {
    let (is_recoverable, actions) = ContainerStateAnalysis::analyze_waiting_reason("SomeUnknownReason", None);

    assert!(is_recoverable);
    assert!(actions.iter().any(|a| a.contains("kc describe pod")));
}

// ============================================================================
// RestartPattern tests
// ============================================================================

#[test]
fn test_restart_pattern_analyze_stable() {
    let pattern = RestartPattern::analyze(0);

    assert_eq!(pattern.restart_count, 0);
    assert!(matches!(pattern.pattern_type, RestartPatternType::Stable));
    assert!(!pattern.is_crash_loop);
    assert!(pattern.avg_interval_seconds.is_none());
}

#[test]
fn test_restart_pattern_analyze_occasional() {
    for count in 1..=3 {
        let pattern = RestartPattern::analyze(count);

        assert_eq!(pattern.restart_count, count);
        assert!(matches!(pattern.pattern_type, RestartPatternType::Occasional));
        assert!(!pattern.is_crash_loop);
    }
}

#[test]
fn test_restart_pattern_analyze_frequent() {
    for count in 4..=10 {
        let pattern = RestartPattern::analyze(count);

        assert_eq!(pattern.restart_count, count);
        assert!(matches!(pattern.pattern_type, RestartPatternType::Frequent));
        assert!(!pattern.is_crash_loop);
    }
}

#[test]
fn test_restart_pattern_analyze_crash_loop() {
    let pattern = RestartPattern::analyze(15);

    assert_eq!(pattern.restart_count, 15);
    assert!(matches!(pattern.pattern_type, RestartPatternType::CrashLoop));
    assert!(pattern.is_crash_loop);
}

#[test]
fn test_restart_pattern_analyze_boundary_values() {
    // Test boundary between stable and occasional
    assert!(matches!(RestartPattern::analyze(0).pattern_type, RestartPatternType::Stable));
    assert!(matches!(RestartPattern::analyze(1).pattern_type, RestartPatternType::Occasional));

    // Test boundary between occasional and frequent
    assert!(matches!(RestartPattern::analyze(3).pattern_type, RestartPatternType::Occasional));
    assert!(matches!(RestartPattern::analyze(4).pattern_type, RestartPatternType::Frequent));

    // Test boundary between frequent and crash loop
    assert!(matches!(RestartPattern::analyze(10).pattern_type, RestartPatternType::Frequent));
    assert!(matches!(RestartPattern::analyze(11).pattern_type, RestartPatternType::CrashLoop));
}

#[test]
fn test_restart_pattern_json_serialization() {
    let pattern = RestartPattern::analyze(5);
    let json = serde_json::to_string(&pattern).unwrap();

    assert!(json.contains("\"restart_count\":5"));
    assert!(json.contains("\"is_crash_loop\":false"));
}

#[test]
fn test_restart_pattern_type_serialization() {
    let stable = RestartPatternType::Stable;
    let occasional = RestartPatternType::Occasional;
    let frequent = RestartPatternType::Frequent;
    let crash_loop = RestartPatternType::CrashLoop;
    let periodic = RestartPatternType::Periodic;

    // These should all serialize without panicking
    let _ = serde_json::to_string(&stable).unwrap();
    let _ = serde_json::to_string(&occasional).unwrap();
    let _ = serde_json::to_string(&frequent).unwrap();
    let _ = serde_json::to_string(&crash_loop).unwrap();
    let _ = serde_json::to_string(&periodic).unwrap();
}
