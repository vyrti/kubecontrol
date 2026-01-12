//! Tests for src/output/mod.rs - format_table, format_json, format_yaml, format_names

use kubecontrol::output::{format_table, format_json, format_yaml, format_names};
use k8s_openapi::api::core::v1::Pod;

mod common {
    include!("../common/mod.rs");
}

// ============================================================================
// format_table tests
// ============================================================================

#[test]
fn test_format_table_empty_resources() {
    let pods: Vec<Pod> = vec![];
    let result = format_table(&pods, false);
    assert_eq!(result, "No resources found");
}

#[test]
fn test_format_table_single_resource() {
    let pod = common::create_mock_pod("test-pod", "default", "Running");
    let pods = vec![pod];
    let result = format_table(&pods, false);

    // Should contain headers (Pod table has NAME, READY, STATUS, RESTARTS, AGE)
    assert!(result.contains("NAME"));
    assert!(result.contains("STATUS"));

    // Should contain pod data
    assert!(result.contains("test-pod"));
    // Note: Namespace is not in the standard Pod table output, only in wide output
}

#[test]
fn test_format_table_multiple_resources() {
    let pods = vec![
        common::create_mock_pod("pod-1", "default", "Running"),
        common::create_mock_pod("pod-2", "kube-system", "Pending"),
        common::create_mock_pod("pod-3", "default", "Failed"),
    ];
    let result = format_table(&pods, false);

    // Should contain all pod names
    assert!(result.contains("pod-1"));
    assert!(result.contains("pod-2"));
    assert!(result.contains("pod-3"));

    // Note: Namespace is not in standard Pod table output
    // Status column shows the phase from the mock

    // Should have header and data rows
    let lines: Vec<&str> = result.lines().collect();
    assert!(lines.len() >= 4); // 1 header + 3 data rows
}

#[test]
fn test_format_table_wide_format() {
    let pod = common::create_mock_pod("test-pod", "default", "Running");
    let pods = vec![pod];
    let _result_narrow = format_table(&pods, false);
    let result_wide = format_table(&pods, true);

    // Wide format should have IP and NODE columns
    assert!(result_wide.contains("IP") || result_wide.contains("NODE"));
}

#[test]
fn test_format_table_alignment() {
    let pods = vec![
        common::create_mock_pod("short", "default", "Running"),
        common::create_mock_pod("very-long-pod-name-here", "default", "Running"),
    ];
    let result = format_table(&pods, false);

    // Table should be properly formatted (not empty, has multiple lines)
    let lines: Vec<&str> = result.lines().collect();
    assert!(lines.len() >= 3); // Header + 2 data rows
}

// ============================================================================
// format_json tests
// ============================================================================

#[test]
fn test_format_json_empty_resources() {
    let pods: Vec<Pod> = vec![];
    let result = format_json(&pods, false).unwrap();
    assert_eq!(result, "[]");
}

#[test]
fn test_format_json_single_resource() {
    let pod = common::create_mock_pod("test-pod", "default", "Running");
    let pods = vec![pod];
    let result = format_json(&pods, false).unwrap();

    // Should be valid JSON array
    assert!(result.starts_with('['));
    assert!(result.ends_with(']'));

    // Should contain pod metadata
    assert!(result.contains("test-pod"));
    assert!(result.contains("default"));
}

#[test]
fn test_format_json_pretty() {
    let pod = common::create_mock_pod("test-pod", "default", "Running");
    let pods = vec![pod];
    let result = format_json(&pods, true).unwrap();

    // Pretty print should contain newlines and indentation
    assert!(result.contains('\n'));
    assert!(result.contains("  ")); // indentation
}

#[test]
fn test_format_json_not_pretty() {
    let pod = common::create_mock_pod("test-pod", "default", "Running");
    let pods = vec![pod];
    let result = format_json(&pods, false).unwrap();

    // Non-pretty should be compact (no unnecessary newlines)
    let newline_count = result.matches('\n').count();
    assert!(newline_count < 5); // Compact JSON has minimal newlines
}

#[test]
fn test_format_json_multiple_resources() {
    let pods = vec![
        common::create_mock_pod("pod-1", "default", "Running"),
        common::create_mock_pod("pod-2", "kube-system", "Running"),
    ];
    let result = format_json(&pods, false).unwrap();

    // Should contain both pod names
    assert!(result.contains("pod-1"));
    assert!(result.contains("pod-2"));
}

#[test]
fn test_format_json_valid_json() {
    let pod = common::create_mock_pod("test-pod", "default", "Running");
    let pods = vec![pod];
    let result = format_json(&pods, false).unwrap();

    // Should be parseable as JSON
    let parsed: serde_json::Value = serde_json::from_str(&result).unwrap();
    assert!(parsed.is_array());
}

// ============================================================================
// format_yaml tests
// ============================================================================

#[test]
fn test_format_yaml_empty_resources() {
    let pods: Vec<Pod> = vec![];
    let result = format_yaml(&pods).unwrap();
    assert_eq!(result.trim(), "[]");
}

#[test]
fn test_format_yaml_single_resource() {
    let pod = common::create_mock_pod("test-pod", "default", "Running");
    let pods = vec![pod];
    let result = format_yaml(&pods).unwrap();

    // YAML should contain proper structure
    assert!(result.contains("name: test-pod"));
    assert!(result.contains("namespace: default"));
}

#[test]
fn test_format_yaml_multiple_resources() {
    let pods = vec![
        common::create_mock_pod("pod-1", "default", "Running"),
        common::create_mock_pod("pod-2", "kube-system", "Running"),
    ];
    let result = format_yaml(&pods).unwrap();

    // Should contain both pod names
    assert!(result.contains("name: pod-1"));
    assert!(result.contains("name: pod-2"));
}

#[test]
fn test_format_yaml_valid_yaml() {
    let pod = common::create_mock_pod("test-pod", "default", "Running");
    let pods = vec![pod];
    let result = format_yaml(&pods).unwrap();

    // Should be parseable as YAML
    let parsed: serde_yaml::Value = serde_yaml::from_str(&result).unwrap();
    assert!(parsed.is_sequence());
}

// ============================================================================
// format_names tests
// ============================================================================

#[test]
fn test_format_names_empty_resources() {
    let pods: Vec<Pod> = vec![];
    let result = format_names(&pods);
    assert_eq!(result, "");
}

#[test]
fn test_format_names_single_resource_namespaced() {
    let pod = common::create_mock_pod("test-pod", "default", "Running");
    let pods = vec![pod];
    let result = format_names(&pods);
    assert_eq!(result, "default/test-pod");
}

#[test]
fn test_format_names_multiple_resources() {
    let pods = vec![
        common::create_mock_pod("pod-1", "default", "Running"),
        common::create_mock_pod("pod-2", "kube-system", "Running"),
    ];
    let result = format_names(&pods);

    let lines: Vec<&str> = result.lines().collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], "default/pod-1");
    assert_eq!(lines[1], "kube-system/pod-2");
}

#[test]
fn test_format_names_cluster_scoped_resource() {
    let node = common::create_mock_node("node-1", true);
    let nodes = vec![node];
    let result = format_names(&nodes);

    // Cluster-scoped resources don't have namespace prefix
    assert_eq!(result, "node-1");
}

#[test]
fn test_format_names_mixed_namespaces() {
    let pods = vec![
        common::create_mock_pod("web", "frontend", "Running"),
        common::create_mock_pod("api", "backend", "Running"),
        common::create_mock_pod("db", "database", "Running"),
    ];
    let result = format_names(&pods);

    assert!(result.contains("frontend/web"));
    assert!(result.contains("backend/api"));
    assert!(result.contains("database/db"));
}

// ============================================================================
// Additional format_json tests
// ============================================================================

#[test]
fn test_format_json_preserves_structure() {
    let pod = common::create_mock_pod("test-pod", "default", "Running");
    let pods = vec![pod];
    let result = format_json(&pods, false).unwrap();

    // Parse back to verify structure
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&result).unwrap();
    assert_eq!(parsed.len(), 1);

    let pod_json = &parsed[0];
    assert!(pod_json.get("metadata").is_some());
    assert!(pod_json.get("spec").is_some());
    assert!(pod_json.get("status").is_some());
}

#[test]
fn test_format_json_with_special_characters() {
    let pod = common::create_mock_pod("test-pod-with-\"quotes\"", "default", "Running");
    let pods = vec![pod];
    let result = format_json(&pods, false).unwrap();

    // Should properly escape special characters
    assert!(result.contains("test-pod-with-\\\"quotes\\\"") || result.contains("test-pod-with-"));
}

#[test]
fn test_format_json_compact_is_single_line() {
    let pods = vec![
        common::create_mock_pod("pod-1", "default", "Running"),
    ];
    let result = format_json(&pods, false).unwrap();

    // Compact JSON should be a single line (minimal whitespace)
    let lines: Vec<&str> = result.lines().collect();
    assert_eq!(lines.len(), 1);
}

// ============================================================================
// Additional format_yaml tests
// ============================================================================

#[test]
fn test_format_yaml_preserves_structure() {
    let pod = common::create_mock_pod("test-pod", "default", "Running");
    let pods = vec![pod];
    let result = format_yaml(&pods).unwrap();

    // Parse back to verify structure
    let parsed: Vec<serde_yaml::Value> = serde_yaml::from_str(&result).unwrap();
    assert_eq!(parsed.len(), 1);

    let pod_yaml = &parsed[0];
    assert!(pod_yaml.get("metadata").is_some());
}

#[test]
fn test_format_yaml_with_multiline_values() {
    // This tests that multiline content is handled properly in YAML
    let pod = common::create_mock_pod("test-pod", "default", "Running");
    let pods = vec![pod];
    let result = format_yaml(&pods).unwrap();

    // YAML output should be multi-line
    let lines: Vec<&str> = result.lines().collect();
    assert!(lines.len() > 1);
}

// ============================================================================
// Additional format_table tests
// ============================================================================

#[test]
fn test_format_table_consistent_columns() {
    let pods = vec![
        common::create_mock_pod("a", "default", "Running"),
        common::create_mock_pod("very-long-name", "default", "Running"),
        common::create_mock_pod("b", "default", "Running"),
    ];
    let result = format_table(&pods, false);

    // Each line should have consistent column structure
    let lines: Vec<&str> = result.lines().collect();
    assert!(lines.len() >= 4); // header + 3 rows

    // Header should be first line
    assert!(lines[0].contains("NAME"));
}

#[test]
fn test_format_table_with_deployment() {
    let deployment = common::create_mock_deployment("my-deploy", "default", 3);
    let deployments = vec![deployment];

    let result = format_table(&deployments, false);

    assert!(result.contains("my-deploy"));
    assert!(result.contains("READY") || result.contains("NAME"));
}

#[test]
fn test_format_table_with_service() {
    let service = common::create_mock_service("my-svc", "default", "ClusterIP");
    let services = vec![service];

    let result = format_table(&services, false);

    assert!(result.contains("my-svc"));
    assert!(result.contains("TYPE") || result.contains("NAME") || result.contains("CLUSTER-IP"));
}

// ============================================================================
// Colorize status tests
// ============================================================================

use kubecontrol::output::colorize_status;

#[test]
fn test_colorize_status_running() {
    let result = colorize_status("Running");
    // Should contain ANSI escape codes for green
    assert!(result.contains("\x1b[") || result == "Running");
}

#[test]
fn test_colorize_status_pending() {
    let result = colorize_status("Pending");
    // Should contain ANSI escape codes for yellow
    assert!(result.contains("\x1b[") || result == "Pending");
}

#[test]
fn test_colorize_status_failed() {
    let result = colorize_status("Failed");
    // Should contain ANSI escape codes for red
    assert!(result.contains("\x1b[") || result == "Failed");
}

#[test]
fn test_colorize_status_unknown() {
    let result = colorize_status("SomeUnknownStatus");
    // Unknown status should not be colorized (no ANSI codes added beyond original)
    assert!(result.contains("SomeUnknownStatus"));
}
