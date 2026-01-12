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
