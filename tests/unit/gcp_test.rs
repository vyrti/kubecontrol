//! GCP GKE detection unit tests
//!
//! Tests for GKE-specific detection helper functions.

use k8s_openapi::api::core::v1::Node;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kubecontrol::debug::gcp::{is_gke, is_gke_autopilot};
use std::collections::BTreeMap;

// ============================================================================
// Helper functions to create mock nodes
// ============================================================================

fn create_node_with_labels(name: &str, labels: BTreeMap<String, String>) -> Node {
    Node {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        ..Default::default()
    }
}

// ============================================================================
// is_gke tests
// ============================================================================

#[test]
fn test_is_gke_with_nodepool_label() {
    let mut labels = BTreeMap::new();
    labels.insert("cloud.google.com/gke-nodepool".to_string(), "default-pool".to_string());

    let nodes = vec![create_node_with_labels("gke-node", labels)];

    assert!(is_gke(&nodes));
}

#[test]
fn test_is_gke_with_os_distribution_label() {
    let mut labels = BTreeMap::new();
    labels.insert("cloud.google.com/gke-os-distribution".to_string(), "cos".to_string());

    let nodes = vec![create_node_with_labels("gke-node", labels)];

    assert!(is_gke(&nodes));
}

#[test]
fn test_is_gke_with_both_labels() {
    let mut labels = BTreeMap::new();
    labels.insert("cloud.google.com/gke-nodepool".to_string(), "default-pool".to_string());
    labels.insert("cloud.google.com/gke-os-distribution".to_string(), "cos".to_string());

    let nodes = vec![create_node_with_labels("gke-node", labels)];

    assert!(is_gke(&nodes));
}

#[test]
fn test_is_gke_without_gke_labels() {
    let mut labels = BTreeMap::new();
    labels.insert("some-other-label".to_string(), "value".to_string());

    let nodes = vec![create_node_with_labels("generic-node", labels)];

    assert!(!is_gke(&nodes));
}

#[test]
fn test_is_gke_empty_labels() {
    let nodes = vec![create_node_with_labels("node", BTreeMap::new())];

    assert!(!is_gke(&nodes));
}

#[test]
fn test_is_gke_no_labels() {
    let node = Node {
        metadata: ObjectMeta {
            name: Some("node".to_string()),
            labels: None,
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(!is_gke(&[node]));
}

#[test]
fn test_is_gke_empty_node_list() {
    let nodes: Vec<Node> = vec![];

    assert!(!is_gke(&nodes));
}

#[test]
fn test_is_gke_multiple_nodes_one_is_gke() {
    let mut gke_labels = BTreeMap::new();
    gke_labels.insert("cloud.google.com/gke-nodepool".to_string(), "pool".to_string());

    let nodes = vec![
        create_node_with_labels("non-gke", BTreeMap::new()),
        create_node_with_labels("gke-node", gke_labels),
    ];

    assert!(is_gke(&nodes));
}

// ============================================================================
// is_gke_autopilot tests
// ============================================================================

#[test]
fn test_is_gke_autopilot_true() {
    let mut labels = BTreeMap::new();
    labels.insert("cloud.google.com/gke-autopilot".to_string(), "true".to_string());

    let nodes = vec![create_node_with_labels("autopilot-node", labels)];

    assert!(is_gke_autopilot(&nodes));
}

#[test]
fn test_is_gke_autopilot_with_empty_value() {
    let mut labels = BTreeMap::new();
    labels.insert("cloud.google.com/gke-autopilot".to_string(), "".to_string());

    let nodes = vec![create_node_with_labels("autopilot-node", labels)];

    // Label exists, value doesn't matter for detection
    assert!(is_gke_autopilot(&nodes));
}

#[test]
fn test_is_gke_autopilot_false_standard_gke() {
    let mut labels = BTreeMap::new();
    labels.insert("cloud.google.com/gke-nodepool".to_string(), "default-pool".to_string());
    // Note: no gke-autopilot label

    let nodes = vec![create_node_with_labels("standard-gke-node", labels)];

    assert!(!is_gke_autopilot(&nodes));
}

#[test]
fn test_is_gke_autopilot_empty_nodes() {
    let nodes: Vec<Node> = vec![];

    assert!(!is_gke_autopilot(&nodes));
}

#[test]
fn test_is_gke_autopilot_no_labels() {
    let node = Node {
        metadata: ObjectMeta {
            name: Some("node".to_string()),
            labels: None,
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(!is_gke_autopilot(&[node]));
}

#[test]
fn test_is_gke_autopilot_multiple_nodes() {
    let mut autopilot_labels = BTreeMap::new();
    autopilot_labels.insert("cloud.google.com/gke-autopilot".to_string(), "true".to_string());

    let nodes = vec![
        create_node_with_labels("ap-node-1", autopilot_labels.clone()),
        create_node_with_labels("ap-node-2", autopilot_labels),
    ];

    assert!(is_gke_autopilot(&nodes));
}

// ============================================================================
// Combination tests
// ============================================================================

#[test]
fn test_gke_autopilot_is_also_gke() {
    let mut labels = BTreeMap::new();
    labels.insert("cloud.google.com/gke-autopilot".to_string(), "true".to_string());
    labels.insert("cloud.google.com/gke-nodepool".to_string(), "default-pool".to_string());

    let nodes = vec![create_node_with_labels("autopilot-node", labels)];

    // Autopilot nodes are also GKE nodes
    assert!(is_gke(&nodes));
    assert!(is_gke_autopilot(&nodes));
}

#[test]
fn test_standard_gke_not_autopilot() {
    let mut labels = BTreeMap::new();
    labels.insert("cloud.google.com/gke-nodepool".to_string(), "default-pool".to_string());
    labels.insert("cloud.google.com/gke-os-distribution".to_string(), "cos".to_string());

    let nodes = vec![create_node_with_labels("standard-node", labels)];

    assert!(is_gke(&nodes));
    assert!(!is_gke_autopilot(&nodes));
}
