//! Azure AKS detection unit tests
//!
//! Tests for AKS-specific detection helper functions.

use k8s_openapi::api::core::v1::Node;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kubecontrol::debug::azure::{is_aks, has_virtual_nodes};
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
// is_aks tests
// ============================================================================

#[test]
fn test_is_aks_with_agentpool_label() {
    let mut labels = BTreeMap::new();
    labels.insert("kubernetes.azure.com/agentpool".to_string(), "nodepool1".to_string());

    let nodes = vec![create_node_with_labels("aks-node", labels)];

    assert!(is_aks(&nodes));
}

#[test]
fn test_is_aks_with_cluster_label() {
    let mut labels = BTreeMap::new();
    labels.insert("kubernetes.azure.com/cluster".to_string(), "my-aks-cluster".to_string());

    let nodes = vec![create_node_with_labels("aks-node", labels)];

    assert!(is_aks(&nodes));
}

#[test]
fn test_is_aks_with_both_labels() {
    let mut labels = BTreeMap::new();
    labels.insert("kubernetes.azure.com/agentpool".to_string(), "nodepool1".to_string());
    labels.insert("kubernetes.azure.com/cluster".to_string(), "my-cluster".to_string());

    let nodes = vec![create_node_with_labels("aks-node", labels)];

    assert!(is_aks(&nodes));
}

#[test]
fn test_is_aks_without_aks_labels() {
    let mut labels = BTreeMap::new();
    labels.insert("some-other-label".to_string(), "value".to_string());

    let nodes = vec![create_node_with_labels("generic-node", labels)];

    assert!(!is_aks(&nodes));
}

#[test]
fn test_is_aks_empty_labels() {
    let nodes = vec![create_node_with_labels("node", BTreeMap::new())];

    assert!(!is_aks(&nodes));
}

#[test]
fn test_is_aks_no_labels() {
    let node = Node {
        metadata: ObjectMeta {
            name: Some("node".to_string()),
            labels: None,
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(!is_aks(&[node]));
}

#[test]
fn test_is_aks_empty_node_list() {
    let nodes: Vec<Node> = vec![];

    assert!(!is_aks(&nodes));
}

#[test]
fn test_is_aks_multiple_nodes_one_is_aks() {
    let mut aks_labels = BTreeMap::new();
    aks_labels.insert("kubernetes.azure.com/agentpool".to_string(), "pool".to_string());

    let nodes = vec![
        create_node_with_labels("non-aks", BTreeMap::new()),
        create_node_with_labels("aks-node", aks_labels),
    ];

    assert!(is_aks(&nodes));
}

// ============================================================================
// has_virtual_nodes tests
// ============================================================================

#[test]
fn test_has_virtual_nodes_true() {
    let mut labels = BTreeMap::new();
    labels.insert("type".to_string(), "virtual-kubelet".to_string());

    let nodes = vec![create_node_with_labels("virtual-node-aci-linux", labels)];

    assert!(has_virtual_nodes(&nodes));
}

#[test]
fn test_has_virtual_nodes_false_no_virtual_nodes() {
    let mut labels = BTreeMap::new();
    labels.insert("kubernetes.azure.com/agentpool".to_string(), "nodepool1".to_string());

    let nodes = vec![create_node_with_labels("aks-node", labels)];

    assert!(!has_virtual_nodes(&nodes));
}

#[test]
fn test_has_virtual_nodes_empty_nodes() {
    let nodes: Vec<Node> = vec![];

    assert!(!has_virtual_nodes(&nodes));
}

#[test]
fn test_has_virtual_nodes_no_labels() {
    let node = Node {
        metadata: ObjectMeta {
            name: Some("node".to_string()),
            labels: None,
            ..Default::default()
        },
        ..Default::default()
    };

    assert!(!has_virtual_nodes(&[node]));
}

#[test]
fn test_has_virtual_nodes_wrong_type_label_value() {
    let mut labels = BTreeMap::new();
    labels.insert("type".to_string(), "regular-node".to_string());

    let nodes = vec![create_node_with_labels("node", labels)];

    assert!(!has_virtual_nodes(&nodes));
}

#[test]
fn test_has_virtual_nodes_mixed_cluster() {
    let mut aks_labels = BTreeMap::new();
    aks_labels.insert("kubernetes.azure.com/agentpool".to_string(), "nodepool1".to_string());

    let mut virtual_labels = BTreeMap::new();
    virtual_labels.insert("type".to_string(), "virtual-kubelet".to_string());

    let nodes = vec![
        create_node_with_labels("aks-node-1", aks_labels.clone()),
        create_node_with_labels("aks-node-2", aks_labels),
        create_node_with_labels("virtual-node-aci-linux", virtual_labels),
    ];

    assert!(has_virtual_nodes(&nodes));
}

// ============================================================================
// Combination tests
// ============================================================================

#[test]
fn test_aks_cluster_without_virtual_nodes() {
    let mut labels = BTreeMap::new();
    labels.insert("kubernetes.azure.com/agentpool".to_string(), "nodepool1".to_string());

    let nodes = vec![
        create_node_with_labels("aks-node-1", labels.clone()),
        create_node_with_labels("aks-node-2", labels),
    ];

    assert!(is_aks(&nodes));
    assert!(!has_virtual_nodes(&nodes));
}

#[test]
fn test_aks_cluster_with_virtual_nodes() {
    let mut aks_labels = BTreeMap::new();
    aks_labels.insert("kubernetes.azure.com/agentpool".to_string(), "nodepool1".to_string());

    let mut virtual_labels = BTreeMap::new();
    virtual_labels.insert("type".to_string(), "virtual-kubelet".to_string());
    virtual_labels.insert("kubernetes.azure.com/cluster".to_string(), "my-cluster".to_string());

    let nodes = vec![
        create_node_with_labels("aks-node", aks_labels),
        create_node_with_labels("virtual-node-aci-linux", virtual_labels),
    ];

    assert!(is_aks(&nodes));
    assert!(has_virtual_nodes(&nodes));
}
