//! Integration tests for Node operations
//!
//! These tests require a real Kubernetes cluster.
//! Run with: cargo test integration::nodes_test -- --ignored

use kubecontrol::client::create_client;
use kubecontrol::resources::{KubeResource, Listable, Tabular};
use k8s_openapi::api::core::v1::Node;
use kube::Api;

/// Test listing nodes
#[tokio::test]
#[ignore]
async fn test_list_nodes() {
    let client = create_client(None).await.expect("Should create client");
    let api = Node::api_all(client);

    let nodes = Node::list_resources(&api, None, None).await;
    assert!(nodes.is_ok(), "Should list nodes");

    let nodes = nodes.unwrap();
    // Every cluster should have at least one node
    assert!(!nodes.is_empty(), "Cluster should have at least one node");
}

/// Test Node KubeResource trait constants
#[test]
fn test_node_resource_constants() {
    assert_eq!(Node::KIND, "Node");
    assert_eq!(Node::GROUP, "");
    assert_eq!(Node::VERSION, "v1");
    assert_eq!(Node::PLURAL, "nodes");
    assert!(!Node::NAMESPACED); // Nodes are cluster-scoped
    assert!(Node::ALIASES.contains(&"no"));
}

/// Test Node is not namespaced
#[tokio::test]
#[ignore]
async fn test_node_cluster_scoped() {
    let client = create_client(None).await.expect("Should create client");
    let api = Node::api_all(client);

    let nodes = Node::list_resources(&api, None, None).await.expect("Should list nodes");

    if let Some(node) = nodes.first() {
        // Nodes should not have a namespace
        assert!(node.namespace().is_none(), "Node should not have namespace");
    }
}

/// Test Node Tabular trait
#[tokio::test]
#[ignore]
async fn test_node_tabular_trait() {
    let client = create_client(None).await.expect("Should create client");
    let api = Node::api_all(client);

    let nodes = Node::list_resources(&api, None, None).await.expect("Should list nodes");

    if let Some(node) = nodes.first() {
        let headers = Node::headers();
        let row = node.row();

        assert_eq!(headers.len(), row.len(), "Headers and row should have same length");
        assert!(!node.name().is_empty(), "Node should have a name");
    }
}

/// Test node wide output
#[tokio::test]
#[ignore]
async fn test_node_wide_output() {
    let client = create_client(None).await.expect("Should create client");
    let api = Node::api_all(client);

    let nodes = Node::list_resources(&api, None, None).await.expect("Should list nodes");

    if let Some(node) = nodes.first() {
        let headers_wide = Node::headers_wide();
        let row_wide = node.row_wide();

        assert_eq!(headers_wide.len(), row_wide.len(), "Wide headers and row should match");
    }
}

/// Test getting a specific node
#[tokio::test]
#[ignore]
async fn test_get_specific_node() {
    let client = create_client(None).await.expect("Should create client");
    let api: Api<Node> = Api::all(client.clone());

    // First, list nodes to get a valid node name
    let nodes = api.list(&Default::default()).await.expect("Should list nodes");

    if let Some(node) = nodes.items.first() {
        let node_name = node.name();
        let retrieved = api.get(node_name).await;
        assert!(retrieved.is_ok(), "Should get specific node");

        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.name(), node_name, "Retrieved node should have correct name");
    }
}

/// Test node metadata
#[tokio::test]
#[ignore]
async fn test_node_metadata() {
    let client = create_client(None).await.expect("Should create client");
    let api = Node::api_all(client);

    let nodes = Node::list_resources(&api, None, None).await.expect("Should list nodes");

    if let Some(node) = nodes.first() {
        // Test metadata access
        let metadata = node.metadata();
        assert!(metadata.name.is_some(), "Node should have name in metadata");
        // Nodes don't have namespace
        assert!(metadata.namespace.is_none(), "Node should not have namespace");

        // Test KubeResource trait methods
        assert!(!node.name().is_empty(), "name() should return non-empty string");
    }
}

/// Test node status conditions
#[tokio::test]
#[ignore]
async fn test_node_conditions() {
    let client = create_client(None).await.expect("Should create client");
    let api: Api<Node> = Api::all(client);

    let nodes = api.list(&Default::default()).await.expect("Should list nodes");

    if let Some(node) = nodes.items.first() {
        if let Some(status) = &node.status {
            if let Some(conditions) = &status.conditions {
                assert!(!conditions.is_empty(), "Node should have conditions");

                // Check for Ready condition
                let ready_condition = conditions.iter().find(|c| c.type_ == "Ready");
                assert!(ready_condition.is_some(), "Node should have Ready condition");

                if let Some(ready) = ready_condition {
                    assert!(
                        ready.status == "True" || ready.status == "False" || ready.status == "Unknown",
                        "Ready status should be True, False, or Unknown"
                    );
                }
            }
        }
    }
}

/// Test node addresses
#[tokio::test]
#[ignore]
async fn test_node_addresses() {
    let client = create_client(None).await.expect("Should create client");
    let api: Api<Node> = Api::all(client);

    let nodes = api.list(&Default::default()).await.expect("Should list nodes");

    if let Some(node) = nodes.items.first() {
        if let Some(status) = &node.status {
            if let Some(addresses) = &status.addresses {
                assert!(!addresses.is_empty(), "Node should have addresses");

                for addr in addresses {
                    assert!(!addr.address.is_empty(), "Address should not be empty");
                    assert!(
                        ["Hostname", "InternalIP", "ExternalIP", "InternalDNS", "ExternalDNS"]
                            .contains(&addr.type_.as_str()),
                        "Address type should be valid: {}",
                        addr.type_
                    );
                }
            }
        }
    }
}

/// Test node age formatting
#[tokio::test]
#[ignore]
async fn test_node_age() {
    let client = create_client(None).await.expect("Should create client");
    let api = Node::api_all(client);

    let nodes = Node::list_resources(&api, None, None).await.expect("Should list nodes");

    if let Some(node) = nodes.first() {
        let age = node.age();
        assert!(!age.is_empty(), "Age should not be empty");
        assert!(
            age.ends_with('d') || age.ends_with('h') || age.ends_with('m') || age.ends_with('s') || age == "<unknown>",
            "Age should be in correct format: {}",
            age
        );
    }
}

/// Test filtering nodes by label selector
#[tokio::test]
#[ignore]
async fn test_list_nodes_with_label_selector() {
    let client = create_client(None).await.expect("Should create client");
    let api = Node::api_all(client);

    // kubernetes.io/os label should be present on all nodes
    let nodes = Node::list_resources(&api, Some("kubernetes.io/os"), None).await;
    assert!(nodes.is_ok(), "Should filter nodes by label");
}

/// Test node system info
#[tokio::test]
#[ignore]
async fn test_node_system_info() {
    let client = create_client(None).await.expect("Should create client");
    let api: Api<Node> = Api::all(client);

    let nodes = api.list(&Default::default()).await.expect("Should list nodes");

    if let Some(node) = nodes.items.first() {
        if let Some(status) = &node.status {
            if let Some(node_info) = &status.node_info {
                // Check various system info fields
                assert!(!node_info.kubelet_version.is_empty(), "Kubelet version should not be empty");
                assert!(!node_info.os_image.is_empty(), "OS image should not be empty");
                assert!(!node_info.architecture.is_empty(), "Architecture should not be empty");
            }
        }
    }
}
