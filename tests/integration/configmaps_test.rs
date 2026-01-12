//! Integration tests for ConfigMap operations
//!
//! These tests require a real Kubernetes cluster.
//! Run with: cargo test integration::configmaps_test -- --ignored

use kubecontrol::client::create_client;
use kubecontrol::resources::{KubeResource, Listable, Tabular};
use k8s_openapi::api::core::v1::ConfigMap;
use kube::Api;

/// Test listing configmaps in default namespace
#[tokio::test]
#[ignore]
async fn test_list_configmaps_default_namespace() {
    let client = create_client(None).await.expect("Should create client");
    let api = ConfigMap::api(client, None);

    let configmaps = ConfigMap::list_resources(&api, None, None).await;
    assert!(configmaps.is_ok(), "Should list configmaps in default namespace");
}

/// Test listing configmaps in kube-system namespace
#[tokio::test]
#[ignore]
async fn test_list_configmaps_kube_system() {
    let client = create_client(None).await.expect("Should create client");
    let api = ConfigMap::api(client, Some("kube-system"));

    let configmaps = ConfigMap::list_resources(&api, None, None).await;
    assert!(configmaps.is_ok(), "Should list configmaps in kube-system");

    let configmaps = configmaps.unwrap();
    // kube-system should have configmaps (coredns config, etc.)
    assert!(!configmaps.is_empty(), "kube-system should have configmaps");
}

/// Test listing configmaps in all namespaces
#[tokio::test]
#[ignore]
async fn test_list_configmaps_all_namespaces() {
    let client = create_client(None).await.expect("Should create client");
    let api = ConfigMap::api_all(client);

    let configmaps = ConfigMap::list_resources(&api, None, None).await;
    assert!(configmaps.is_ok(), "Should list configmaps in all namespaces");

    let configmaps = configmaps.unwrap();
    assert!(!configmaps.is_empty(), "Should have at least one configmap across all namespaces");
}

/// Test ConfigMap KubeResource trait constants
#[test]
fn test_configmap_resource_constants() {
    assert_eq!(ConfigMap::KIND, "ConfigMap");
    assert_eq!(ConfigMap::GROUP, "");
    assert_eq!(ConfigMap::VERSION, "v1");
    assert_eq!(ConfigMap::PLURAL, "configmaps");
    assert!(ConfigMap::NAMESPACED);
    assert!(ConfigMap::ALIASES.contains(&"cm"));
}

/// Test ConfigMap Tabular trait
#[tokio::test]
#[ignore]
async fn test_configmap_tabular_trait() {
    let client = create_client(None).await.expect("Should create client");
    let api = ConfigMap::api(client, Some("kube-system"));

    let configmaps = ConfigMap::list_resources(&api, None, None).await.expect("Should list configmaps");

    if let Some(configmap) = configmaps.first() {
        let headers = ConfigMap::headers();
        let row = configmap.row();

        assert_eq!(headers.len(), row.len(), "Headers and row should have same length");
        assert!(!configmap.name().is_empty(), "ConfigMap should have a name");
    }
}

/// Test getting a specific configmap
#[tokio::test]
#[ignore]
async fn test_get_specific_configmap() {
    let client = create_client(None).await.expect("Should create client");
    let api: Api<ConfigMap> = Api::namespaced(client.clone(), "kube-system");

    // First, list configmaps to get a valid configmap name
    let configmaps = api.list(&Default::default()).await.expect("Should list configmaps");

    if let Some(configmap) = configmaps.items.first() {
        let configmap_name = configmap.name();
        let retrieved = api.get(configmap_name).await;
        assert!(retrieved.is_ok(), "Should get specific configmap");

        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.name(), configmap_name, "Retrieved configmap should have correct name");
    }
}

/// Test configmap metadata
#[tokio::test]
#[ignore]
async fn test_configmap_metadata() {
    let client = create_client(None).await.expect("Should create client");
    let api = ConfigMap::api(client, Some("kube-system"));

    let configmaps = ConfigMap::list_resources(&api, None, None).await.expect("Should list configmaps");

    if let Some(configmap) = configmaps.first() {
        // Test metadata access
        let metadata = configmap.metadata();
        assert!(metadata.name.is_some(), "ConfigMap should have name in metadata");
        assert!(metadata.namespace.is_some(), "ConfigMap should have namespace in metadata");

        // Test KubeResource trait methods
        assert!(!configmap.name().is_empty(), "name() should return non-empty string");
        assert!(configmap.namespace().is_some(), "namespace() should return Some for namespaced resource");
    }
}

/// Test configmap data access
#[tokio::test]
#[ignore]
async fn test_configmap_data() {
    let client = create_client(None).await.expect("Should create client");
    let api: Api<ConfigMap> = Api::namespaced(client, "kube-system");

    let configmaps = api.list(&Default::default()).await.expect("Should list configmaps");

    // Find a configmap with data
    let configmap_with_data = configmaps.items.iter().find(|cm| cm.data.is_some());

    if let Some(configmap) = configmap_with_data {
        let data = configmap.data.as_ref().unwrap();
        assert!(!data.is_empty(), "ConfigMap should have some data");

        for (key, _value) in data {
            assert!(!key.is_empty(), "ConfigMap data key should not be empty");
        }
    }
}

/// Test configmap age formatting
#[tokio::test]
#[ignore]
async fn test_configmap_age() {
    let client = create_client(None).await.expect("Should create client");
    let api = ConfigMap::api(client, Some("kube-system"));

    let configmaps = ConfigMap::list_resources(&api, None, None).await.expect("Should list configmaps");

    if let Some(configmap) = configmaps.first() {
        let age = configmap.age();
        assert!(!age.is_empty(), "Age should not be empty");
        assert!(
            age.ends_with('d') || age.ends_with('h') || age.ends_with('m') || age.ends_with('s') || age == "<unknown>",
            "Age should be in correct format: {}",
            age
        );
    }
}

/// Test filtering configmaps by label selector
#[tokio::test]
#[ignore]
async fn test_list_configmaps_with_label_selector() {
    let client = create_client(None).await.expect("Should create client");
    let api = ConfigMap::api_all(client);

    // Use a selector - may or may not match
    let configmaps = ConfigMap::list_resources(&api, Some("component"), None).await;
    assert!(configmaps.is_ok(), "Should handle label selector filter");
}

/// Test configmap wide output
#[tokio::test]
#[ignore]
async fn test_configmap_wide_output() {
    let client = create_client(None).await.expect("Should create client");
    let api = ConfigMap::api(client, Some("kube-system"));

    let configmaps = ConfigMap::list_resources(&api, None, None).await.expect("Should list configmaps");

    if let Some(configmap) = configmaps.first() {
        let headers_wide = ConfigMap::headers_wide();
        let row_wide = configmap.row_wide();

        assert_eq!(headers_wide.len(), row_wide.len(), "Wide headers and row should match");
    }
}
