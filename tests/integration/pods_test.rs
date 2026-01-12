//! Integration tests for Pod operations
//!
//! These tests require a real Kubernetes cluster.
//! Run with: cargo test integration::pods_test -- --ignored

use kubecontrol::client::create_client;
use kubecontrol::resources::{KubeResource, Listable, Tabular};
use k8s_openapi::api::core::v1::Pod;
use kube::Api;

/// Test listing pods in default namespace
#[tokio::test]
#[ignore]
async fn test_list_pods_default_namespace() {
    let client = create_client(None).await.expect("Should create client");
    let api = Pod::api(client, None);

    let pods = Pod::list_resources(&api, None, None).await;
    assert!(pods.is_ok(), "Should list pods in default namespace");
}

/// Test listing pods in kube-system namespace
#[tokio::test]
#[ignore]
async fn test_list_pods_kube_system() {
    let client = create_client(None).await.expect("Should create client");
    let api = Pod::api(client, Some("kube-system"));

    let pods = Pod::list_resources(&api, None, None).await;
    assert!(pods.is_ok(), "Should list pods in kube-system");

    let pods = pods.unwrap();
    // kube-system should have system pods
    assert!(!pods.is_empty(), "kube-system should have pods");
}

/// Test listing pods in all namespaces
#[tokio::test]
#[ignore]
async fn test_list_pods_all_namespaces() {
    let client = create_client(None).await.expect("Should create client");
    let api = Pod::api_all(client);

    let pods = Pod::list_resources(&api, None, None).await;
    assert!(pods.is_ok(), "Should list pods in all namespaces");

    let pods = pods.unwrap();
    assert!(!pods.is_empty(), "Should have at least one pod across all namespaces");
}

/// Test Pod KubeResource trait constants
#[test]
fn test_pod_resource_constants() {
    assert_eq!(Pod::KIND, "Pod");
    assert_eq!(Pod::GROUP, "");
    assert_eq!(Pod::VERSION, "v1");
    assert_eq!(Pod::PLURAL, "pods");
    assert!(Pod::NAMESPACED);
}

/// Test Pod Tabular trait
#[tokio::test]
#[ignore]
async fn test_pod_tabular_trait() {
    let client = create_client(None).await.expect("Should create client");
    let api = Pod::api(client, Some("kube-system"));

    let pods = Pod::list_resources(&api, None, None).await.expect("Should list pods");

    if let Some(pod) = pods.first() {
        let headers = Pod::headers();
        let row = pod.row();

        assert_eq!(headers.len(), row.len(), "Headers and row should have same length");
        assert!(!pod.name().is_empty(), "Pod should have a name");
    }
}

/// Test pod wide output
#[tokio::test]
#[ignore]
async fn test_pod_wide_output() {
    let client = create_client(None).await.expect("Should create client");
    let api = Pod::api(client, Some("kube-system"));

    let pods = Pod::list_resources(&api, None, None).await.expect("Should list pods");

    if let Some(pod) = pods.first() {
        let headers_wide = Pod::headers_wide();
        let row_wide = pod.row_wide();

        assert_eq!(headers_wide.len(), row_wide.len(), "Wide headers and row should match");
        assert!(headers_wide.len() > Pod::headers().len(), "Wide output should have more columns");
    }
}

/// Test filtering pods by label selector
#[tokio::test]
#[ignore]
async fn test_list_pods_with_label_selector() {
    let client = create_client(None).await.expect("Should create client");
    let api = Pod::api(client, Some("kube-system"));

    // Common label in kube-system
    let pods = Pod::list_resources(&api, Some("k8s-app"), None).await;
    assert!(pods.is_ok(), "Should filter pods by label");
}

/// Test filtering pods by field selector
#[tokio::test]
#[ignore]
async fn test_list_pods_with_field_selector() {
    let client = create_client(None).await.expect("Should create client");
    let api = Pod::api_all(client);

    // Filter for running pods
    let pods = Pod::list_resources(&api, None, Some("status.phase=Running")).await;
    assert!(pods.is_ok(), "Should filter pods by field selector");

    let pods = pods.unwrap();
    for pod in &pods {
        if let Some(status) = &pod.status {
            if let Some(phase) = &status.phase {
                assert_eq!(phase, "Running", "All filtered pods should be Running");
            }
        }
    }
}

/// Test getting a specific pod
#[tokio::test]
#[ignore]
async fn test_get_specific_pod() {
    let client = create_client(None).await.expect("Should create client");
    let api: Api<Pod> = Api::namespaced(client.clone(), "kube-system");

    // First, list pods to get a valid pod name
    let pods = api.list(&Default::default()).await.expect("Should list pods");

    if let Some(pod) = pods.items.first() {
        let pod_name = pod.name();
        let retrieved = api.get(pod_name).await;
        assert!(retrieved.is_ok(), "Should get specific pod");

        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.name(), pod_name, "Retrieved pod should have correct name");
    }
}

/// Test pod metadata
#[tokio::test]
#[ignore]
async fn test_pod_metadata() {
    let client = create_client(None).await.expect("Should create client");
    let api = Pod::api(client, Some("kube-system"));

    let pods = Pod::list_resources(&api, None, None).await.expect("Should list pods");

    if let Some(pod) = pods.first() {
        // Test metadata access
        let metadata = pod.metadata();
        assert!(metadata.name.is_some(), "Pod should have name in metadata");
        assert!(metadata.namespace.is_some(), "Pod should have namespace in metadata");

        // Test KubeResource trait methods
        assert!(!pod.name().is_empty(), "name() should return non-empty string");
        assert!(pod.namespace().is_some(), "namespace() should return Some for namespaced resource");
    }
}

/// Test pod age formatting
#[tokio::test]
#[ignore]
async fn test_pod_age() {
    let client = create_client(None).await.expect("Should create client");
    let api = Pod::api(client, Some("kube-system"));

    let pods = Pod::list_resources(&api, None, None).await.expect("Should list pods");

    if let Some(pod) = pods.first() {
        let age = pod.age();
        // Age should be a valid duration string (e.g., "5d", "12h", "30m", "10s")
        assert!(!age.is_empty(), "Age should not be empty");
        assert!(
            age.ends_with('d') || age.ends_with('h') || age.ends_with('m') || age.ends_with('s') || age == "<unknown>",
            "Age should be in correct format: {}",
            age
        );
    }
}

/// Test listing pods returns consistent results
#[tokio::test]
#[ignore]
async fn test_pods_list_consistency() {
    let client = create_client(None).await.expect("Should create client");
    let api = Pod::api(client, Some("kube-system"));

    let pods1 = Pod::list_resources(&api, None, None).await.expect("Should list pods");
    let pods2 = Pod::list_resources(&api, None, None).await.expect("Should list pods again");

    // While pods can change, the count should be similar for quick successive calls
    assert!(
        (pods1.len() as i32 - pods2.len() as i32).abs() <= 2,
        "Pod count should be relatively stable"
    );
}
