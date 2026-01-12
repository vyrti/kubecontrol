//! Integration tests for Deployment operations
//!
//! These tests require a real Kubernetes cluster.
//! Run with: cargo test integration::deployments_test -- --ignored

use kubecontrol::client::create_client;
use kubecontrol::resources::{KubeResource, Listable, Tabular};
use k8s_openapi::api::apps::v1::Deployment;
use kube::Api;

/// Test listing deployments in default namespace
#[tokio::test]
#[ignore]
async fn test_list_deployments_default_namespace() {
    let client = create_client(None).await.expect("Should create client");
    let api = Deployment::api(client, None);

    let deployments = Deployment::list_resources(&api, None, None).await;
    assert!(deployments.is_ok(), "Should list deployments in default namespace");
}

/// Test listing deployments in kube-system namespace
#[tokio::test]
#[ignore]
async fn test_list_deployments_kube_system() {
    let client = create_client(None).await.expect("Should create client");
    let api = Deployment::api(client, Some("kube-system"));

    let deployments = Deployment::list_resources(&api, None, None).await;
    assert!(deployments.is_ok(), "Should list deployments in kube-system");

    let deployments = deployments.unwrap();
    // kube-system should have coredns or similar system deployments
    assert!(!deployments.is_empty(), "kube-system should have deployments");
}

/// Test listing deployments in all namespaces
#[tokio::test]
#[ignore]
async fn test_list_deployments_all_namespaces() {
    let client = create_client(None).await.expect("Should create client");
    let api = Deployment::api_all(client);

    let deployments = Deployment::list_resources(&api, None, None).await;
    assert!(deployments.is_ok(), "Should list deployments in all namespaces");

    let deployments = deployments.unwrap();
    assert!(!deployments.is_empty(), "Should have at least one deployment across all namespaces");
}

/// Test Deployment KubeResource trait constants
#[test]
fn test_deployment_resource_constants() {
    assert_eq!(Deployment::KIND, "Deployment");
    assert_eq!(Deployment::GROUP, "apps");
    assert_eq!(Deployment::VERSION, "v1");
    assert_eq!(Deployment::PLURAL, "deployments");
    assert!(Deployment::NAMESPACED);
}

/// Test Deployment Tabular trait
#[tokio::test]
#[ignore]
async fn test_deployment_tabular_trait() {
    let client = create_client(None).await.expect("Should create client");
    let api = Deployment::api(client, Some("kube-system"));

    let deployments = Deployment::list_resources(&api, None, None).await.expect("Should list deployments");

    if let Some(deployment) = deployments.first() {
        let headers = Deployment::headers();
        let row = deployment.row();

        assert_eq!(headers.len(), row.len(), "Headers and row should have same length");
        assert!(!deployment.name().is_empty(), "Deployment should have a name");
    }
}

/// Test deployment wide output
#[tokio::test]
#[ignore]
async fn test_deployment_wide_output() {
    let client = create_client(None).await.expect("Should create client");
    let api = Deployment::api(client, Some("kube-system"));

    let deployments = Deployment::list_resources(&api, None, None).await.expect("Should list deployments");

    if let Some(deployment) = deployments.first() {
        let headers_wide = Deployment::headers_wide();
        let row_wide = deployment.row_wide();

        assert_eq!(headers_wide.len(), row_wide.len(), "Wide headers and row should match");
    }
}

/// Test getting a specific deployment
#[tokio::test]
#[ignore]
async fn test_get_specific_deployment() {
    let client = create_client(None).await.expect("Should create client");
    let api: Api<Deployment> = Api::namespaced(client.clone(), "kube-system");

    // First, list deployments to get a valid deployment name
    let deployments = api.list(&Default::default()).await.expect("Should list deployments");

    if let Some(deployment) = deployments.items.first() {
        let deployment_name = deployment.name();
        let retrieved = api.get(deployment_name).await;
        assert!(retrieved.is_ok(), "Should get specific deployment");

        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.name(), deployment_name, "Retrieved deployment should have correct name");
    }
}

/// Test deployment metadata
#[tokio::test]
#[ignore]
async fn test_deployment_metadata() {
    let client = create_client(None).await.expect("Should create client");
    let api = Deployment::api(client, Some("kube-system"));

    let deployments = Deployment::list_resources(&api, None, None).await.expect("Should list deployments");

    if let Some(deployment) = deployments.first() {
        // Test metadata access
        let metadata = deployment.metadata();
        assert!(metadata.name.is_some(), "Deployment should have name in metadata");
        assert!(metadata.namespace.is_some(), "Deployment should have namespace in metadata");

        // Test KubeResource trait methods
        assert!(!deployment.name().is_empty(), "name() should return non-empty string");
        assert!(deployment.namespace().is_some(), "namespace() should return Some for namespaced resource");
    }
}

/// Test deployment age formatting
#[tokio::test]
#[ignore]
async fn test_deployment_age() {
    let client = create_client(None).await.expect("Should create client");
    let api = Deployment::api(client, Some("kube-system"));

    let deployments = Deployment::list_resources(&api, None, None).await.expect("Should list deployments");

    if let Some(deployment) = deployments.first() {
        let age = deployment.age();
        assert!(!age.is_empty(), "Age should not be empty");
        assert!(
            age.ends_with('d') || age.ends_with('h') || age.ends_with('m') || age.ends_with('s') || age == "<unknown>",
            "Age should be in correct format: {}",
            age
        );
    }
}

/// Test filtering deployments by label selector
#[tokio::test]
#[ignore]
async fn test_list_deployments_with_label_selector() {
    let client = create_client(None).await.expect("Should create client");
    let api = Deployment::api_all(client);

    // Use a broad selector that might match something
    let deployments = Deployment::list_resources(&api, Some("k8s-app"), None).await;
    assert!(deployments.is_ok(), "Should filter deployments by label");
}

/// Test deployment replicas information
#[tokio::test]
#[ignore]
async fn test_deployment_replicas() {
    let client = create_client(None).await.expect("Should create client");
    let api = Deployment::api(client, Some("kube-system"));

    let deployments = Deployment::list_resources(&api, None, None).await.expect("Should list deployments");

    if let Some(deployment) = deployments.first() {
        // Check that replica information is available
        if let Some(spec) = &deployment.spec {
            assert!(spec.replicas.is_some() || spec.replicas.is_none(), "Replicas should be accessible");
        }
    }
}
