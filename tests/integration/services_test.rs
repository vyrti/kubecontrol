//! Integration tests for Service operations
//!
//! These tests require a real Kubernetes cluster.
//! Run with: cargo test integration::services_test -- --ignored

use kubecontrol::client::create_client;
use kubecontrol::resources::{KubeResource, Listable, Tabular};
use k8s_openapi::api::core::v1::Service;
use kube::Api;

/// Test listing services in default namespace
#[tokio::test]
#[ignore]
async fn test_list_services_default_namespace() {
    let client = create_client(None).await.expect("Should create client");
    let api = Service::api(client, None);

    let services = Service::list_resources(&api, None, None).await;
    assert!(services.is_ok(), "Should list services in default namespace");
}

/// Test listing services in kube-system namespace
#[tokio::test]
#[ignore]
async fn test_list_services_kube_system() {
    let client = create_client(None).await.expect("Should create client");
    let api = Service::api(client, Some("kube-system"));

    let services = Service::list_resources(&api, None, None).await;
    assert!(services.is_ok(), "Should list services in kube-system");

    let services = services.unwrap();
    // kube-system should have kube-dns service
    assert!(!services.is_empty(), "kube-system should have services");
}

/// Test listing services in all namespaces
#[tokio::test]
#[ignore]
async fn test_list_services_all_namespaces() {
    let client = create_client(None).await.expect("Should create client");
    let api = Service::api_all(client);

    let services = Service::list_resources(&api, None, None).await;
    assert!(services.is_ok(), "Should list services in all namespaces");

    let services = services.unwrap();
    assert!(!services.is_empty(), "Should have at least one service across all namespaces");
}

/// Test kubernetes default service exists
#[tokio::test]
#[ignore]
async fn test_kubernetes_service_exists() {
    let client = create_client(None).await.expect("Should create client");
    let api: Api<Service> = Api::namespaced(client, "default");

    let service = api.get("kubernetes").await;
    assert!(service.is_ok(), "kubernetes service should exist in default namespace");

    let service = service.unwrap();
    assert_eq!(service.name(), "kubernetes");
}

/// Test Service KubeResource trait constants
#[test]
fn test_service_resource_constants() {
    assert_eq!(Service::KIND, "Service");
    assert_eq!(Service::GROUP, "");
    assert_eq!(Service::VERSION, "v1");
    assert_eq!(Service::PLURAL, "services");
    assert!(Service::NAMESPACED);
}

/// Test Service Tabular trait
#[tokio::test]
#[ignore]
async fn test_service_tabular_trait() {
    let client = create_client(None).await.expect("Should create client");
    let api = Service::api(client, Some("default"));

    let services = Service::list_resources(&api, None, None).await.expect("Should list services");

    if let Some(service) = services.first() {
        let headers = Service::headers();
        let row = service.row();

        assert_eq!(headers.len(), row.len(), "Headers and row should have same length");
        assert!(!service.name().is_empty(), "Service should have a name");
    }
}

/// Test service wide output
#[tokio::test]
#[ignore]
async fn test_service_wide_output() {
    let client = create_client(None).await.expect("Should create client");
    let api = Service::api(client, Some("default"));

    let services = Service::list_resources(&api, None, None).await.expect("Should list services");

    if let Some(service) = services.first() {
        let headers_wide = Service::headers_wide();
        let row_wide = service.row_wide();

        assert_eq!(headers_wide.len(), row_wide.len(), "Wide headers and row should match");
    }
}

/// Test getting a specific service
#[tokio::test]
#[ignore]
async fn test_get_specific_service() {
    let client = create_client(None).await.expect("Should create client");
    let api: Api<Service> = Api::namespaced(client.clone(), "default");

    // kubernetes service should always exist
    let service = api.get("kubernetes").await;
    assert!(service.is_ok(), "Should get kubernetes service");

    let service = service.unwrap();
    assert_eq!(service.name(), "kubernetes", "Retrieved service should have correct name");
}

/// Test service metadata
#[tokio::test]
#[ignore]
async fn test_service_metadata() {
    let client = create_client(None).await.expect("Should create client");
    let api = Service::api(client, Some("default"));

    let services = Service::list_resources(&api, None, None).await.expect("Should list services");

    if let Some(service) = services.first() {
        // Test metadata access
        let metadata = service.metadata();
        assert!(metadata.name.is_some(), "Service should have name in metadata");
        assert!(metadata.namespace.is_some(), "Service should have namespace in metadata");

        // Test KubeResource trait methods
        assert!(!service.name().is_empty(), "name() should return non-empty string");
        assert!(service.namespace().is_some(), "namespace() should return Some for namespaced resource");
    }
}

/// Test service type information
#[tokio::test]
#[ignore]
async fn test_service_type() {
    let client = create_client(None).await.expect("Should create client");
    let api: Api<Service> = Api::namespaced(client, "default");

    let service = api.get("kubernetes").await.expect("Should get kubernetes service");

    if let Some(spec) = &service.spec {
        let service_type = spec.type_.as_deref().unwrap_or("ClusterIP");
        assert!(
            ["ClusterIP", "NodePort", "LoadBalancer", "ExternalName"].contains(&service_type),
            "Service type should be valid: {}",
            service_type
        );
    }
}

/// Test service ports information
#[tokio::test]
#[ignore]
async fn test_service_ports() {
    let client = create_client(None).await.expect("Should create client");
    let api: Api<Service> = Api::namespaced(client, "default");

    let service = api.get("kubernetes").await.expect("Should get kubernetes service");

    if let Some(spec) = &service.spec {
        if let Some(ports) = &spec.ports {
            assert!(!ports.is_empty(), "kubernetes service should have ports");
            for port in ports {
                assert!(port.port > 0, "Port should be positive");
            }
        }
    }
}

/// Test service age formatting
#[tokio::test]
#[ignore]
async fn test_service_age() {
    let client = create_client(None).await.expect("Should create client");
    let api = Service::api(client, Some("default"));

    let services = Service::list_resources(&api, None, None).await.expect("Should list services");

    if let Some(service) = services.first() {
        let age = service.age();
        assert!(!age.is_empty(), "Age should not be empty");
    }
}
