//! Integration tests for Kubernetes client operations
//!
//! These tests require a real Kubernetes cluster.
//! Run with: cargo test integration::client_test -- --ignored

use kubecontrol::client::{create_client, list_contexts, current_context};

/// Test creating a client with the default context
#[tokio::test]
#[ignore]
async fn test_create_client_default_context() {
    let client = create_client(None).await;
    assert!(client.is_ok(), "Should create client with default context");
}

/// Test creating a client with a specific context
/// Note: This test assumes the current context exists
#[tokio::test]
#[ignore]
async fn test_create_client_with_current_context() {
    let ctx_name = current_context().expect("Should have current context");
    let client = create_client(Some(&ctx_name)).await;
    assert!(client.is_ok(), "Should create client with specific context");
}

/// Test creating a client with a non-existent context
#[tokio::test]
#[ignore]
async fn test_create_client_nonexistent_context() {
    let client = create_client(Some("nonexistent-context-12345")).await;
    assert!(client.is_err(), "Should fail with non-existent context");
}

/// Test listing available contexts
#[test]
#[ignore]
fn test_list_contexts() {
    let contexts = list_contexts();
    assert!(contexts.is_ok(), "Should list contexts");

    let contexts = contexts.unwrap();
    assert!(!contexts.is_empty(), "Should have at least one context");

    // Verify context structure
    for ctx in &contexts {
        assert!(!ctx.name.is_empty(), "Context name should not be empty");
    }
}

/// Test that one context is marked as current
#[test]
#[ignore]
fn test_list_contexts_has_current() {
    let contexts = list_contexts().expect("Should list contexts");

    let current_count = contexts.iter().filter(|c| c.is_current).count();
    assert_eq!(current_count, 1, "Should have exactly one current context");
}

/// Test getting current context name
#[test]
#[ignore]
fn test_current_context() {
    let ctx = current_context();
    assert!(ctx.is_ok(), "Should get current context");

    let ctx_name = ctx.unwrap();
    assert!(!ctx_name.is_empty(), "Current context name should not be empty");
}

/// Test that current context is in the list
#[test]
#[ignore]
fn test_current_context_in_list() {
    let current = current_context().expect("Should get current context");
    let contexts = list_contexts().expect("Should list contexts");

    let found = contexts.iter().find(|c| c.name == current);
    assert!(found.is_some(), "Current context should be in context list");
    assert!(found.unwrap().is_current, "Current context should be marked as current");
}

/// Test context info structure
#[test]
#[ignore]
fn test_context_info_structure() {
    let contexts = list_contexts().expect("Should list contexts");

    for ctx in contexts {
        // Name is always required
        assert!(!ctx.name.is_empty(), "Context name should not be empty");

        // Cluster may or may not be set
        if let Some(cluster) = &ctx.cluster {
            assert!(!cluster.is_empty(), "If cluster is set, it should not be empty");
        }
    }
}

/// Test client can perform basic API call
#[tokio::test]
#[ignore]
async fn test_client_api_access() {
    use k8s_openapi::api::core::v1::Namespace;
    use kube::Api;

    let client = create_client(None).await.expect("Should create client");
    let namespaces: Api<Namespace> = Api::all(client);

    let ns_list = namespaces.list(&Default::default()).await;
    assert!(ns_list.is_ok(), "Should be able to list namespaces");

    let ns_list = ns_list.unwrap();
    assert!(!ns_list.items.is_empty(), "Should have at least one namespace");
}

/// Test client respects the context parameter
#[tokio::test]
#[ignore]
async fn test_client_context_parameter() {
    // This test verifies that the context parameter is being used
    // We use the current context to ensure it works
    let current = current_context().expect("Should have current context");

    let client = create_client(Some(&current)).await;
    assert!(client.is_ok(), "Should create client with explicit context");
}
