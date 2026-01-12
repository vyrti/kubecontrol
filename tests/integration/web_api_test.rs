//! Integration tests for Web API endpoints
//!
//! These tests require a real Kubernetes cluster and start a test server.
//! Run with: cargo test integration::web_api_test -- --ignored

use kubecontrol::web::handlers::AppState;
use axum::{
    body::Body,
    http::{Request, StatusCode},
    Router,
    routing::get,
};
use tower::ServiceExt;

/// Helper to create a test app state
async fn create_test_state() -> AppState {
    AppState::new(None, None).await.expect("Should create app state")
}

/// Test GET /api/pulse endpoint returns cluster info
#[tokio::test]
#[ignore]
async fn test_pulse_endpoint() {
    let state = create_test_state().await;
    let app = Router::new()
        .route("/api/pulse", get(kubecontrol::web::handlers::get_pulse))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/pulse")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Check expected fields - PulseResponse structure
    assert!(json.get("context").is_some(), "Should have context field");
    assert!(json.get("resource_counts").is_some(), "Should have resource_counts field");

    // resource_counts contains pods, nodes, etc.
    let resource_counts = json.get("resource_counts").unwrap();
    assert!(resource_counts.get("pods").is_some(), "Should have pods in resource_counts");
    assert!(resource_counts.get("nodes").is_some(), "Should have nodes in resource_counts");
}

/// Test GET /api/pods endpoint returns pod list
#[tokio::test]
#[ignore]
async fn test_list_pods_endpoint() {
    let state = create_test_state().await;
    let app = Router::new()
        .route("/api/pods", get(kubecontrol::web::handlers::list_pods))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/pods")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json.is_array(), "Response should be an array");
}

/// Test GET /api/pods with namespace query parameter
#[tokio::test]
#[ignore]
async fn test_list_pods_with_namespace() {
    let state = create_test_state().await;
    let app = Router::new()
        .route("/api/pods", get(kubecontrol::web::handlers::list_pods))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/pods?namespace=kube-system")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json.is_array(), "Response should be an array");

    // All pods should be in kube-system
    if let Some(pods) = json.as_array() {
        for pod in pods {
            let ns = pod["namespace"].as_str();
            assert_eq!(ns, Some("kube-system"), "All pods should be in kube-system");
        }
    }
}

/// Test GET /api/deployments endpoint
#[tokio::test]
#[ignore]
async fn test_list_deployments_endpoint() {
    let state = create_test_state().await;
    let app = Router::new()
        .route("/api/deployments", get(kubecontrol::web::handlers::list_deployments))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/deployments")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json.is_array(), "Response should be an array");
}

/// Test GET /api/services endpoint
#[tokio::test]
#[ignore]
async fn test_list_services_endpoint() {
    let state = create_test_state().await;
    let app = Router::new()
        .route("/api/services", get(kubecontrol::web::handlers::list_services))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/services")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json.is_array(), "Response should be an array");
}

/// Test GET /api/configmaps endpoint
#[tokio::test]
#[ignore]
async fn test_list_configmaps_endpoint() {
    let state = create_test_state().await;
    let app = Router::new()
        .route("/api/configmaps", get(kubecontrol::web::handlers::list_configmaps))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/configmaps")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json.is_array(), "Response should be an array");
}

/// Test GET /api/nodes endpoint
#[tokio::test]
#[ignore]
async fn test_list_nodes_endpoint() {
    let state = create_test_state().await;
    let app = Router::new()
        .route("/api/nodes", get(kubecontrol::web::handlers::list_nodes))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/nodes")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json.is_array(), "Response should be an array");
    // Should have at least one node
    assert!(!json.as_array().unwrap().is_empty(), "Should have at least one node");
}

/// Test GET /api/namespaces endpoint
#[tokio::test]
#[ignore]
async fn test_list_namespaces_endpoint() {
    let state = create_test_state().await;
    let app = Router::new()
        .route("/api/namespaces", get(kubecontrol::web::handlers::list_namespaces))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/namespaces")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json.is_array(), "Response should be an array");
    // Should have at least default, kube-system, kube-public namespaces
    assert!(json.as_array().unwrap().len() >= 3, "Should have at least 3 namespaces");
}

/// Test GET /api/events endpoint
#[tokio::test]
#[ignore]
async fn test_list_events_endpoint() {
    let state = create_test_state().await;
    let app = Router::new()
        .route("/api/events", get(kubecontrol::web::handlers::list_events))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/events")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json.is_array(), "Response should be an array");
}

/// Test GET /api/search endpoint
#[tokio::test]
#[ignore]
async fn test_search_endpoint() {
    let state = create_test_state().await;
    let app = Router::new()
        .route("/api/search", get(kubecontrol::web::handlers::search_resources))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/search?q=kube")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Search results is an array of SearchResult items
    assert!(json.is_array(), "Response should be an array");

    // Should find resources with "kube" in the name (e.g., kube-system resources)
    let results = json.as_array().unwrap();
    // Results may be empty or have items depending on cluster state
    for result in results {
        assert!(result.get("resource_type").is_some(), "Each result should have resource_type");
        assert!(result.get("name").is_some(), "Each result should have name");
    }
}

/// Test GET /api/health/scan endpoint
#[tokio::test]
#[ignore]
async fn test_health_scan_endpoint() {
    let state = create_test_state().await;
    let app = Router::new()
        .route("/api/health/scan", get(kubecontrol::web::handlers::scan_health))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/health/scan")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Health scan should return an object with issues array
    assert!(json.is_object() || json.is_array(), "Response should be an object or array");
}

/// Test GET /api/contexts endpoint
#[tokio::test]
#[ignore]
async fn test_list_contexts_endpoint() {
    let state = create_test_state().await;
    let app = Router::new()
        .route("/api/contexts", get(kubecontrol::web::handlers::list_contexts_handler))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/contexts")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert!(json.is_array(), "Response should be an array");
    // Should have at least one context
    assert!(!json.as_array().unwrap().is_empty(), "Should have at least one context");
}

/// Test GET /api/context endpoint
#[tokio::test]
#[ignore]
async fn test_get_current_context_endpoint() {
    let state = create_test_state().await;
    let app = Router::new()
        .route("/api/context", get(kubecontrol::web::handlers::get_current_context))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/context")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);

    let body = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();

    // Should return context name
    assert!(json.is_string() || json.is_object(), "Response should be a string or object");
}

/// Test GET /api/statefulsets endpoint
#[tokio::test]
#[ignore]
async fn test_list_statefulsets_endpoint() {
    let state = create_test_state().await;
    let app = Router::new()
        .route("/api/statefulsets", get(kubecontrol::web::handlers::list_statefulsets))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/statefulsets")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

/// Test GET /api/daemonsets endpoint
#[tokio::test]
#[ignore]
async fn test_list_daemonsets_endpoint() {
    let state = create_test_state().await;
    let app = Router::new()
        .route("/api/daemonsets", get(kubecontrol::web::handlers::list_daemonsets))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/daemonsets")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

/// Test GET /api/replicasets endpoint
#[tokio::test]
#[ignore]
async fn test_list_replicasets_endpoint() {
    let state = create_test_state().await;
    let app = Router::new()
        .route("/api/replicasets", get(kubecontrol::web::handlers::list_replicasets))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/replicasets")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

/// Test GET /api/secrets endpoint
#[tokio::test]
#[ignore]
async fn test_list_secrets_endpoint() {
    let state = create_test_state().await;
    let app = Router::new()
        .route("/api/secrets", get(kubecontrol::web::handlers::list_secrets))
        .with_state(state);

    let response = app
        .oneshot(
            Request::builder()
                .uri("/api/secrets")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}
