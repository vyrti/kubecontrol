//! Web server implementation using axum

use crate::error::Result;
use crate::web::{assets::serve_assets, handlers, websocket};
use axum::{
    routing::{delete, get, post, put},
    Router,
};
use std::net::SocketAddr;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

/// Start the web UI server
pub async fn start_server(port: u16, context: Option<String>, namespace: Option<String>, open_browser: bool) -> Result<()> {
    // Create shared state
    let state = handlers::AppState::new(context, namespace).await?;

    // Build CORS layer
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    // Build router
    let app = Router::new()
        // === Pulse (cluster overview) ===
        .route("/api/pulse", get(handlers::get_pulse))

        // === Pod endpoints ===
        .route("/api/pods", get(handlers::list_pods))
        .route("/api/pods/{ns}/{name}", get(handlers::get_pod))
        .route("/api/pods/{ns}/{name}", delete(handlers::delete_pod))
        .route("/api/pods/{ns}/{name}/logs", get(handlers::get_pod_logs))

        // === Deployment endpoints ===
        .route("/api/deployments", get(handlers::list_deployments))
        .route("/api/deployments/{ns}/{name}", get(handlers::get_deployment))
        .route("/api/deployments/{ns}/{name}", delete(handlers::delete_deployment))
        .route("/api/deployments/{ns}/{name}/scale", put(handlers::scale_deployment))
        .route("/api/deployments/{ns}/{name}/restart", post(handlers::restart_deployment))

        // === Service endpoints ===
        .route("/api/services", get(handlers::list_services))
        .route("/api/services/{ns}/{name}", get(handlers::get_service))
        .route("/api/services/{ns}/{name}", delete(handlers::delete_service))

        // === ConfigMap endpoints ===
        .route("/api/configmaps", get(handlers::list_configmaps))
        .route("/api/configmaps/{ns}/{name}", get(handlers::get_configmap))
        .route("/api/configmaps/{ns}/{name}", delete(handlers::delete_configmap))

        // === Secret endpoints ===
        .route("/api/secrets", get(handlers::list_secrets))
        .route("/api/secrets/{ns}/{name}", get(handlers::get_secret))
        .route("/api/secrets/{ns}/{name}", delete(handlers::delete_secret))

        // === ReplicaSet endpoints ===
        .route("/api/replicasets", get(handlers::list_replicasets))
        .route("/api/replicasets/{ns}/{name}", delete(handlers::delete_replicaset))

        // === StatefulSet endpoints ===
        .route("/api/statefulsets", get(handlers::list_statefulsets))
        .route("/api/statefulsets/{ns}/{name}", delete(handlers::delete_statefulset))
        .route("/api/statefulsets/{ns}/{name}/scale", put(handlers::scale_statefulset))
        .route("/api/statefulsets/{ns}/{name}/restart", post(handlers::restart_statefulset))

        // === DaemonSet endpoints ===
        .route("/api/daemonsets", get(handlers::list_daemonsets))
        .route("/api/daemonsets/{ns}/{name}", delete(handlers::delete_daemonset))
        .route("/api/daemonsets/{ns}/{name}/restart", post(handlers::restart_daemonset))

        // === Namespace endpoints ===
        .route("/api/namespaces", get(handlers::list_namespaces))
        .route("/api/namespaces/{name}", get(handlers::get_namespace))
        .route("/api/namespaces/{name}", delete(handlers::delete_namespace))

        // === Node endpoints ===
        .route("/api/nodes", get(handlers::list_nodes))
        .route("/api/nodes/{name}", get(handlers::get_node))
        .route("/api/nodes/{name}/cordon", post(handlers::cordon_node))
        .route("/api/nodes/{name}/uncordon", post(handlers::uncordon_node))

        // === Events endpoints ===
        .route("/api/events", get(handlers::list_events))

        // === Search endpoint ===
        .route("/api/search", get(handlers::search_resources))

        // === Health scanner endpoint ===
        .route("/api/health/scan", get(handlers::scan_health))

        // === Debug endpoints ===
        .route("/api/debug/dns", get(handlers::debug_dns))
        .route("/api/debug/network", get(handlers::debug_network))
        .route("/api/debug/pod/{ns}/{name}", get(handlers::debug_pod))
        .route("/api/debug/node/{name}", get(handlers::debug_node))
        .route("/api/debug/deployment/{ns}/{name}", get(handlers::debug_deployment))
        .route("/api/debug/service/{ns}/{name}", get(handlers::debug_service))
        .route("/api/debug/storage", get(handlers::debug_storage))
        .route("/api/debug/security", get(handlers::debug_security))
        .route("/api/debug/resources", get(handlers::debug_resources))
        .route("/api/debug/events", get(handlers::debug_events))
        .route("/api/debug/ingress", get(handlers::debug_ingress))
        .route("/api/debug/cluster", get(handlers::debug_cluster))
        .route("/api/debug/all", get(handlers::debug_all))

        // === Context endpoints ===
        .route("/api/contexts", get(handlers::list_contexts_handler))
        .route("/api/context", get(handlers::get_current_context))

        // === Apply endpoint ===
        .route("/api/apply", post(handlers::apply_yaml))

        // === WebSocket endpoints ===
        .route("/api/ws/logs/{ns}/{name}", get(websocket::ws_logs_handler))
        .route("/api/ws/exec/{ns}/{name}", get(websocket::ws_exec_handler))

        // Serve embedded frontend
        .fallback(serve_assets)
        .layer(cors)
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let url = format!("http://{}", addr);

    println!("Dashboard running at {}", url);

    // Open browser if requested
    if open_browser {
        if let Err(e) = open::that(&url) {
            tracing::warn!("Failed to open browser: {}", e);
        }
    }

    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!("Web server listening on {}", addr);

    axum::serve(listener, app)
        .await
        .map_err(|e| crate::error::KcError::Config(format!("Server error: {}", e)))?;

    Ok(())
}
