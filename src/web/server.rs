//! Web server implementation using axum

use crate::error::Result;
use crate::web::{assets::serve_assets, handlers, websocket};
use axum::{
    routing::get,
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
        // API endpoints
        .route("/api/pods", get(handlers::list_pods))
        .route("/api/pods/{ns}/{name}", get(handlers::get_pod))
        .route("/api/pods/{ns}/{name}/logs", get(handlers::get_pod_logs))
        .route("/api/deployments", get(handlers::list_deployments))
        .route("/api/services", get(handlers::list_services))
        .route("/api/namespaces", get(handlers::list_namespaces))
        .route("/api/nodes", get(handlers::list_nodes))
        .route("/api/contexts", get(handlers::list_contexts_handler))
        .route("/api/context", get(handlers::get_current_context))
        // WebSocket endpoints
        .route("/api/ws/logs/{ns}/{name}", get(websocket::ws_logs_handler))
        .route("/api/ws/exec/{ns}/{name}", get(websocket::ws_exec_handler))
        // Serve embedded frontend
        .fallback(serve_assets)
        .layer(cors)
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], port));
    let url = format!("http://{}", addr);

    println!("🚀 Dashboard running at {}", url);
    println!("🔑 Token: (auto-authenticated via localhost)");

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
