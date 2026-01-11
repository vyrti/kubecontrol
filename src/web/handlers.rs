//! HTTP handlers for the web API

use crate::client::{create_client, list_contexts as get_contexts, current_context};
use crate::error::Result;
use crate::resources::{KubeResource, Tabular};
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Namespace, Node, Pod, Service};
use kube::{Api, Client};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Shared application state
#[derive(Clone)]
pub struct AppState {
    pub client: Arc<RwLock<Client>>,
    pub context: Option<String>,
    pub namespace: Option<String>,
}

impl AppState {
    pub async fn new(context: Option<String>, namespace: Option<String>) -> Result<Self> {
        let client = create_client(context.as_deref()).await?;
        Ok(Self {
            client: Arc::new(RwLock::new(client)),
            context,
            namespace,
        })
    }
}

/// Query parameters for list endpoints
#[derive(Debug, Deserialize)]
pub struct ListQuery {
    pub namespace: Option<String>,
    pub all_namespaces: Option<bool>,
    pub selector: Option<String>,
}

/// Pod summary for API response
#[derive(Debug, Serialize)]
pub struct PodSummary {
    pub name: String,
    pub namespace: String,
    pub status: String,
    pub ready: String,
    pub restarts: i32,
    pub age: String,
    pub ip: Option<String>,
    pub node: Option<String>,
}

/// Deployment summary
#[derive(Debug, Serialize)]
pub struct DeploymentSummary {
    pub name: String,
    pub namespace: String,
    pub ready: String,
    pub up_to_date: i32,
    pub available: i32,
    pub age: String,
}

/// Service summary
#[derive(Debug, Serialize)]
pub struct ServiceSummary {
    pub name: String,
    pub namespace: String,
    pub service_type: String,
    pub cluster_ip: String,
    pub external_ip: String,
    pub ports: String,
    pub age: String,
}

/// Namespace summary
#[derive(Debug, Serialize)]
pub struct NamespaceSummary {
    pub name: String,
    pub status: String,
    pub age: String,
}

/// Node summary
#[derive(Debug, Serialize)]
pub struct NodeSummary {
    pub name: String,
    pub status: String,
    pub roles: String,
    pub age: String,
    pub version: String,
}

/// Context summary
#[derive(Debug, Serialize)]
pub struct ContextSummary {
    pub name: String,
    pub cluster: Option<String>,
    pub namespace: Option<String>,
    pub is_current: bool,
}

/// API error response
#[derive(Debug, Serialize)]
pub struct ApiError {
    pub error: String,
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        (StatusCode::INTERNAL_SERVER_ERROR, Json(self)).into_response()
    }
}

/// List pods
pub async fn list_pods(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> std::result::Result<Json<Vec<PodSummary>>, ApiError> {
    let client = state.client.read().await.clone();
    let ns = query.namespace.as_deref().or(state.namespace.as_deref());

    let api: Api<Pod> = if query.all_namespaces.unwrap_or(false) {
        Api::all(client)
    } else {
        match ns {
            Some(n) => Api::namespaced(client, n),
            None => Api::default_namespaced(client),
        }
    };

    let pods = api
        .list(&Default::default())
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    let summaries: Vec<PodSummary> = pods
        .items
        .into_iter()
        .map(|pod| {
            let row = pod.row();
            PodSummary {
                name: pod.name().to_string(),
                namespace: pod.namespace().unwrap_or("default").to_string(),
                status: row.get(2).cloned().unwrap_or_default(),
                ready: row.get(1).cloned().unwrap_or_default(),
                restarts: row.get(3).and_then(|s| s.parse().ok()).unwrap_or(0),
                age: row.get(4).cloned().unwrap_or_default(),
                ip: pod.status.as_ref().and_then(|s| s.pod_ip.clone()),
                node: pod.spec.as_ref().and_then(|s| s.node_name.clone()),
            }
        })
        .collect();

    Ok(Json(summaries))
}

/// Get a specific pod
pub async fn get_pod(
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
) -> std::result::Result<Json<Pod>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<Pod> = Api::namespaced(client, &ns);

    let pod = api
        .get(&name)
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    Ok(Json(pod))
}

/// Get pod logs
pub async fn get_pod_logs(
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
    Query(params): Query<LogsQuery>,
) -> std::result::Result<String, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<Pod> = Api::namespaced(client, &ns);

    let mut lp = kube::api::LogParams::default();
    if let Some(container) = params.container {
        lp.container = Some(container);
    }
    if let Some(tail) = params.tail {
        lp.tail_lines = Some(tail);
    }

    let logs = api
        .logs(&name, &lp)
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    Ok(logs)
}

#[derive(Debug, Deserialize)]
pub struct LogsQuery {
    pub container: Option<String>,
    pub tail: Option<i64>,
    pub follow: Option<bool>,
}

/// List deployments
pub async fn list_deployments(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> std::result::Result<Json<Vec<DeploymentSummary>>, ApiError> {
    let client = state.client.read().await.clone();
    let ns = query.namespace.as_deref().or(state.namespace.as_deref());

    let api: Api<Deployment> = if query.all_namespaces.unwrap_or(false) {
        Api::all(client)
    } else {
        match ns {
            Some(n) => Api::namespaced(client, n),
            None => Api::default_namespaced(client),
        }
    };

    let deployments = api
        .list(&Default::default())
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    let summaries: Vec<DeploymentSummary> = deployments
        .items
        .into_iter()
        .map(|deploy| {
            let status = deploy.status.as_ref();
            let desired = deploy.spec.as_ref().and_then(|s| s.replicas).unwrap_or(0);
            let ready = status.and_then(|s| s.ready_replicas).unwrap_or(0);

            DeploymentSummary {
                name: deploy.name().to_string(),
                namespace: deploy.namespace().unwrap_or("default").to_string(),
                ready: format!("{}/{}", ready, desired),
                up_to_date: status.and_then(|s| s.updated_replicas).unwrap_or(0),
                available: status.and_then(|s| s.available_replicas).unwrap_or(0),
                age: deploy.age(),
            }
        })
        .collect();

    Ok(Json(summaries))
}

/// List services
pub async fn list_services(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> std::result::Result<Json<Vec<ServiceSummary>>, ApiError> {
    let client = state.client.read().await.clone();
    let ns = query.namespace.as_deref().or(state.namespace.as_deref());

    let api: Api<Service> = if query.all_namespaces.unwrap_or(false) {
        Api::all(client)
    } else {
        match ns {
            Some(n) => Api::namespaced(client, n),
            None => Api::default_namespaced(client),
        }
    };

    let services = api
        .list(&Default::default())
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    let summaries: Vec<ServiceSummary> = services
        .items
        .into_iter()
        .map(|svc| {
            let row = svc.row();
            ServiceSummary {
                name: svc.name().to_string(),
                namespace: svc.namespace().unwrap_or("default").to_string(),
                service_type: row.get(1).cloned().unwrap_or_default(),
                cluster_ip: row.get(2).cloned().unwrap_or_default(),
                external_ip: row.get(3).cloned().unwrap_or_default(),
                ports: row.get(4).cloned().unwrap_or_default(),
                age: svc.age(),
            }
        })
        .collect();

    Ok(Json(summaries))
}

/// List namespaces
pub async fn list_namespaces(
    State(state): State<AppState>,
) -> std::result::Result<Json<Vec<NamespaceSummary>>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<Namespace> = Api::all(client);

    let namespaces = api
        .list(&Default::default())
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    let summaries: Vec<NamespaceSummary> = namespaces
        .items
        .into_iter()
        .map(|ns| {
            let row = ns.row();
            NamespaceSummary {
                name: ns.name().to_string(),
                status: row.get(1).cloned().unwrap_or_default(),
                age: ns.age(),
            }
        })
        .collect();

    Ok(Json(summaries))
}

/// List nodes
pub async fn list_nodes(
    State(state): State<AppState>,
) -> std::result::Result<Json<Vec<NodeSummary>>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<Node> = Api::all(client);

    let nodes = api
        .list(&Default::default())
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    let summaries: Vec<NodeSummary> = nodes
        .items
        .into_iter()
        .map(|node| {
            let row = node.row();
            NodeSummary {
                name: node.name().to_string(),
                status: row.get(1).cloned().unwrap_or_default(),
                roles: row.get(2).cloned().unwrap_or_default(),
                age: node.age(),
                version: row.get(4).cloned().unwrap_or_default(),
            }
        })
        .collect();

    Ok(Json(summaries))
}

/// List contexts
pub async fn list_contexts_handler() -> std::result::Result<Json<Vec<ContextSummary>>, ApiError> {
    let contexts = get_contexts()
        .map_err(|e| ApiError { error: e.to_string() })?;

    let summaries: Vec<ContextSummary> = contexts
        .into_iter()
        .map(|ctx| ContextSummary {
            name: ctx.name,
            cluster: ctx.cluster,
            namespace: ctx.namespace,
            is_current: ctx.is_current,
        })
        .collect();

    Ok(Json(summaries))
}

/// Get current context
pub async fn get_current_context() -> std::result::Result<Json<String>, ApiError> {
    let ctx = current_context()
        .map_err(|e| ApiError { error: e.to_string() })?;
    Ok(Json(ctx))
}
