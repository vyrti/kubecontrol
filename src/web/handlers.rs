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
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::core::v1::{ConfigMap, Event, Namespace, Node, Pod, Secret, Service};
use kube::{api::{DeleteParams, Patch, PatchParams}, Api, Client};
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
    pub replicas: i32,
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

/// ConfigMap summary
#[derive(Debug, Serialize)]
pub struct ConfigMapSummary {
    pub name: String,
    pub namespace: String,
    pub data_count: usize,
    pub age: String,
}

/// Secret summary
#[derive(Debug, Serialize)]
pub struct SecretSummary {
    pub name: String,
    pub namespace: String,
    pub secret_type: String,
    pub data_count: usize,
    pub age: String,
}

/// ReplicaSet summary
#[derive(Debug, Serialize)]
pub struct ReplicaSetSummary {
    pub name: String,
    pub namespace: String,
    pub desired: i32,
    pub current: i32,
    pub ready: i32,
    pub age: String,
}

/// StatefulSet summary
#[derive(Debug, Serialize)]
pub struct StatefulSetSummary {
    pub name: String,
    pub namespace: String,
    pub ready: String,
    pub replicas: i32,
    pub age: String,
}

/// DaemonSet summary
#[derive(Debug, Serialize)]
pub struct DaemonSetSummary {
    pub name: String,
    pub namespace: String,
    pub desired: i32,
    pub current: i32,
    pub ready: i32,
    pub available: i32,
    pub age: String,
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

/// Success response
#[derive(Debug, Serialize)]
pub struct SuccessResponse {
    pub message: String,
}

// ============================================================================
// Pod Handlers
// ============================================================================

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
    if params.previous.unwrap_or(false) {
        lp.previous = true;
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
    pub previous: Option<bool>,
}

/// Delete pod
pub async fn delete_pod(
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
    Query(params): Query<DeleteQuery>,
) -> std::result::Result<Json<SuccessResponse>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<Pod> = Api::namespaced(client, &ns);

    let mut dp = DeleteParams::default();
    if let Some(grace) = params.grace_period {
        dp = dp.grace_period(grace as u32);
    }
    if params.force.unwrap_or(false) {
        dp = dp.grace_period(0);
    }

    api.delete(&name, &dp)
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    Ok(Json(SuccessResponse {
        message: format!("Pod {}/{} deleted", ns, name),
    }))
}

#[derive(Debug, Deserialize)]
pub struct DeleteQuery {
    pub grace_period: Option<i64>,
    pub force: Option<bool>,
}

// ============================================================================
// Deployment Handlers
// ============================================================================

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
                replicas: desired,
            }
        })
        .collect();

    Ok(Json(summaries))
}

/// Get deployment
pub async fn get_deployment(
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
) -> std::result::Result<Json<Deployment>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<Deployment> = Api::namespaced(client, &ns);

    let deploy = api
        .get(&name)
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    Ok(Json(deploy))
}

/// Scale deployment
pub async fn scale_deployment(
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
    Json(body): Json<ScaleRequest>,
) -> std::result::Result<Json<SuccessResponse>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<Deployment> = Api::namespaced(client, &ns);

    let patch = serde_json::json!({
        "spec": {
            "replicas": body.replicas
        }
    });

    api.patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    Ok(Json(SuccessResponse {
        message: format!("Deployment {}/{} scaled to {} replicas", ns, name, body.replicas),
    }))
}

/// Restart deployment
pub async fn restart_deployment(
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
) -> std::result::Result<Json<SuccessResponse>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<Deployment> = Api::namespaced(client, &ns);

    let now = chrono::Utc::now().to_rfc3339();
    let patch = serde_json::json!({
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "kubectl.kubernetes.io/restartedAt": now
                    }
                }
            }
        }
    });

    api.patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    Ok(Json(SuccessResponse {
        message: format!("Deployment {}/{} restarted", ns, name),
    }))
}

/// Delete deployment
pub async fn delete_deployment(
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
) -> std::result::Result<Json<SuccessResponse>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<Deployment> = Api::namespaced(client, &ns);

    api.delete(&name, &DeleteParams::default())
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    Ok(Json(SuccessResponse {
        message: format!("Deployment {}/{} deleted", ns, name),
    }))
}

#[derive(Debug, Deserialize)]
pub struct ScaleRequest {
    pub replicas: i32,
}

// ============================================================================
// Service Handlers
// ============================================================================

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

/// Get service
pub async fn get_service(
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
) -> std::result::Result<Json<Service>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<Service> = Api::namespaced(client, &ns);

    let svc = api
        .get(&name)
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    Ok(Json(svc))
}

/// Delete service
pub async fn delete_service(
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
) -> std::result::Result<Json<SuccessResponse>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<Service> = Api::namespaced(client, &ns);

    api.delete(&name, &DeleteParams::default())
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    Ok(Json(SuccessResponse {
        message: format!("Service {}/{} deleted", ns, name),
    }))
}

// ============================================================================
// ConfigMap Handlers
// ============================================================================

/// List configmaps
pub async fn list_configmaps(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> std::result::Result<Json<Vec<ConfigMapSummary>>, ApiError> {
    let client = state.client.read().await.clone();
    let ns = query.namespace.as_deref().or(state.namespace.as_deref());

    let api: Api<ConfigMap> = if query.all_namespaces.unwrap_or(false) {
        Api::all(client)
    } else {
        match ns {
            Some(n) => Api::namespaced(client, n),
            None => Api::default_namespaced(client),
        }
    };

    let cms = api
        .list(&Default::default())
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    let summaries: Vec<ConfigMapSummary> = cms
        .items
        .into_iter()
        .map(|cm| ConfigMapSummary {
            name: cm.name().to_string(),
            namespace: cm.namespace().unwrap_or("default").to_string(),
            data_count: cm.data.as_ref().map(|d| d.len()).unwrap_or(0),
            age: cm.age(),
        })
        .collect();

    Ok(Json(summaries))
}

/// Get configmap
pub async fn get_configmap(
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
) -> std::result::Result<Json<ConfigMap>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<ConfigMap> = Api::namespaced(client, &ns);

    let cm = api
        .get(&name)
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    Ok(Json(cm))
}

/// Delete configmap
pub async fn delete_configmap(
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
) -> std::result::Result<Json<SuccessResponse>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<ConfigMap> = Api::namespaced(client, &ns);

    api.delete(&name, &DeleteParams::default())
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    Ok(Json(SuccessResponse {
        message: format!("ConfigMap {}/{} deleted", ns, name),
    }))
}

// ============================================================================
// Secret Handlers
// ============================================================================

/// List secrets
pub async fn list_secrets(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> std::result::Result<Json<Vec<SecretSummary>>, ApiError> {
    let client = state.client.read().await.clone();
    let ns = query.namespace.as_deref().or(state.namespace.as_deref());

    let api: Api<Secret> = if query.all_namespaces.unwrap_or(false) {
        Api::all(client)
    } else {
        match ns {
            Some(n) => Api::namespaced(client, n),
            None => Api::default_namespaced(client),
        }
    };

    let secrets = api
        .list(&Default::default())
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    let summaries: Vec<SecretSummary> = secrets
        .items
        .into_iter()
        .map(|secret| SecretSummary {
            name: secret.name().to_string(),
            namespace: secret.namespace().unwrap_or("default").to_string(),
            secret_type: secret.type_.clone().unwrap_or_default(),
            data_count: secret.data.as_ref().map(|d| d.len()).unwrap_or(0),
            age: secret.age(),
        })
        .collect();

    Ok(Json(summaries))
}

/// Get secret (metadata only, not data for security)
pub async fn get_secret(
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
) -> std::result::Result<Json<Secret>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<Secret> = Api::namespaced(client, &ns);

    let secret = api
        .get(&name)
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    Ok(Json(secret))
}

/// Delete secret
pub async fn delete_secret(
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
) -> std::result::Result<Json<SuccessResponse>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<Secret> = Api::namespaced(client, &ns);

    api.delete(&name, &DeleteParams::default())
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    Ok(Json(SuccessResponse {
        message: format!("Secret {}/{} deleted", ns, name),
    }))
}

// ============================================================================
// ReplicaSet Handlers
// ============================================================================

/// List replicasets
pub async fn list_replicasets(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> std::result::Result<Json<Vec<ReplicaSetSummary>>, ApiError> {
    let client = state.client.read().await.clone();
    let ns = query.namespace.as_deref().or(state.namespace.as_deref());

    let api: Api<ReplicaSet> = if query.all_namespaces.unwrap_or(false) {
        Api::all(client)
    } else {
        match ns {
            Some(n) => Api::namespaced(client, n),
            None => Api::default_namespaced(client),
        }
    };

    let rss = api
        .list(&Default::default())
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    let summaries: Vec<ReplicaSetSummary> = rss
        .items
        .into_iter()
        .map(|rs| {
            let status = rs.status.as_ref();
            ReplicaSetSummary {
                name: rs.name().to_string(),
                namespace: rs.namespace().unwrap_or("default").to_string(),
                desired: rs.spec.as_ref().and_then(|s| s.replicas).unwrap_or(0),
                current: status.map(|s| s.replicas).unwrap_or(0),
                ready: status.and_then(|s| s.ready_replicas).unwrap_or(0),
                age: rs.age(),
            }
        })
        .collect();

    Ok(Json(summaries))
}

/// Delete replicaset
pub async fn delete_replicaset(
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
) -> std::result::Result<Json<SuccessResponse>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<ReplicaSet> = Api::namespaced(client, &ns);

    api.delete(&name, &DeleteParams::default())
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    Ok(Json(SuccessResponse {
        message: format!("ReplicaSet {}/{} deleted", ns, name),
    }))
}

// ============================================================================
// StatefulSet Handlers
// ============================================================================

/// List statefulsets
pub async fn list_statefulsets(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> std::result::Result<Json<Vec<StatefulSetSummary>>, ApiError> {
    let client = state.client.read().await.clone();
    let ns = query.namespace.as_deref().or(state.namespace.as_deref());

    let api: Api<StatefulSet> = if query.all_namespaces.unwrap_or(false) {
        Api::all(client)
    } else {
        match ns {
            Some(n) => Api::namespaced(client, n),
            None => Api::default_namespaced(client),
        }
    };

    let stss = api
        .list(&Default::default())
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    let summaries: Vec<StatefulSetSummary> = stss
        .items
        .into_iter()
        .map(|sts| {
            let status = sts.status.as_ref();
            let desired = sts.spec.as_ref().and_then(|s| s.replicas).unwrap_or(0);
            let ready = status.and_then(|s| s.ready_replicas).unwrap_or(0);

            StatefulSetSummary {
                name: sts.name().to_string(),
                namespace: sts.namespace().unwrap_or("default").to_string(),
                ready: format!("{}/{}", ready, desired),
                replicas: desired,
                age: sts.age(),
            }
        })
        .collect();

    Ok(Json(summaries))
}

/// Scale statefulset
pub async fn scale_statefulset(
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
    Json(body): Json<ScaleRequest>,
) -> std::result::Result<Json<SuccessResponse>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<StatefulSet> = Api::namespaced(client, &ns);

    let patch = serde_json::json!({
        "spec": {
            "replicas": body.replicas
        }
    });

    api.patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    Ok(Json(SuccessResponse {
        message: format!("StatefulSet {}/{} scaled to {} replicas", ns, name, body.replicas),
    }))
}

/// Restart statefulset
pub async fn restart_statefulset(
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
) -> std::result::Result<Json<SuccessResponse>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<StatefulSet> = Api::namespaced(client, &ns);

    let now = chrono::Utc::now().to_rfc3339();
    let patch = serde_json::json!({
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "kubectl.kubernetes.io/restartedAt": now
                    }
                }
            }
        }
    });

    api.patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    Ok(Json(SuccessResponse {
        message: format!("StatefulSet {}/{} restarted", ns, name),
    }))
}

/// Delete statefulset
pub async fn delete_statefulset(
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
) -> std::result::Result<Json<SuccessResponse>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<StatefulSet> = Api::namespaced(client, &ns);

    api.delete(&name, &DeleteParams::default())
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    Ok(Json(SuccessResponse {
        message: format!("StatefulSet {}/{} deleted", ns, name),
    }))
}

// ============================================================================
// DaemonSet Handlers
// ============================================================================

/// List daemonsets
pub async fn list_daemonsets(
    State(state): State<AppState>,
    Query(query): Query<ListQuery>,
) -> std::result::Result<Json<Vec<DaemonSetSummary>>, ApiError> {
    let client = state.client.read().await.clone();
    let ns = query.namespace.as_deref().or(state.namespace.as_deref());

    let api: Api<DaemonSet> = if query.all_namespaces.unwrap_or(false) {
        Api::all(client)
    } else {
        match ns {
            Some(n) => Api::namespaced(client, n),
            None => Api::default_namespaced(client),
        }
    };

    let dss = api
        .list(&Default::default())
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    let summaries: Vec<DaemonSetSummary> = dss
        .items
        .into_iter()
        .map(|ds| {
            let status = ds.status.as_ref();
            DaemonSetSummary {
                name: ds.name().to_string(),
                namespace: ds.namespace().unwrap_or("default").to_string(),
                desired: status.map(|s| s.desired_number_scheduled).unwrap_or(0),
                current: status.map(|s| s.current_number_scheduled).unwrap_or(0),
                ready: status.map(|s| s.number_ready).unwrap_or(0),
                available: status.and_then(|s| s.number_available).unwrap_or(0),
                age: ds.age(),
            }
        })
        .collect();

    Ok(Json(summaries))
}

/// Restart daemonset
pub async fn restart_daemonset(
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
) -> std::result::Result<Json<SuccessResponse>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<DaemonSet> = Api::namespaced(client, &ns);

    let now = chrono::Utc::now().to_rfc3339();
    let patch = serde_json::json!({
        "spec": {
            "template": {
                "metadata": {
                    "annotations": {
                        "kubectl.kubernetes.io/restartedAt": now
                    }
                }
            }
        }
    });

    api.patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    Ok(Json(SuccessResponse {
        message: format!("DaemonSet {}/{} restarted", ns, name),
    }))
}

/// Delete daemonset
pub async fn delete_daemonset(
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
) -> std::result::Result<Json<SuccessResponse>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<DaemonSet> = Api::namespaced(client, &ns);

    api.delete(&name, &DeleteParams::default())
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    Ok(Json(SuccessResponse {
        message: format!("DaemonSet {}/{} deleted", ns, name),
    }))
}

// ============================================================================
// Namespace Handlers
// ============================================================================

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

/// Get namespace
pub async fn get_namespace(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> std::result::Result<Json<Namespace>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<Namespace> = Api::all(client);

    let ns = api
        .get(&name)
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    Ok(Json(ns))
}

/// Delete namespace
pub async fn delete_namespace(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> std::result::Result<Json<SuccessResponse>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<Namespace> = Api::all(client);

    api.delete(&name, &DeleteParams::default())
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    Ok(Json(SuccessResponse {
        message: format!("Namespace {} deleted", name),
    }))
}

// ============================================================================
// Node Handlers
// ============================================================================

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

/// Get node
pub async fn get_node(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> std::result::Result<Json<Node>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<Node> = Api::all(client);

    let node = api
        .get(&name)
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    Ok(Json(node))
}

/// Cordon node
pub async fn cordon_node(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> std::result::Result<Json<SuccessResponse>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<Node> = Api::all(client);

    let patch = serde_json::json!({
        "spec": {
            "unschedulable": true
        }
    });

    api.patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    Ok(Json(SuccessResponse {
        message: format!("Node {} cordoned", name),
    }))
}

/// Uncordon node
pub async fn uncordon_node(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> std::result::Result<Json<SuccessResponse>, ApiError> {
    let client = state.client.read().await.clone();
    let api: Api<Node> = Api::all(client);

    let patch = serde_json::json!({
        "spec": {
            "unschedulable": false
        }
    });

    api.patch(&name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    Ok(Json(SuccessResponse {
        message: format!("Node {} uncordoned", name),
    }))
}

// ============================================================================
// Context Handlers
// ============================================================================

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

// ============================================================================
// Apply/Create Handlers
// ============================================================================

/// Apply YAML manifest
pub async fn apply_yaml(
    State(state): State<AppState>,
    body: String,
) -> std::result::Result<Json<SuccessResponse>, ApiError> {
    let client = state.client.read().await.clone();

    // Parse YAML to determine resource type
    let value: serde_json::Value = serde_yaml::from_str(&body)
        .map_err(|e| ApiError { error: format!("Invalid YAML: {}", e) })?;

    let kind = value.get("kind")
        .and_then(|k| k.as_str())
        .ok_or_else(|| ApiError { error: "Missing 'kind' field".to_string() })?;

    let api_version = value.get("apiVersion")
        .and_then(|v| v.as_str())
        .ok_or_else(|| ApiError { error: "Missing 'apiVersion' field".to_string() })?;

    let metadata = value.get("metadata")
        .ok_or_else(|| ApiError { error: "Missing 'metadata' field".to_string() })?;

    let name = metadata.get("name")
        .and_then(|n| n.as_str())
        .ok_or_else(|| ApiError { error: "Missing 'metadata.name' field".to_string() })?;

    let namespace = metadata.get("namespace")
        .and_then(|n| n.as_str())
        .unwrap_or("default");

    // Apply based on resource type
    let pp = PatchParams::apply("kc-ui").force();

    match (api_version, kind) {
        ("v1", "Pod") => {
            let api: Api<Pod> = Api::namespaced(client, namespace);
            api.patch(name, &pp, &Patch::Apply(&value))
                .await
                .map_err(|e| ApiError { error: e.to_string() })?;
        }
        ("v1", "Service") => {
            let api: Api<Service> = Api::namespaced(client, namespace);
            api.patch(name, &pp, &Patch::Apply(&value))
                .await
                .map_err(|e| ApiError { error: e.to_string() })?;
        }
        ("v1", "ConfigMap") => {
            let api: Api<ConfigMap> = Api::namespaced(client, namespace);
            api.patch(name, &pp, &Patch::Apply(&value))
                .await
                .map_err(|e| ApiError { error: e.to_string() })?;
        }
        ("v1", "Secret") => {
            let api: Api<Secret> = Api::namespaced(client, namespace);
            api.patch(name, &pp, &Patch::Apply(&value))
                .await
                .map_err(|e| ApiError { error: e.to_string() })?;
        }
        ("v1", "Namespace") => {
            let api: Api<Namespace> = Api::all(client);
            api.patch(name, &pp, &Patch::Apply(&value))
                .await
                .map_err(|e| ApiError { error: e.to_string() })?;
        }
        ("apps/v1", "Deployment") => {
            let api: Api<Deployment> = Api::namespaced(client, namespace);
            api.patch(name, &pp, &Patch::Apply(&value))
                .await
                .map_err(|e| ApiError { error: e.to_string() })?;
        }
        ("apps/v1", "StatefulSet") => {
            let api: Api<StatefulSet> = Api::namespaced(client, namespace);
            api.patch(name, &pp, &Patch::Apply(&value))
                .await
                .map_err(|e| ApiError { error: e.to_string() })?;
        }
        ("apps/v1", "DaemonSet") => {
            let api: Api<DaemonSet> = Api::namespaced(client, namespace);
            api.patch(name, &pp, &Patch::Apply(&value))
                .await
                .map_err(|e| ApiError { error: e.to_string() })?;
        }
        ("apps/v1", "ReplicaSet") => {
            let api: Api<ReplicaSet> = Api::namespaced(client, namespace);
            api.patch(name, &pp, &Patch::Apply(&value))
                .await
                .map_err(|e| ApiError { error: e.to_string() })?;
        }
        _ => {
            return Err(ApiError {
                error: format!("Unsupported resource type: {}/{}", api_version, kind),
            });
        }
    }

    Ok(Json(SuccessResponse {
        message: format!("{} {}/{} applied", kind, namespace, name),
    }))
}

// ============================================================================
// Events Handlers
// ============================================================================

/// Event summary for API response
#[derive(Debug, Serialize)]
pub struct EventSummary {
    pub event_type: String,
    pub reason: String,
    pub message: String,
    pub object_kind: String,
    pub object_name: String,
    pub object_namespace: String,
    pub count: i32,
    pub first_timestamp: String,
    pub last_timestamp: String,
    pub age: String,
}

/// Query parameters for events
#[derive(Debug, Deserialize)]
pub struct EventsQuery {
    pub namespace: Option<String>,
    pub all_namespaces: Option<bool>,
    pub event_type: Option<String>, // "Warning" or "Normal"
    pub limit: Option<usize>,
}

/// List events
pub async fn list_events(
    State(state): State<AppState>,
    Query(query): Query<EventsQuery>,
) -> std::result::Result<Json<Vec<EventSummary>>, ApiError> {
    let client = state.client.read().await.clone();
    let ns = query.namespace.as_deref().or(state.namespace.as_deref());

    let api: Api<Event> = if query.all_namespaces.unwrap_or(true) {
        Api::all(client)
    } else {
        match ns {
            Some(n) => Api::namespaced(client, n),
            None => Api::default_namespaced(client),
        }
    };

    let events = api
        .list(&Default::default())
        .await
        .map_err(|e| ApiError { error: e.to_string() })?;

    let mut summaries: Vec<EventSummary> = events
        .items
        .into_iter()
        .filter(|event| {
            // Filter by event type if specified
            if let Some(ref et) = query.event_type {
                event.type_.as_ref().map(|t| t == et).unwrap_or(false)
            } else {
                true
            }
        })
        .map(|event| {
            let involved_object = &event.involved_object;
            let first_ts = event
                .first_timestamp
                .as_ref()
                .map(|t| t.0.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_default();
            let last_ts = event
                .last_timestamp
                .as_ref()
                .map(|t| t.0.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_default();

            // Calculate age from last_timestamp
            let age = event
                .last_timestamp
                .as_ref()
                .map(|t| {
                    let duration = chrono::Utc::now().signed_duration_since(t.0);
                    if duration.num_days() > 0 {
                        format!("{}d", duration.num_days())
                    } else if duration.num_hours() > 0 {
                        format!("{}h", duration.num_hours())
                    } else if duration.num_minutes() > 0 {
                        format!("{}m", duration.num_minutes())
                    } else {
                        format!("{}s", duration.num_seconds())
                    }
                })
                .unwrap_or_else(|| "-".to_string());

            EventSummary {
                event_type: event.type_.unwrap_or_else(|| "Normal".to_string()),
                reason: event.reason.unwrap_or_default(),
                message: event.message.unwrap_or_default(),
                object_kind: involved_object.kind.clone().unwrap_or_default(),
                object_name: involved_object.name.clone().unwrap_or_default(),
                object_namespace: involved_object.namespace.clone().unwrap_or_default(),
                count: event.count.unwrap_or(1),
                first_timestamp: first_ts,
                last_timestamp: last_ts,
                age,
            }
        })
        .collect();

    // Sort by last_timestamp descending (most recent first)
    summaries.sort_by(|a, b| b.last_timestamp.cmp(&a.last_timestamp));

    // Apply limit if specified
    if let Some(limit) = query.limit {
        summaries.truncate(limit);
    }

    Ok(Json(summaries))
}

// ============================================================================
// Pulse (Cluster Overview) Handlers
// ============================================================================

/// Cluster pulse/overview response
#[derive(Debug, Serialize)]
pub struct PulseResponse {
    pub context: String,
    pub namespace: Option<String>,
    pub resource_counts: ResourceCounts,
    pub pod_status_breakdown: PodStatusBreakdown,
    pub node_status: Vec<NodeStatusItem>,
    pub recent_events: Vec<EventSummary>,
}

#[derive(Debug, Serialize)]
pub struct ResourceCounts {
    pub pods: usize,
    pub deployments: usize,
    pub statefulsets: usize,
    pub daemonsets: usize,
    pub services: usize,
    pub configmaps: usize,
    pub secrets: usize,
    pub nodes: usize,
    pub namespaces: usize,
}

#[derive(Debug, Serialize)]
pub struct PodStatusBreakdown {
    pub running: usize,
    pub pending: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub unknown: usize,
    pub total: usize,
}

#[derive(Debug, Serialize)]
pub struct NodeStatusItem {
    pub name: String,
    pub status: String,
    pub cpu_capacity: String,
    pub memory_capacity: String,
}

/// Get cluster pulse/overview
pub async fn get_pulse(
    State(state): State<AppState>,
) -> std::result::Result<Json<PulseResponse>, ApiError> {
    let client = state.client.read().await.clone();

    // Get current context
    let context = current_context().unwrap_or_else(|_| "unknown".to_string());

    // Create APIs first
    let pods_api: Api<Pod> = Api::all(client.clone());
    let deployments_api: Api<Deployment> = Api::all(client.clone());
    let statefulsets_api: Api<StatefulSet> = Api::all(client.clone());
    let daemonsets_api: Api<DaemonSet> = Api::all(client.clone());
    let services_api: Api<Service> = Api::all(client.clone());
    let configmaps_api: Api<ConfigMap> = Api::all(client.clone());
    let secrets_api: Api<Secret> = Api::all(client.clone());
    let nodes_api: Api<Node> = Api::all(client.clone());
    let namespaces_api: Api<Namespace> = Api::all(client.clone());
    let events_api: Api<Event> = Api::all(client.clone());

    let lp = Default::default();

    // Fetch all resource counts in parallel
    let (pods_result, deployments_result, statefulsets_result, daemonsets_result,
         services_result, configmaps_result, secrets_result, nodes_result,
         namespaces_result, events_result) = tokio::join!(
        pods_api.list(&lp),
        deployments_api.list(&lp),
        statefulsets_api.list(&lp),
        daemonsets_api.list(&lp),
        services_api.list(&lp),
        configmaps_api.list(&lp),
        secrets_api.list(&lp),
        nodes_api.list(&lp),
        namespaces_api.list(&lp),
        events_api.list(&lp),
    );

    let pods = pods_result.map_err(|e| ApiError { error: e.to_string() })?;
    let deployments = deployments_result.map_err(|e| ApiError { error: e.to_string() })?;
    let statefulsets = statefulsets_result.map_err(|e| ApiError { error: e.to_string() })?;
    let daemonsets = daemonsets_result.map_err(|e| ApiError { error: e.to_string() })?;
    let services = services_result.map_err(|e| ApiError { error: e.to_string() })?;
    let configmaps = configmaps_result.map_err(|e| ApiError { error: e.to_string() })?;
    let secrets = secrets_result.map_err(|e| ApiError { error: e.to_string() })?;
    let nodes = nodes_result.map_err(|e| ApiError { error: e.to_string() })?;
    let namespaces = namespaces_result.map_err(|e| ApiError { error: e.to_string() })?;
    let events = events_result.map_err(|e| ApiError { error: e.to_string() })?;

    // Calculate pod status breakdown
    let mut pod_status = PodStatusBreakdown {
        running: 0,
        pending: 0,
        succeeded: 0,
        failed: 0,
        unknown: 0,
        total: pods.items.len(),
    };

    for pod in &pods.items {
        if let Some(status) = &pod.status {
            match status.phase.as_deref() {
                Some("Running") => pod_status.running += 1,
                Some("Pending") => pod_status.pending += 1,
                Some("Succeeded") => pod_status.succeeded += 1,
                Some("Failed") => pod_status.failed += 1,
                _ => pod_status.unknown += 1,
            }
        } else {
            pod_status.unknown += 1;
        }
    }

    // Get node status
    let node_status: Vec<NodeStatusItem> = nodes
        .items
        .iter()
        .map(|node| {
            let name = node.metadata.name.clone().unwrap_or_default();
            let status = node
                .status
                .as_ref()
                .and_then(|s| s.conditions.as_ref())
                .and_then(|conditions| {
                    conditions.iter().find(|c| c.type_ == "Ready")
                })
                .map(|c| {
                    if c.status == "True" {
                        "Ready".to_string()
                    } else {
                        "NotReady".to_string()
                    }
                })
                .unwrap_or_else(|| "Unknown".to_string());

            let cpu_capacity = node
                .status
                .as_ref()
                .and_then(|s| s.capacity.as_ref())
                .and_then(|c| c.get("cpu"))
                .map(|q| q.0.clone())
                .unwrap_or_else(|| "-".to_string());

            let memory_capacity = node
                .status
                .as_ref()
                .and_then(|s| s.capacity.as_ref())
                .and_then(|c| c.get("memory"))
                .map(|q| q.0.clone())
                .unwrap_or_else(|| "-".to_string());

            NodeStatusItem {
                name,
                status,
                cpu_capacity,
                memory_capacity,
            }
        })
        .collect();

    // Get recent events (last 10, sorted by timestamp)
    let mut recent_events: Vec<EventSummary> = events
        .items
        .into_iter()
        .map(|event| {
            let involved_object = &event.involved_object;
            let first_ts = event
                .first_timestamp
                .as_ref()
                .map(|t| t.0.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_default();
            let last_ts = event
                .last_timestamp
                .as_ref()
                .map(|t| t.0.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_default();
            let age = event
                .last_timestamp
                .as_ref()
                .map(|t| {
                    let duration = chrono::Utc::now().signed_duration_since(t.0);
                    if duration.num_days() > 0 {
                        format!("{}d", duration.num_days())
                    } else if duration.num_hours() > 0 {
                        format!("{}h", duration.num_hours())
                    } else if duration.num_minutes() > 0 {
                        format!("{}m", duration.num_minutes())
                    } else {
                        format!("{}s", duration.num_seconds())
                    }
                })
                .unwrap_or_else(|| "-".to_string());

            EventSummary {
                event_type: event.type_.unwrap_or_else(|| "Normal".to_string()),
                reason: event.reason.unwrap_or_default(),
                message: event.message.unwrap_or_default(),
                object_kind: involved_object.kind.clone().unwrap_or_default(),
                object_name: involved_object.name.clone().unwrap_or_default(),
                object_namespace: involved_object.namespace.clone().unwrap_or_default(),
                count: event.count.unwrap_or(1),
                first_timestamp: first_ts,
                last_timestamp: last_ts.clone(),
                age,
            }
        })
        .collect();

    recent_events.sort_by(|a, b| b.last_timestamp.cmp(&a.last_timestamp));
    recent_events.truncate(10);

    let resource_counts = ResourceCounts {
        pods: pods.items.len(),
        deployments: deployments.items.len(),
        statefulsets: statefulsets.items.len(),
        daemonsets: daemonsets.items.len(),
        services: services.items.len(),
        configmaps: configmaps.items.len(),
        secrets: secrets.items.len(),
        nodes: node_status.len(),
        namespaces: namespaces.items.len(),
    };

    Ok(Json(PulseResponse {
        context,
        namespace: state.namespace.clone(),
        resource_counts,
        pod_status_breakdown: pod_status,
        node_status,
        recent_events,
    }))
}

// ============================================================================
// Search Handlers
// ============================================================================

/// Search result item
#[derive(Debug, Serialize)]
pub struct SearchResult {
    pub resource_type: String,
    pub name: String,
    pub namespace: Option<String>,
}

/// Query parameters for search
#[derive(Debug, Deserialize)]
pub struct SearchQuery {
    pub q: String,
}

/// Search across all resources
pub async fn search_resources(
    State(state): State<AppState>,
    Query(query): Query<SearchQuery>,
) -> std::result::Result<Json<Vec<SearchResult>>, ApiError> {
    let client = state.client.read().await.clone();
    let search_term = query.q.to_lowercase();

    let mut results = Vec::new();

    // Search pods
    if let Ok(pods) = Api::<Pod>::all(client.clone()).list(&Default::default()).await {
        for pod in pods.items {
            if let Some(name) = &pod.metadata.name {
                if name.to_lowercase().contains(&search_term) {
                    results.push(SearchResult {
                        resource_type: "Pod".to_string(),
                        name: name.clone(),
                        namespace: pod.metadata.namespace.clone(),
                    });
                }
            }
        }
    }

    // Search deployments
    if let Ok(deployments) = Api::<Deployment>::all(client.clone()).list(&Default::default()).await {
        for deploy in deployments.items {
            if let Some(name) = &deploy.metadata.name {
                if name.to_lowercase().contains(&search_term) {
                    results.push(SearchResult {
                        resource_type: "Deployment".to_string(),
                        name: name.clone(),
                        namespace: deploy.metadata.namespace.clone(),
                    });
                }
            }
        }
    }

    // Search services
    if let Ok(services) = Api::<Service>::all(client.clone()).list(&Default::default()).await {
        for svc in services.items {
            if let Some(name) = &svc.metadata.name {
                if name.to_lowercase().contains(&search_term) {
                    results.push(SearchResult {
                        resource_type: "Service".to_string(),
                        name: name.clone(),
                        namespace: svc.metadata.namespace.clone(),
                    });
                }
            }
        }
    }

    // Search configmaps
    if let Ok(cms) = Api::<ConfigMap>::all(client.clone()).list(&Default::default()).await {
        for cm in cms.items {
            if let Some(name) = &cm.metadata.name {
                if name.to_lowercase().contains(&search_term) {
                    results.push(SearchResult {
                        resource_type: "ConfigMap".to_string(),
                        name: name.clone(),
                        namespace: cm.metadata.namespace.clone(),
                    });
                }
            }
        }
    }

    // Search secrets
    if let Ok(secrets) = Api::<Secret>::all(client.clone()).list(&Default::default()).await {
        for secret in secrets.items {
            if let Some(name) = &secret.metadata.name {
                if name.to_lowercase().contains(&search_term) {
                    results.push(SearchResult {
                        resource_type: "Secret".to_string(),
                        name: name.clone(),
                        namespace: secret.metadata.namespace.clone(),
                    });
                }
            }
        }
    }

    // Search nodes
    if let Ok(nodes) = Api::<Node>::all(client.clone()).list(&Default::default()).await {
        for node in nodes.items {
            if let Some(name) = &node.metadata.name {
                if name.to_lowercase().contains(&search_term) {
                    results.push(SearchResult {
                        resource_type: "Node".to_string(),
                        name: name.clone(),
                        namespace: None,
                    });
                }
            }
        }
    }

    // Search namespaces
    if let Ok(namespaces) = Api::<Namespace>::all(client.clone()).list(&Default::default()).await {
        for ns in namespaces.items {
            if let Some(name) = &ns.metadata.name {
                if name.to_lowercase().contains(&search_term) {
                    results.push(SearchResult {
                        resource_type: "Namespace".to_string(),
                        name: name.clone(),
                        namespace: None,
                    });
                }
            }
        }
    }

    // Limit results
    results.truncate(50);

    Ok(Json(results))
}

// ============================================================================
// Health Scanner Handlers (Popeye-style)
// ============================================================================

/// Health issue severity
#[derive(Debug, Serialize, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    Warning,
    Info,
}

/// Health issue
#[derive(Debug, Serialize)]
pub struct HealthIssue {
    pub severity: Severity,
    pub resource_type: String,
    pub resource_name: String,
    pub namespace: Option<String>,
    pub issue: String,
    pub recommendation: String,
}

/// Health scan response
#[derive(Debug, Serialize)]
pub struct HealthScanResponse {
    pub issues: Vec<HealthIssue>,
    pub summary: HealthSummary,
}

#[derive(Debug, Serialize)]
pub struct HealthSummary {
    pub critical: usize,
    pub warning: usize,
    pub info: usize,
    pub total: usize,
}

/// Scan cluster for health issues
pub async fn scan_health(
    State(state): State<AppState>,
) -> std::result::Result<Json<HealthScanResponse>, ApiError> {
    let client = state.client.read().await.clone();
    let mut issues = Vec::new();

    // Scan pods
    if let Ok(pods) = Api::<Pod>::all(client.clone()).list(&Default::default()).await {
        for pod in pods.items {
            let name = pod.metadata.name.clone().unwrap_or_default();
            let namespace = pod.metadata.namespace.clone();

            if let Some(spec) = &pod.spec {
                for container in &spec.containers {
                    // Check for missing resource limits
                    let has_limits = container.resources.as_ref()
                        .and_then(|r| r.limits.as_ref())
                        .map(|l| l.contains_key("cpu") || l.contains_key("memory"))
                        .unwrap_or(false);

                    if !has_limits {
                        issues.push(HealthIssue {
                            severity: Severity::Warning,
                            resource_type: "Pod".to_string(),
                            resource_name: name.clone(),
                            namespace: namespace.clone(),
                            issue: format!("Container '{}' has no resource limits", container.name),
                            recommendation: "Set resource limits to prevent resource exhaustion".to_string(),
                        });
                    }

                    // Check for latest tag
                    if let Some(image) = &container.image {
                        if image.ends_with(":latest") || !image.contains(':') {
                            issues.push(HealthIssue {
                                severity: Severity::Warning,
                                resource_type: "Pod".to_string(),
                                resource_name: name.clone(),
                                namespace: namespace.clone(),
                                issue: format!("Container '{}' uses :latest or untagged image", container.name),
                                recommendation: "Use specific image tags for reproducibility".to_string(),
                            });
                        }
                    }

                    // Check for missing probes
                    if container.liveness_probe.is_none() && container.readiness_probe.is_none() {
                        issues.push(HealthIssue {
                            severity: Severity::Info,
                            resource_type: "Pod".to_string(),
                            resource_name: name.clone(),
                            namespace: namespace.clone(),
                            issue: format!("Container '{}' has no liveness/readiness probes", container.name),
                            recommendation: "Add probes for better health monitoring".to_string(),
                        });
                    }

                    // Check for privileged containers
                    if container.security_context.as_ref()
                        .and_then(|sc| sc.privileged)
                        .unwrap_or(false) {
                        issues.push(HealthIssue {
                            severity: Severity::Critical,
                            resource_type: "Pod".to_string(),
                            resource_name: name.clone(),
                            namespace: namespace.clone(),
                            issue: format!("Container '{}' runs in privileged mode", container.name),
                            recommendation: "Avoid privileged mode unless absolutely necessary".to_string(),
                        });
                    }

                    // Check for root user
                    let runs_as_root = container.security_context.as_ref()
                        .and_then(|sc| sc.run_as_user)
                        .map(|uid| uid == 0)
                        .unwrap_or(false);
                    if runs_as_root {
                        issues.push(HealthIssue {
                            severity: Severity::Warning,
                            resource_type: "Pod".to_string(),
                            resource_name: name.clone(),
                            namespace: namespace.clone(),
                            issue: format!("Container '{}' runs as root (UID 0)", container.name),
                            recommendation: "Run containers as non-root user".to_string(),
                        });
                    }
                }
            }

            // Check restart count
            if let Some(status) = &pod.status {
                if let Some(container_statuses) = &status.container_statuses {
                    for cs in container_statuses {
                        if cs.restart_count > 5 {
                            issues.push(HealthIssue {
                                severity: Severity::Warning,
                                resource_type: "Pod".to_string(),
                                resource_name: name.clone(),
                                namespace: namespace.clone(),
                                issue: format!("Container '{}' has {} restarts", cs.name, cs.restart_count),
                                recommendation: "Investigate container crash causes".to_string(),
                            });
                        }
                    }
                }
            }
        }
    }

    // Scan deployments for replica issues
    if let Ok(deployments) = Api::<Deployment>::all(client.clone()).list(&Default::default()).await {
        for deploy in deployments.items {
            let name = deploy.metadata.name.clone().unwrap_or_default();
            let namespace = deploy.metadata.namespace.clone();

            if let Some(status) = &deploy.status {
                let desired = status.replicas.unwrap_or(0);
                let ready = status.ready_replicas.unwrap_or(0);

                if desired > 0 && ready == 0 {
                    issues.push(HealthIssue {
                        severity: Severity::Critical,
                        resource_type: "Deployment".to_string(),
                        resource_name: name.clone(),
                        namespace: namespace.clone(),
                        issue: format!("No ready replicas ({} desired)", desired),
                        recommendation: "Check pod status and events for failures".to_string(),
                    });
                } else if ready < desired {
                    issues.push(HealthIssue {
                        severity: Severity::Warning,
                        resource_type: "Deployment".to_string(),
                        resource_name: name.clone(),
                        namespace: namespace.clone(),
                        issue: format!("Only {}/{} replicas ready", ready, desired),
                        recommendation: "Check pod events for scaling issues".to_string(),
                    });
                }
            }

            // Check for single replica
            if let Some(spec) = &deploy.spec {
                if spec.replicas == Some(1) {
                    issues.push(HealthIssue {
                        severity: Severity::Info,
                        resource_type: "Deployment".to_string(),
                        resource_name: name.clone(),
                        namespace: namespace.clone(),
                        issue: "Single replica deployment".to_string(),
                        recommendation: "Consider multiple replicas for high availability".to_string(),
                    });
                }
            }
        }
    }

    // Sort by severity
    issues.sort_by(|a, b| a.severity.cmp(&b.severity));

    let summary = HealthSummary {
        critical: issues.iter().filter(|i| i.severity == Severity::Critical).count(),
        warning: issues.iter().filter(|i| i.severity == Severity::Warning).count(),
        info: issues.iter().filter(|i| i.severity == Severity::Info).count(),
        total: issues.len(),
    };

    Ok(Json(HealthScanResponse { issues, summary }))
}
