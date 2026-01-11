//! WebSocket handlers for real-time features

use crate::web::handlers::AppState;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        Path, Query, State,
    },
    response::IntoResponse,
};
use futures::{SinkExt, StreamExt};
use futures::AsyncBufReadExt as FuturesAsyncBufReadExt;
use k8s_openapi::api::core::v1::Pod;
use kube::{api::LogParams, Api};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct LogsWsQuery {
    pub container: Option<String>,
    pub tail: Option<i64>,
}

/// WebSocket handler for streaming logs
pub async fn ws_logs_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
    Query(params): Query<LogsWsQuery>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_logs_ws(socket, state, ns, name, params))
}

async fn handle_logs_ws(
    mut socket: WebSocket,
    state: AppState,
    ns: String,
    name: String,
    params: LogsWsQuery,
) {
    let client = state.client.read().await.clone();
    let api: Api<Pod> = Api::namespaced(client, &ns);

    let mut lp = LogParams {
        follow: true,
        ..Default::default()
    };

    if let Some(container) = params.container {
        lp.container = Some(container);
    }
    if let Some(tail) = params.tail {
        lp.tail_lines = Some(tail);
    }

    // Stream logs using futures-compatible approach
    match api.log_stream(&name, &lp).await {
        Ok(stream) => {
            let reader = futures::io::BufReader::new(stream);
            let mut lines = reader.lines();

            while let Some(line_result) = lines.next().await {
                match line_result {
                    Ok(line) => {
                        if socket.send(Message::Text(line.into())).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        }
        Err(e) => {
            let _ = socket
                .send(Message::Text(format!("Error: {}", e).into()))
                .await;
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ExecWsQuery {
    pub container: Option<String>,
    pub shell: Option<String>,
}

/// WebSocket handler for exec (terminal)
pub async fn ws_exec_handler(
    ws: WebSocketUpgrade,
    State(state): State<AppState>,
    Path((ns, name)): Path<(String, String)>,
    Query(params): Query<ExecWsQuery>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_exec_ws(socket, state, ns, name, params))
}

async fn handle_exec_ws(
    socket: WebSocket,
    _state: AppState,
    ns: String,
    name: String,
    params: ExecWsQuery,
) {
    let (mut sender, mut receiver) = socket.split();

    // Send initial message
    let shell = params.shell.as_deref().unwrap_or("/bin/sh");
    let _ = sender
        .send(Message::Text(
            format!("Connecting to {}:{} (shell: {})...\r\n", ns, name, shell).into(),
        ))
        .await;

    // Note: Full exec implementation requires kube-rs attach/exec API
    // This is a placeholder that shows the architecture
    let _ = sender
        .send(Message::Text(
            "Web terminal exec not fully implemented yet.\r\n\
             Use 'kc exec' or 'kc shell' from the CLI.\r\n"
                .to_string().into(),
        ))
        .await;

    // Echo back any input for now (demo)
    while let Some(Ok(msg)) = receiver.next().await {
        match msg {
            Message::Text(text) => {
                let response = format!("echo: {}", text);
                if sender.send(Message::Text(response.into())).await.is_err() {
                    break;
                }
            }
            Message::Binary(data) => {
                if sender.send(Message::Binary(data)).await.is_err() {
                    break;
                }
            }
            Message::Close(_) => break,
            _ => {}
        }
    }
}
