//! Exec command implementation - execute commands in pods

use crate::cli::ExecArgs;
use crate::client::create_client;
use crate::error::{KcError, Result};
use k8s_openapi::api::core::v1::Pod;
use kube::api::{AttachParams, ListParams};
use kube::Api;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Run the exec command
pub async fn run_exec(
    context: Option<&str>,
    namespace: Option<&str>,
    args: &ExecArgs,
) -> Result<()> {
    if args.command.is_empty() {
        return Err(KcError::InvalidArgument(
            "No command specified. Use -- followed by the command to execute".to_string(),
        ));
    }

    let client = create_client(context).await?;
    let ns = namespace.unwrap_or("default");
    let api: Api<Pod> = Api::namespaced(client.clone(), ns);

    // Build attach params
    let mut ap = AttachParams::default();

    if let Some(container) = &args.container {
        ap = ap.container(container);
    }

    if args.stdin {
        ap = ap.stdin(true);
    }

    if args.tty {
        ap = ap.tty(true);
        // When TTY is enabled, stderr is multiplexed into stdout
        ap = ap.stdout(true).stderr(false);
    } else {
        ap = ap.stdout(true).stderr(true);
    }

    // Execute command with better error handling
    let attached = match api.exec(&args.pod, &args.command, &ap).await {
        Ok(attached) => attached,
        Err(e) => {
            // Check if this is a 404 Not Found error
            if is_not_found_error(&e) {
                // Try to find similar pods in other namespaces
                let suggestions = find_similar_pods(&client, &args.pod, ns).await;

                let mut error_msg = format!(
                    "Pod '{}' not found in namespace '{}'.",
                    args.pod, ns
                );

                if !suggestions.is_empty() {
                    error_msg.push_str("\n\nDid you mean one of these?\n");
                    for (pod_name, pod_ns) in &suggestions {
                        error_msg.push_str(&format!("  - {} (namespace: {})\n", pod_name, pod_ns));
                        error_msg.push_str(&format!("    Run: kc exec -n {} {} -- <command>\n", pod_ns, pod_name));
                    }
                } else {
                    error_msg.push_str("\n\nTip: Use `kc pods -A` to list pods in all namespaces.");
                }

                return Err(KcError::InvalidArgument(error_msg));
            }
            return Err(e.into());
        }
    };

    let mut attached = attached;

    // Handle I/O streams using async read
    let stdout = attached.stdout();
    let stderr = attached.stderr();
    let stdin = attached.stdin();

    // Spawn tasks for handling streams
    let stdout_task = if let Some(mut stdout) = stdout {
        Some(tokio::spawn(async move {
            let mut stdout_writer = tokio::io::stdout();
            let mut buf = vec![0u8; 4096];
            loop {
                match stdout.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        stdout_writer.write_all(&buf[..n]).await.ok();
                        stdout_writer.flush().await.ok();
                    }
                    Err(_) => break,
                }
            }
        }))
    } else {
        None
    };

    let stderr_task = if let Some(mut stderr) = stderr {
        Some(tokio::spawn(async move {
            let mut stderr_writer = tokio::io::stderr();
            let mut buf = vec![0u8; 4096];
            loop {
                match stderr.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        stderr_writer.write_all(&buf[..n]).await.ok();
                        stderr_writer.flush().await.ok();
                    }
                    Err(_) => break,
                }
            }
        }))
    } else {
        None
    };

    // Handle stdin if enabled
    let stdin_task = if args.stdin {
        if let Some(mut stdin_writer) = stdin {
            Some(tokio::spawn(async move {
                let mut stdin_reader = tokio::io::stdin();
                let mut buf = vec![0u8; 1024];
                loop {
                    match stdin_reader.read(&mut buf).await {
                        Ok(0) => break, // EOF
                        Ok(n) => {
                            if stdin_writer.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }))
        } else {
            None
        }
    } else {
        None
    };

    // Wait for stdin task first (if exists)
    if let Some(task) = stdin_task {
        task.await.ok();
    }

    // Wait for output tasks
    if let Some(task) = stdout_task {
        task.await.ok();
    }
    if let Some(task) = stderr_task {
        task.await.ok();
    }

    // Wait for process to complete
    attached
        .join()
        .await
        .map_err(|e| KcError::Io(std::io::Error::new(std::io::ErrorKind::Other, e.to_string())))?;

    Ok(())
}

/// Check if an error is a 404 Not Found error
fn is_not_found_error(e: &kube::Error) -> bool {
    match e {
        kube::Error::Api(api_err) => api_err.code == 404,
        kube::Error::UpgradeConnection(upgrade_err) => {
            // Check the error message for 404
            let msg = upgrade_err.to_string().to_lowercase();
            msg.contains("404") || msg.contains("not found")
        }
        _ => false,
    }
}

/// Find pods with similar names in other namespaces
async fn find_similar_pods(
    client: &kube::Client,
    pod_name: &str,
    current_ns: &str,
) -> Vec<(String, String)> {
    let mut suggestions = Vec::new();

    // Search all namespaces for pods with similar names
    let all_pods: Api<Pod> = Api::all(client.clone());

    if let Ok(pod_list) = all_pods.list(&ListParams::default()).await {
        let pod_name_lower = pod_name.to_lowercase();

        for pod in pod_list.items {
            let name = pod.metadata.name.as_deref().unwrap_or("");
            let ns = pod.metadata.namespace.as_deref().unwrap_or("default");

            // Skip pods in the current namespace (we already know it's not there)
            if ns == current_ns {
                continue;
            }

            // Check for exact match or similar names
            let name_lower = name.to_lowercase();
            if name_lower == pod_name_lower
                || name_lower.contains(&pod_name_lower)
                || pod_name_lower.contains(&name_lower)
                || string_similarity(&name_lower, &pod_name_lower) > 0.6
            {
                suggestions.push((name.to_string(), ns.to_string()));

                // Limit to 5 suggestions
                if suggestions.len() >= 5 {
                    break;
                }
            }
        }
    }

    // Sort by exact matches first, then by similarity
    suggestions.sort_by(|a, b| {
        let a_exact = a.0.to_lowercase() == pod_name.to_lowercase();
        let b_exact = b.0.to_lowercase() == pod_name.to_lowercase();
        b_exact.cmp(&a_exact)
    });

    suggestions
}

/// Simple string similarity (Jaccard-like) for fuzzy matching
fn string_similarity(a: &str, b: &str) -> f64 {
    if a == b {
        return 1.0;
    }

    let a_chars: std::collections::HashSet<char> = a.chars().collect();
    let b_chars: std::collections::HashSet<char> = b.chars().collect();

    let intersection = a_chars.intersection(&b_chars).count();
    let union = a_chars.union(&b_chars).count();

    if union == 0 {
        0.0
    } else {
        intersection as f64 / union as f64
    }
}
