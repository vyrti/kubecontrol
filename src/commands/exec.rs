//! Exec command implementation - execute commands in pods

use crate::cli::ExecArgs;
use crate::client::create_client;
use crate::error::{KcError, Result};
use k8s_openapi::api::core::v1::Pod;
use kube::api::AttachParams;
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
    let api: Api<Pod> = Api::namespaced(client, ns);

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
    }

    ap = ap.stdout(true).stderr(true);

    // Execute command
    let mut attached = api.exec(&args.pod, &args.command, &ap).await?;

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
