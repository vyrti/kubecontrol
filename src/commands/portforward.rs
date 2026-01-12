//! Port-forward command implementation

use crate::cli::PortForwardArgs;
use crate::client::create_client;
use crate::error::{KcError, Result};
use k8s_openapi::api::core::v1::Pod;
use kube::Api;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::signal;

/// Port mapping (local -> remote)
struct PortMapping {
    local: u16,
    remote: u16,
}

/// Run the port-forward command
pub async fn run_port_forward(
    context: Option<&str>,
    namespace: Option<&str>,
    args: &PortForwardArgs,
) -> Result<()> {
    if args.ports.is_empty() {
        return Err(KcError::InvalidArgument(
            "No ports specified. Format: local:remote or just remote".to_string(),
        ));
    }

    let client = create_client(context).await?;
    let ns = namespace.unwrap_or("default");
    let api: Api<Pod> = Api::namespaced(client, ns);

    // Parse port mappings
    let mappings = parse_port_mappings(&args.ports)?;

    // Print forwarding info
    for mapping in &mappings {
        println!(
            "Forwarding from {}:{} -> {}:{}",
            args.address, mapping.local, args.pod, mapping.remote
        );
    }

    // Start port forwarding for each mapping
    let mut handles = Vec::new();

    for mapping in mappings {
        let api = api.clone();
        let pod_name = args.pod.clone();
        let address = args.address.clone();

        let handle = tokio::spawn(async move {
            if let Err(e) = forward_port(&api, &pod_name, &address, mapping).await {
                eprintln!("Port forward error: {}", e);
            }
        });

        handles.push(handle);
    }

    println!("Forwarding, press Ctrl+C to exit...");

    // Wait for Ctrl+C
    signal::ctrl_c().await.ok();
    println!("\nStopping port forwarding...");

    // Cancel all port forwards
    for handle in handles {
        handle.abort();
    }

    Ok(())
}

fn parse_port_mappings(ports: &[String]) -> Result<Vec<PortMapping>> {
    let mut mappings = Vec::new();

    for port_str in ports {
        let parts: Vec<&str> = port_str.split(':').collect();

        let mapping = match parts.as_slice() {
            [remote] => {
                // Just remote port, use same for local
                let port: u16 = remote.parse().map_err(|_| {
                    KcError::InvalidArgument(format!("Invalid port: {}", remote))
                })?;
                PortMapping {
                    local: port,
                    remote: port,
                }
            }
            [local, remote] => {
                let local_port: u16 = local.parse().map_err(|_| {
                    KcError::InvalidArgument(format!("Invalid local port: {}", local))
                })?;
                let remote_port: u16 = remote.parse().map_err(|_| {
                    KcError::InvalidArgument(format!("Invalid remote port: {}", remote))
                })?;
                PortMapping {
                    local: local_port,
                    remote: remote_port,
                }
            }
            _ => {
                return Err(KcError::InvalidArgument(format!(
                    "Invalid port format: {}. Expected 'local:remote' or 'remote'",
                    port_str
                )));
            }
        };

        mappings.push(mapping);
    }

    Ok(mappings)
}

async fn forward_port(
    api: &Api<Pod>,
    pod_name: &str,
    address: &str,
    mapping: PortMapping,
) -> Result<()> {
    let bind_addr = format!("{}:{}", address, mapping.local);
    let listener = TcpListener::bind(&bind_addr).await.map_err(|e| {
        KcError::Io(std::io::Error::new(
            e.kind(),
            format!("Failed to bind to {}: {}", bind_addr, e),
        ))
    })?;

    loop {
        let (mut client_stream, _) = listener.accept().await?;

        // Create port forward to pod
        let mut pf = api.portforward(pod_name, &[mapping.remote]).await?;

        let mut upstream = pf
            .take_stream(mapping.remote)
            .ok_or_else(|| KcError::InvalidArgument("Failed to get port forward stream".to_string()))?;

        // Spawn task to handle bidirectional copying
        tokio::spawn(async move {
            let (mut client_read, mut client_write) = client_stream.split();
            let (mut upstream_read, mut upstream_write) = tokio::io::split(upstream);

            let client_to_upstream = tokio::io::copy(&mut client_read, &mut upstream_write);
            let upstream_to_client = tokio::io::copy(&mut upstream_read, &mut client_write);

            tokio::select! {
                _ = client_to_upstream => {}
                _ = upstream_to_client => {}
            }
        });
    }
}
