//! Version command implementation
//!
//! Shows cluster version and platform information with auto-detection
//! for cloud providers (AWS, GCP, Azure) and distributions (EKS, GKE, AKS, etc.).

use crate::cli::{OutputFormat, VersionArgs};
use crate::client::create_client;
use crate::debug::cloud::{get_cluster_info, ClusterInfo};
use crate::error::Result;
use owo_colors::OwoColorize;

/// Execute the version command
pub async fn run_version(
    context: Option<&str>,
    args: &VersionArgs,
    output: OutputFormat,
) -> Result<()> {
    // Show client version only if requested
    if args.client {
        print_client_version(output)?;
        return Ok(());
    }

    // Get cluster info
    let client = create_client(context).await?;
    let cluster_info = get_cluster_info(&client).await?;

    // Output based on format
    match output {
        OutputFormat::Json => {
            let json = serde_json::to_string_pretty(&cluster_info)?;
            println!("{}", json);
        }
        OutputFormat::Yaml => {
            let yaml = serde_yaml::to_string(&cluster_info)?;
            println!("{}", yaml);
        }
        _ => {
            if args.extended {
                print_extended_info(&cluster_info);
            } else {
                print_basic_info(&cluster_info);
            }
        }
    }

    Ok(())
}

/// Print client version only
fn print_client_version(output: OutputFormat) -> Result<()> {
    let version = env!("CARGO_PKG_VERSION");
    let name = env!("CARGO_PKG_NAME");

    match output {
        OutputFormat::Json => {
            println!(r#"{{"name": "{}", "version": "{}"}}"#, name, version);
        }
        OutputFormat::Yaml => {
            println!("name: {}", name);
            println!("version: {}", version);
        }
        _ => {
            println!("{} version {}", name.bold(), version.green());
        }
    }

    Ok(())
}

/// Print basic cluster information
fn print_basic_info(info: &ClusterInfo) {
    println!();
    println!("{}", "Cluster Information".bold());
    println!("{}", "=".repeat(50));

    println!("Kubernetes Version: {}", info.kubernetes_version.green());
    println!("Platform:           {}", info.platform.to_string().cyan());

    if let Some(provider) = &info.cloud_provider {
        println!("Cloud Provider:     {}", provider.to_string().cyan());
    }

    if let Some(region) = &info.region {
        println!("Region:             {}", region);
    }

    if let Some(zone) = &info.zone {
        println!("Zone:               {}", zone);
    }

    if let Some(name) = &info.cluster_name {
        println!("Cluster Name:       {}", name);
    }

    println!();
    println!("{}", "Node Summary".bold());
    println!("{}", "-".repeat(30));
    println!("Total Nodes:        {}", info.nodes.total);
    println!("  Ready:            {}", info.nodes.ready.to_string().green());

    if info.is_managed() {
        println!("  Control Plane:    {} (managed)", info.nodes.control_plane);
    } else {
        println!("  Control Plane:    {}", info.nodes.control_plane);
    }

    println!("  Workers:          {}", info.nodes.workers);

    if !info.nodes.architectures.is_empty() {
        println!("Architecture:       {}", info.nodes.architectures.join(", "));
    }

    if !info.nodes.instance_types.is_empty() {
        let types: Vec<String> = info.nodes.instance_types
            .iter()
            .map(|(k, v)| format!("{} ({})", k, v))
            .collect();
        println!("Instance Types:     {}", types.join(", "));
    }

    println!();
}

/// Print extended cluster information
fn print_extended_info(info: &ClusterInfo) {
    // Print basic info first
    print_basic_info(info);

    // Additional details
    println!("{}", "Version Details".bold());
    println!("{}", "-".repeat(30));

    for component in &info.components {
        let status_color = if component.status == "Running" {
            component.status.green().to_string()
        } else {
            component.status.yellow().to_string()
        };
        println!("{:20} {} ({})",
            format!("{}:", component.name),
            component.version,
            status_color
        );
    }

    // Metadata
    if let Some(kubelet_version) = info.metadata.get("kubelet_version") {
        println!("{:20} {}", "kubelet:", kubelet_version);
    }

    if let Some(runtime) = info.metadata.get("container_runtime") {
        println!("{:20} {}", "Container Runtime:", runtime);
    }

    if let Some(kernel) = info.metadata.get("kernel_version") {
        println!("{:20} {}", "Kernel:", kernel);
    }

    println!();

    // OS images distribution
    if !info.nodes.os_images.is_empty() {
        println!("{}", "OS Distribution".bold());
        println!("{}", "-".repeat(30));
        for (os, count) in &info.nodes.os_images {
            println!("  {} ({} nodes)", os, count);
        }
        println!();
    }

    // Managed service info
    if info.is_managed() {
        println!("{}", "Managed Service".bold());
        println!("{}", "-".repeat(30));
        println!("Control Plane:      Managed by {}",
            info.cloud_provider.as_ref()
                .map(|p| p.to_string())
                .unwrap_or_else(|| "Provider".to_string())
        );

        match &info.platform {
            crate::debug::cloud::KubernetesDistribution::EKS => {
                println!("Dashboard:          https://console.aws.amazon.com/eks");
            }
            crate::debug::cloud::KubernetesDistribution::GKE => {
                println!("Dashboard:          https://console.cloud.google.com/kubernetes");
            }
            crate::debug::cloud::KubernetesDistribution::AKS => {
                println!("Dashboard:          https://portal.azure.com/#blade/Microsoft_Azure_ContainerService");
            }
            _ => {}
        }
        println!();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_version_format() {
        let version = env!("CARGO_PKG_VERSION");
        assert!(!version.is_empty());
    }
}
