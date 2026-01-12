//! Get command implementation - generic resource access

use crate::cli::{GetArgs, OutputFormat};
use crate::client::create_client;
use crate::error::{KcError, Result};
use crate::output::{format_json, format_names, format_table, format_yaml};
use crate::resources::{KubeResource, Listable, Tabular, RESOURCE_REGISTRY};
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::core::v1::{ConfigMap, Namespace, Node, Pod, Secret, Service};
use kube::{Api, Client};
use serde::Serialize;

/// Run the get command
pub async fn run_get(
    context: Option<&str>,
    namespace: Option<&str>,
    args: &GetArgs,
    output: OutputFormat,
) -> Result<()> {
    let client = create_client(context).await?;
    let ns = namespace.unwrap_or("default");

    let info = RESOURCE_REGISTRY
        .lookup(&args.resource_type)
        .ok_or_else(|| KcError::InvalidResourceType(args.resource_type.clone()))?;

    // Determine if we're listing all namespaces
    let all_ns = args.list_args.all_namespaces;

    match info.kind {
        "Pod" => get_resource::<Pod>(&client, ns, all_ns, args, output).await,
        "Deployment" => get_resource::<Deployment>(&client, ns, all_ns, args, output).await,
        "Service" => get_resource::<Service>(&client, ns, all_ns, args, output).await,
        "ConfigMap" => get_resource::<ConfigMap>(&client, ns, all_ns, args, output).await,
        "Secret" => get_resource::<Secret>(&client, ns, all_ns, args, output).await,
        "StatefulSet" => get_resource::<StatefulSet>(&client, ns, all_ns, args, output).await,
        "DaemonSet" => get_resource::<DaemonSet>(&client, ns, all_ns, args, output).await,
        "ReplicaSet" => get_resource::<ReplicaSet>(&client, ns, all_ns, args, output).await,
        "Node" => get_resource::<Node>(&client, ns, false, args, output).await,
        "Namespace" => get_resource::<Namespace>(&client, ns, false, args, output).await,
        _ => Err(KcError::InvalidResourceType(format!(
            "get not supported for {}",
            info.kind
        ))),
    }
}

async fn get_resource<T>(
    client: &Client,
    namespace: &str,
    all_namespaces: bool,
    args: &GetArgs,
    output: OutputFormat,
) -> Result<()>
where
    T: KubeResource + Listable + Tabular + Serialize,
{
    if let Some(name) = &args.name {
        // Get single resource
        let api: Api<T> = if T::NAMESPACED {
            T::api(client.clone(), Some(namespace))
        } else {
            T::api_all(client.clone())
        };

        let resource = api.get(name).await?;
        print_resource(&[resource], output, args.list_args.wide)?;
    } else {
        // List resources
        let api: Api<T> = if all_namespaces && T::NAMESPACED {
            T::api_all(client.clone())
        } else if T::NAMESPACED {
            T::api(client.clone(), Some(namespace))
        } else {
            T::api_all(client.clone())
        };

        let resources = T::list_resources(
            &api,
            args.list_args.selector.as_deref(),
            args.list_args.field_selector.as_deref(),
        )
        .await?;

        print_resource(&resources, output, args.list_args.wide)?;
    }

    Ok(())
}

fn print_resource<T: Tabular + Serialize>(
    resources: &[T],
    output: OutputFormat,
    wide: bool,
) -> Result<()> {
    let output_str = match output {
        OutputFormat::Table => format_table(resources, false),
        OutputFormat::Wide => format_table(resources, true),
        OutputFormat::Json => format_json(resources, true)?,
        OutputFormat::Yaml => format_yaml(resources)?,
        OutputFormat::Name => format_names(resources),
    };

    if !output_str.is_empty() {
        println!("{}", output_str);
    } else if matches!(output, OutputFormat::Table | OutputFormat::Wide) {
        println!("No resources found");
    }

    Ok(())
}
