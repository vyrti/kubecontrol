//! Describe command implementation

use crate::cli::DescribeArgs;
use crate::client::create_client;
use crate::error::{KcError, Result};
use crate::resources::{Describable, KubeResource, Listable, RESOURCE_REGISTRY};
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::core::v1::{ConfigMap, Namespace, Node, Pod, Secret, Service};
use kube::{Api, Client};

/// Run the describe command
pub async fn run_describe(
    context: Option<&str>,
    namespace: Option<&str>,
    args: &DescribeArgs,
) -> Result<()> {
    let client = create_client(context).await?;
    let ns = namespace.unwrap_or("default");

    let info = RESOURCE_REGISTRY
        .lookup(&args.resource_type)
        .ok_or_else(|| KcError::InvalidResourceType(args.resource_type.clone()))?;

    match info.kind {
        "Pod" => describe_resource::<Pod>(&client, Some(ns), &args.name).await,
        "Deployment" => describe_resource::<Deployment>(&client, Some(ns), &args.name).await,
        "Service" => describe_resource::<Service>(&client, Some(ns), &args.name).await,
        "ConfigMap" => describe_resource::<ConfigMap>(&client, Some(ns), &args.name).await,
        "Secret" => describe_resource::<Secret>(&client, Some(ns), &args.name).await,
        "StatefulSet" => describe_resource::<StatefulSet>(&client, Some(ns), &args.name).await,
        "DaemonSet" => describe_resource::<DaemonSet>(&client, Some(ns), &args.name).await,
        "ReplicaSet" => describe_resource::<ReplicaSet>(&client, Some(ns), &args.name).await,
        "Node" => describe_resource::<Node>(&client, None, &args.name).await,
        "Namespace" => describe_resource::<Namespace>(&client, None, &args.name).await,
        _ => Err(KcError::InvalidResourceType(format!(
            "describe not supported for {}",
            info.kind
        ))),
    }
}

async fn describe_resource<T>(client: &Client, namespace: Option<&str>, name: &str) -> Result<()>
where
    T: KubeResource + Listable + Describable,
{
    let api: Api<T> = T::api(client.clone(), namespace);
    let resource = api.get(name).await?;
    let description = resource.describe(client).await?;
    println!("{}", description);
    Ok(())
}
