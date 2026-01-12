//! Delete command implementation

use crate::cli::DeleteArgs;
use crate::client::create_client;
use crate::error::{KcError, Result};
use crate::resources::{KubeResource, Listable, RESOURCE_REGISTRY};
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::core::v1::{ConfigMap, Namespace, Node, Pod, Secret, Service};
use kube::api::DeleteParams;
use kube::{Api, Client};
use std::io::{self, Write};

/// Run the delete command
pub async fn run_delete(
    context: Option<&str>,
    namespace: Option<&str>,
    args: &DeleteArgs,
) -> Result<()> {
    let client = create_client(context).await?;
    let ns = namespace.unwrap_or("default");

    let info = RESOURCE_REGISTRY
        .lookup(&args.resource_type)
        .ok_or_else(|| KcError::InvalidResourceType(args.resource_type.clone()))?;

    if args.names.is_empty() {
        return Err(KcError::InvalidArgument(
            "No resource names specified".to_string(),
        ));
    }

    // Confirmation prompt unless --yes
    if !args.yes {
        print!(
            "Delete {} {}? [y/N]: ",
            info.kind,
            args.names.join(", ")
        );
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;

        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted");
            return Ok(());
        }
    }

    // Build delete params
    let mut dp = DeleteParams::default();
    if let Some(grace) = args.grace_period {
        dp = dp.grace_period(grace as u32);
    }
    if args.force {
        dp = dp.grace_period(0);
    }

    // Delete each resource
    for name in &args.names {
        match info.kind {
            "Pod" => delete_resource::<Pod>(&client, Some(ns), name, &dp).await?,
            "Deployment" => delete_resource::<Deployment>(&client, Some(ns), name, &dp).await?,
            "Service" => delete_resource::<Service>(&client, Some(ns), name, &dp).await?,
            "ConfigMap" => delete_resource::<ConfigMap>(&client, Some(ns), name, &dp).await?,
            "Secret" => delete_resource::<Secret>(&client, Some(ns), name, &dp).await?,
            "StatefulSet" => delete_resource::<StatefulSet>(&client, Some(ns), name, &dp).await?,
            "DaemonSet" => delete_resource::<DaemonSet>(&client, Some(ns), name, &dp).await?,
            "ReplicaSet" => delete_resource::<ReplicaSet>(&client, Some(ns), name, &dp).await?,
            "Node" => delete_resource::<Node>(&client, None, name, &dp).await?,
            "Namespace" => delete_resource::<Namespace>(&client, None, name, &dp).await?,
            _ => {
                return Err(KcError::InvalidResourceType(format!(
                    "delete not supported for {}",
                    info.kind
                )))
            }
        }
        println!("{} \"{}\" deleted", info.kind.to_lowercase(), name);
    }

    Ok(())
}

async fn delete_resource<T>(
    client: &Client,
    namespace: Option<&str>,
    name: &str,
    dp: &DeleteParams,
) -> Result<()>
where
    T: KubeResource + Listable,
{
    let api: Api<T> = T::api(client.clone(), namespace);
    api.delete(name, dp).await?;
    Ok(())
}
