//! Scale command implementation

use crate::cli::ScaleArgs;
use crate::client::create_client;
use crate::error::{KcError, Result};
use crate::resources::Scalable;
use k8s_openapi::api::apps::v1::{Deployment, ReplicaSet, StatefulSet};
use kube::Api;

/// Run the scale command
pub async fn run_scale(
    context: Option<&str>,
    namespace: Option<&str>,
    args: &ScaleArgs,
) -> Result<()> {
    let client = create_client(context).await?;
    let ns = namespace.unwrap_or("default");

    let resource_type = args.resource_type.to_lowercase();

    match resource_type.as_str() {
        "deployment" | "deploy" | "deployments" => {
            let api: Api<Deployment> = Api::namespaced(client, ns);
            Deployment::scale(&api, &args.name, args.replicas).await?;
            println!(
                "deployment.apps/{} scaled to {} replicas",
                args.name, args.replicas
            );
        }
        "statefulset" | "sts" | "statefulsets" => {
            let api: Api<StatefulSet> = Api::namespaced(client, ns);
            StatefulSet::scale(&api, &args.name, args.replicas).await?;
            println!(
                "statefulset.apps/{} scaled to {} replicas",
                args.name, args.replicas
            );
        }
        "replicaset" | "rs" | "replicasets" => {
            let api: Api<ReplicaSet> = Api::namespaced(client, ns);
            ReplicaSet::scale(&api, &args.name, args.replicas).await?;
            println!(
                "replicaset.apps/{} scaled to {} replicas",
                args.name, args.replicas
            );
        }
        _ => {
            return Err(KcError::InvalidArgument(format!(
                "Cannot scale resource type '{}'. Supported types: deployment, statefulset, replicaset",
                args.resource_type
            )));
        }
    }

    Ok(())
}
