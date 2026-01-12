//! Restart command implementation

use crate::cli::RestartArgs;
use crate::client::create_client;
use crate::error::{KcError, Result};
use crate::resources::Rollable;
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, StatefulSet};
use kube::Api;

/// Run the restart command (triggers a rollout restart)
pub async fn run_restart(
    context: Option<&str>,
    namespace: Option<&str>,
    args: &RestartArgs,
) -> Result<()> {
    let client = create_client(context).await?;
    let ns = namespace.unwrap_or("default");

    let resource_type = args.resource_type.to_lowercase();

    match resource_type.as_str() {
        "deployment" | "deploy" | "deployments" => {
            let api: Api<Deployment> = Api::namespaced(client, ns);
            Deployment::restart(&api, &args.name).await?;
            println!("deployment.apps/{} restarted", args.name);
        }
        "statefulset" | "sts" | "statefulsets" => {
            let api: Api<StatefulSet> = Api::namespaced(client, ns);
            StatefulSet::restart(&api, &args.name).await?;
            println!("statefulset.apps/{} restarted", args.name);
        }
        "daemonset" | "ds" | "daemonsets" => {
            let api: Api<DaemonSet> = Api::namespaced(client, ns);
            DaemonSet::restart(&api, &args.name).await?;
            println!("daemonset.apps/{} restarted", args.name);
        }
        _ => {
            return Err(KcError::InvalidArgument(format!(
                "Cannot restart resource type '{}'. Supported types: deployment, statefulset, daemonset",
                args.resource_type
            )));
        }
    }

    Ok(())
}
