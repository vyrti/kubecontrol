//! List command implementation

use crate::cli::{ListArgs, OutputFormat};
use crate::client::create_client;
use crate::error::Result;
use crate::output::{format_json, format_names, format_table, format_yaml};
use crate::resources::{Listable, Tabular};

/// Generic list command for any resource type
pub async fn list_resources<T>(
    context: Option<&str>,
    namespace: Option<&str>,
    args: &ListArgs,
    output: OutputFormat,
) -> Result<()>
where
    T: Listable + Tabular + serde::Serialize,
{
    let client = create_client(context).await?;

    let api = if args.all_namespaces && T::NAMESPACED {
        T::api_all(client)
    } else {
        T::api(client, namespace)
    };

    let resources = T::list_resources(
        &api,
        args.selector.as_deref(),
        args.field_selector.as_deref(),
    )
    .await?;

    let output_str = match output {
        OutputFormat::Table => format_table(&resources, false),
        OutputFormat::Wide => format_table(&resources, true),
        OutputFormat::Json => format_json(&resources, true)?,
        OutputFormat::Yaml => format_yaml(&resources)?,
        OutputFormat::Name => format_names(&resources),
    };

    println!("{}", output_str);
    Ok(())
}

/// List pods
pub async fn list_pods(
    context: Option<&str>,
    namespace: Option<&str>,
    args: &ListArgs,
    output: OutputFormat,
) -> Result<()> {
    use k8s_openapi::api::core::v1::Pod;
    list_resources::<Pod>(context, namespace, args, output).await
}

/// List deployments
pub async fn list_deployments(
    context: Option<&str>,
    namespace: Option<&str>,
    args: &ListArgs,
    output: OutputFormat,
) -> Result<()> {
    use k8s_openapi::api::apps::v1::Deployment;
    list_resources::<Deployment>(context, namespace, args, output).await
}

/// List services
pub async fn list_services(
    context: Option<&str>,
    namespace: Option<&str>,
    args: &ListArgs,
    output: OutputFormat,
) -> Result<()> {
    use k8s_openapi::api::core::v1::Service;
    list_resources::<Service>(context, namespace, args, output).await
}

/// List configmaps
pub async fn list_configmaps(
    context: Option<&str>,
    namespace: Option<&str>,
    args: &ListArgs,
    output: OutputFormat,
) -> Result<()> {
    use k8s_openapi::api::core::v1::ConfigMap;
    list_resources::<ConfigMap>(context, namespace, args, output).await
}

/// List secrets
pub async fn list_secrets(
    context: Option<&str>,
    namespace: Option<&str>,
    args: &ListArgs,
    output: OutputFormat,
) -> Result<()> {
    use k8s_openapi::api::core::v1::Secret;
    list_resources::<Secret>(context, namespace, args, output).await
}

/// List namespaces
pub async fn list_namespaces(
    context: Option<&str>,
    args: &ListArgs,
    output: OutputFormat,
) -> Result<()> {
    use k8s_openapi::api::core::v1::Namespace;
    list_resources::<Namespace>(context, None, args, output).await
}

/// List nodes
pub async fn list_nodes(
    context: Option<&str>,
    args: &ListArgs,
    output: OutputFormat,
) -> Result<()> {
    use k8s_openapi::api::core::v1::Node;
    list_resources::<Node>(context, None, args, output).await
}

/// List replicasets
pub async fn list_replicasets(
    context: Option<&str>,
    namespace: Option<&str>,
    args: &ListArgs,
    output: OutputFormat,
) -> Result<()> {
    use k8s_openapi::api::apps::v1::ReplicaSet;
    list_resources::<ReplicaSet>(context, namespace, args, output).await
}

/// List statefulsets
pub async fn list_statefulsets(
    context: Option<&str>,
    namespace: Option<&str>,
    args: &ListArgs,
    output: OutputFormat,
) -> Result<()> {
    use k8s_openapi::api::apps::v1::StatefulSet;
    list_resources::<StatefulSet>(context, namespace, args, output).await
}

/// List daemonsets
pub async fn list_daemonsets(
    context: Option<&str>,
    namespace: Option<&str>,
    args: &ListArgs,
    output: OutputFormat,
) -> Result<()> {
    use k8s_openapi::api::apps::v1::DaemonSet;
    list_resources::<DaemonSet>(context, namespace, args, output).await
}
