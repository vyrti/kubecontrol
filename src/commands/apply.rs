//! Apply command implementation - apply YAML configurations

use crate::cli::ApplyArgs;
use crate::client::create_client;
use crate::error::{KcError, Result};
use k8s_openapi::api::apps::v1::{DaemonSet, Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::core::v1::{ConfigMap, Namespace, Pod, Secret, Service};
use kube::api::{Patch, PatchParams};
use kube::{Api, Client};
use serde_json::Value;
use std::fs;
use std::io::{self, Read};

/// Run the apply command
pub async fn run_apply(context: Option<&str>, args: &ApplyArgs) -> Result<()> {
    if args.filename.is_empty() {
        return Err(KcError::InvalidArgument(
            "No filename specified. Use -f to specify a file".to_string(),
        ));
    }

    let client = create_client(context).await?;

    for filename in &args.filename {
        let content = read_file_or_stdin(filename)?;

        // Handle multiple YAML documents in a single file
        for doc in serde_yaml::Deserializer::from_str(&content) {
            let value: Value = serde::Deserialize::deserialize(doc).map_err(|e| {
                KcError::Serialization(format!("Failed to parse YAML: {}", e))
            })?;

            if value.is_null() {
                continue; // Skip empty documents
            }

            apply_resource(&client, &value, args.dry_run).await?;
        }
    }

    Ok(())
}

/// Run the create command (similar to apply but uses create semantics)
pub async fn run_create(context: Option<&str>, args: &ApplyArgs) -> Result<()> {
    if args.filename.is_empty() {
        return Err(KcError::InvalidArgument(
            "No filename specified. Use -f to specify a file".to_string(),
        ));
    }

    let client = create_client(context).await?;

    for filename in &args.filename {
        let content = read_file_or_stdin(filename)?;

        for doc in serde_yaml::Deserializer::from_str(&content) {
            let value: Value = serde::Deserialize::deserialize(doc).map_err(|e| {
                KcError::Serialization(format!("Failed to parse YAML: {}", e))
            })?;

            if value.is_null() {
                continue;
            }

            create_resource(&client, &value, args.dry_run).await?;
        }
    }

    Ok(())
}

fn read_file_or_stdin(filename: &str) -> Result<String> {
    if filename == "-" {
        let mut content = String::new();
        io::stdin()
            .read_to_string(&mut content)
            .map_err(|e| KcError::Io(e))?;
        Ok(content)
    } else {
        fs::read_to_string(filename).map_err(|e| KcError::Io(e))
    }
}

async fn apply_resource(client: &Client, value: &Value, dry_run: bool) -> Result<()> {
    let kind = value
        .get("kind")
        .and_then(|k| k.as_str())
        .ok_or_else(|| KcError::InvalidArgument("Missing 'kind' field in YAML".to_string()))?;

    let api_version = value
        .get("apiVersion")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            KcError::InvalidArgument("Missing 'apiVersion' field in YAML".to_string())
        })?;

    let metadata = value
        .get("metadata")
        .ok_or_else(|| KcError::InvalidArgument("Missing 'metadata' field in YAML".to_string()))?;

    let name = metadata
        .get("name")
        .and_then(|n| n.as_str())
        .ok_or_else(|| {
            KcError::InvalidArgument("Missing 'metadata.name' field in YAML".to_string())
        })?;

    let namespace = metadata
        .get("namespace")
        .and_then(|n| n.as_str())
        .unwrap_or("default");

    let mut pp = PatchParams::apply("kc").force();
    if dry_run {
        pp = pp.dry_run();
    }

    match (api_version, kind) {
        ("v1", "Pod") => {
            let api: Api<Pod> = Api::namespaced(client.clone(), namespace);
            api.patch(name, &pp, &Patch::Apply(value)).await?;
        }
        ("v1", "Service") => {
            let api: Api<Service> = Api::namespaced(client.clone(), namespace);
            api.patch(name, &pp, &Patch::Apply(value)).await?;
        }
        ("v1", "ConfigMap") => {
            let api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
            api.patch(name, &pp, &Patch::Apply(value)).await?;
        }
        ("v1", "Secret") => {
            let api: Api<Secret> = Api::namespaced(client.clone(), namespace);
            api.patch(name, &pp, &Patch::Apply(value)).await?;
        }
        ("v1", "Namespace") => {
            let api: Api<Namespace> = Api::all(client.clone());
            api.patch(name, &pp, &Patch::Apply(value)).await?;
        }
        ("apps/v1", "Deployment") => {
            let api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
            api.patch(name, &pp, &Patch::Apply(value)).await?;
        }
        ("apps/v1", "StatefulSet") => {
            let api: Api<StatefulSet> = Api::namespaced(client.clone(), namespace);
            api.patch(name, &pp, &Patch::Apply(value)).await?;
        }
        ("apps/v1", "DaemonSet") => {
            let api: Api<DaemonSet> = Api::namespaced(client.clone(), namespace);
            api.patch(name, &pp, &Patch::Apply(value)).await?;
        }
        ("apps/v1", "ReplicaSet") => {
            let api: Api<ReplicaSet> = Api::namespaced(client.clone(), namespace);
            api.patch(name, &pp, &Patch::Apply(value)).await?;
        }
        _ => {
            return Err(KcError::InvalidResourceType(format!(
                "Unsupported resource type: {}/{}",
                api_version, kind
            )));
        }
    }

    let action = if dry_run {
        "configured (dry run)"
    } else {
        "configured"
    };
    println!("{}.{} {} {}", kind.to_lowercase(), api_version, name, action);

    Ok(())
}

async fn create_resource(client: &Client, value: &Value, dry_run: bool) -> Result<()> {
    let kind = value
        .get("kind")
        .and_then(|k| k.as_str())
        .ok_or_else(|| KcError::InvalidArgument("Missing 'kind' field in YAML".to_string()))?;

    let api_version = value
        .get("apiVersion")
        .and_then(|v| v.as_str())
        .ok_or_else(|| {
            KcError::InvalidArgument("Missing 'apiVersion' field in YAML".to_string())
        })?;

    let metadata = value
        .get("metadata")
        .ok_or_else(|| KcError::InvalidArgument("Missing 'metadata' field in YAML".to_string()))?;

    let name = metadata
        .get("name")
        .and_then(|n| n.as_str())
        .ok_or_else(|| {
            KcError::InvalidArgument("Missing 'metadata.name' field in YAML".to_string())
        })?;

    let namespace = metadata
        .get("namespace")
        .and_then(|n| n.as_str())
        .unwrap_or("default");

    // Use server-side apply for create as well (idempotent)
    let mut pp = PatchParams::apply("kc").force();
    if dry_run {
        pp = pp.dry_run();
    }

    match (api_version, kind) {
        ("v1", "Pod") => {
            let api: Api<Pod> = Api::namespaced(client.clone(), namespace);
            api.patch(name, &pp, &Patch::Apply(value)).await?;
        }
        ("v1", "Service") => {
            let api: Api<Service> = Api::namespaced(client.clone(), namespace);
            api.patch(name, &pp, &Patch::Apply(value)).await?;
        }
        ("v1", "ConfigMap") => {
            let api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
            api.patch(name, &pp, &Patch::Apply(value)).await?;
        }
        ("v1", "Secret") => {
            let api: Api<Secret> = Api::namespaced(client.clone(), namespace);
            api.patch(name, &pp, &Patch::Apply(value)).await?;
        }
        ("v1", "Namespace") => {
            let api: Api<Namespace> = Api::all(client.clone());
            api.patch(name, &pp, &Patch::Apply(value)).await?;
        }
        ("apps/v1", "Deployment") => {
            let api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
            api.patch(name, &pp, &Patch::Apply(value)).await?;
        }
        ("apps/v1", "StatefulSet") => {
            let api: Api<StatefulSet> = Api::namespaced(client.clone(), namespace);
            api.patch(name, &pp, &Patch::Apply(value)).await?;
        }
        ("apps/v1", "DaemonSet") => {
            let api: Api<DaemonSet> = Api::namespaced(client.clone(), namespace);
            api.patch(name, &pp, &Patch::Apply(value)).await?;
        }
        ("apps/v1", "ReplicaSet") => {
            let api: Api<ReplicaSet> = Api::namespaced(client.clone(), namespace);
            api.patch(name, &pp, &Patch::Apply(value)).await?;
        }
        _ => {
            return Err(KcError::InvalidResourceType(format!(
                "Unsupported resource type: {}/{}",
                api_version, kind
            )));
        }
    }

    let action = if dry_run {
        "created (dry run)"
    } else {
        "created"
    };
    println!("{}.{} {} {}", kind.to_lowercase(), api_version, name, action);

    Ok(())
}
