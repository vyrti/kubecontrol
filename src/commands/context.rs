//! Context and namespace switching commands

use crate::cli::OutputFormat;
use crate::client::{list_contexts, ContextInfo};
use crate::error::Result;
use owo_colors::OwoColorize;

/// List or switch contexts
pub fn handle_context(name: Option<&str>, output: OutputFormat) -> Result<()> {
    let contexts = list_contexts()?;

    match name {
        Some(_name) => {
            // TODO: Implement context switching by modifying kubeconfig
            println!("Context switching not yet implemented");
            println!("Use: kubectl config use-context {}", _name);
            Ok(())
        }
        None => {
            // List contexts
            print_contexts(&contexts, output)
        }
    }
}

fn print_contexts(contexts: &[ContextInfo], output: OutputFormat) -> Result<()> {
    match output {
        OutputFormat::Table | OutputFormat::Wide => {
            println!(
                "{:2} {:30} {:30} {:20}",
                "", "NAME".bold(), "CLUSTER".bold(), "NAMESPACE".bold()
            );

            for ctx in contexts {
                let marker = if ctx.is_current { "*" } else { "" };
                let cluster = ctx.cluster.as_deref().unwrap_or("");
                let namespace = ctx.namespace.as_deref().unwrap_or("");

                if ctx.is_current {
                    println!(
                        "{:2} {:30} {:30} {:20}",
                        marker.green(),
                        ctx.name.green(),
                        cluster.green(),
                        namespace.green()
                    );
                } else {
                    println!("{:2} {:30} {:30} {:20}", marker, ctx.name, cluster, namespace);
                }
            }
        }
        OutputFormat::Name => {
            for ctx in contexts {
                println!("{}", ctx.name);
            }
        }
        OutputFormat::Json => {
            let json: Vec<_> = contexts
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "name": c.name,
                        "cluster": c.cluster,
                        "namespace": c.namespace,
                        "current": c.is_current
                    })
                })
                .collect();
            println!("{}", serde_json::to_string_pretty(&json)?);
        }
        OutputFormat::Yaml => {
            let yaml: Vec<_> = contexts
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "name": c.name,
                        "cluster": c.cluster,
                        "namespace": c.namespace,
                        "current": c.is_current
                    })
                })
                .collect();
            println!("{}", serde_yaml::to_string(&yaml)?);
        }
    }

    Ok(())
}

/// List namespaces available in the cluster
pub async fn handle_ns(
    context: Option<&str>,
    name: Option<&str>,
    output: OutputFormat,
) -> Result<()> {
    use crate::cli::ListArgs;
    use crate::commands::list_namespaces;

    match name {
        Some(_name) => {
            // TODO: Implement namespace switching
            println!("Namespace switching not yet implemented");
            println!("Use: -n {} with your commands", _name);
            Ok(())
        }
        None => {
            // List namespaces
            let args = ListArgs {
                selector: None,
                field_selector: None,
                all_namespaces: false,
                wide: false,
            };
            list_namespaces(context, &args, output).await
        }
    }
}
