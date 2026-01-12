//! kubecontrol (kc) - A fast, user-friendly Kubernetes CLI tool

use anyhow::Result;
use clap::Parser;
use kubecontrol::cli::{Cli, Command, OutputFormat};
use kubecontrol::commands;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Setup tracing
    setup_tracing(cli.verbose);

    // Handle color settings
    if cli.no_color {
        owo_colors::set_override(false);
    }

    // Get effective output format
    let output = if cli.output == OutputFormat::Table && matches!(&cli.command, Command::Pods(a) | Command::Deployments(a) | Command::Services(a) | Command::Configmaps(a) | Command::Secrets(a) | Command::Namespaces(a) | Command::Nodes(a) | Command::Replicasets(a) | Command::Statefulsets(a) | Command::Daemonsets(a) if a.wide) {
        OutputFormat::Wide
    } else {
        cli.output
    };

    // Execute command
    let result = match cli.command {
        Command::Pods(ref args) => {
            commands::list_pods(
                cli.context.as_deref(),
                cli.namespace.as_deref(),
                args,
                output,
            )
            .await
        }
        Command::Deployments(ref args) => {
            commands::list_deployments(
                cli.context.as_deref(),
                cli.namespace.as_deref(),
                args,
                output,
            )
            .await
        }
        Command::Services(ref args) => {
            commands::list_services(
                cli.context.as_deref(),
                cli.namespace.as_deref(),
                args,
                output,
            )
            .await
        }
        Command::Configmaps(ref args) => {
            commands::list_configmaps(
                cli.context.as_deref(),
                cli.namespace.as_deref(),
                args,
                output,
            )
            .await
        }
        Command::Secrets(ref args) => {
            commands::list_secrets(
                cli.context.as_deref(),
                cli.namespace.as_deref(),
                args,
                output,
            )
            .await
        }
        Command::Namespaces(ref args) => {
            commands::list_namespaces(cli.context.as_deref(), args, output).await
        }
        Command::Nodes(ref args) => {
            commands::list_nodes(cli.context.as_deref(), args, output).await
        }
        Command::Replicasets(ref args) => {
            commands::list_replicasets(
                cli.context.as_deref(),
                cli.namespace.as_deref(),
                args,
                output,
            )
            .await
        }
        Command::Statefulsets(ref args) => {
            commands::list_statefulsets(
                cli.context.as_deref(),
                cli.namespace.as_deref(),
                args,
                output,
            )
            .await
        }
        Command::Daemonsets(ref args) => {
            commands::list_daemonsets(
                cli.context.as_deref(),
                cli.namespace.as_deref(),
                args,
                output,
            )
            .await
        }
        Command::Get(ref _args) => {
            eprintln!("'get' command not yet implemented");
            Ok(())
        }
        Command::Describe(ref _args) => {
            eprintln!("'describe' command not yet implemented");
            Ok(())
        }
        Command::Logs(ref _args) => {
            eprintln!("'logs' command not yet implemented");
            Ok(())
        }
        Command::Exec(ref _args) => {
            eprintln!("'exec' command not yet implemented");
            Ok(())
        }
        Command::Shell(ref _args) => {
            eprintln!("'shell' command not yet implemented");
            Ok(())
        }
        Command::PortForward(ref _args) => {
            eprintln!("'port-forward' command not yet implemented");
            Ok(())
        }
        Command::Delete(ref _args) => {
            eprintln!("'delete' command not yet implemented");
            Ok(())
        }
        Command::Apply(ref _args) => {
            eprintln!("'apply' command not yet implemented");
            Ok(())
        }
        Command::Create(ref _args) => {
            eprintln!("'create' command not yet implemented");
            Ok(())
        }
        Command::Scale(ref _args) => {
            eprintln!("'scale' command not yet implemented");
            Ok(())
        }
        Command::Restart(ref _args) => {
            eprintln!("'restart' command not yet implemented");
            Ok(())
        }
        Command::Context(ref args) => {
            commands::handle_context(args.name.as_deref(), output)
        }
        Command::Ns(ref args) => {
            commands::handle_ns(cli.context.as_deref(), args.name.as_deref(), output).await
        }
        Command::Completions(ref args) => {
            generate_completions(args.shell);
            Ok(())
        }
        Command::Ui(ref args) => {
            kubecontrol::web::start_server(
                args.port,
                cli.context.clone(),
                cli.namespace.clone(),
                !args.no_open,
            )
            .await
        }
        Command::Debug(ref args) => {
            commands::run_debug(
                cli.context.as_deref(),
                cli.namespace.as_deref(),
                args,
                output,
            )
            .await
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }

    Ok(())
}

fn setup_tracing(verbose: u8) {
    let filter = match verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    tracing_subscriber::registry()
        .with(EnvFilter::try_from_default_env().unwrap_or_else(|_| filter.into()))
        .with(tracing_subscriber::fmt::layer().with_target(false))
        .init();
}

fn generate_completions(shell: clap_complete::Shell) {
    use clap::CommandFactory;
    use clap_complete::generate;

    let mut cmd = Cli::command();
    generate(shell, &mut cmd, "kc", &mut std::io::stdout());
}
