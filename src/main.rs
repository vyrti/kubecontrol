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
        Command::Get(ref args) => {
            commands::run_get(
                cli.context.as_deref(),
                cli.namespace.as_deref(),
                args,
                output,
            )
            .await
        }
        Command::Describe(ref args) => {
            commands::run_describe(
                cli.context.as_deref(),
                cli.namespace.as_deref(),
                args,
            )
            .await
        }
        Command::Logs(ref args) => {
            commands::run_logs(
                cli.context.as_deref(),
                cli.namespace.as_deref(),
                args,
            )
            .await
        }
        Command::Exec(ref args) => {
            commands::run_exec(
                cli.context.as_deref(),
                cli.namespace.as_deref(),
                args,
            )
            .await
        }
        Command::Shell(ref args) => {
            commands::run_shell(
                cli.context.as_deref(),
                cli.namespace.as_deref(),
                args,
            )
            .await
        }
        Command::PortForward(ref args) => {
            commands::run_port_forward(
                cli.context.as_deref(),
                cli.namespace.as_deref(),
                args,
            )
            .await
        }
        Command::Delete(ref args) => {
            commands::run_delete(
                cli.context.as_deref(),
                cli.namespace.as_deref(),
                args,
            )
            .await
        }
        Command::Apply(ref args) => {
            commands::run_apply(cli.context.as_deref(), args).await
        }
        Command::Create(ref args) => {
            commands::run_create(cli.context.as_deref(), args).await
        }
        Command::Scale(ref args) => {
            commands::run_scale(
                cli.context.as_deref(),
                cli.namespace.as_deref(),
                args,
            )
            .await
        }
        Command::Restart(ref args) => {
            commands::run_restart(
                cli.context.as_deref(),
                cli.namespace.as_deref(),
                args,
            )
            .await
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
        Command::Version(ref args) => {
            commands::run_version(cli.context.as_deref(), args, output).await
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
