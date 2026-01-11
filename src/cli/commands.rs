//! CLI command definitions using clap

use clap::{Parser, Subcommand, Args, ValueEnum};

#[derive(Parser)]
#[command(
    name = "kc",
    author = "Aleksei Zaitsev",
    version,
    about = "A fast, user-friendly Kubernetes CLI tool",
    long_about = None,
)]
pub struct Cli {
    /// Kubernetes context to use
    #[arg(long, global = true, env = "KC_CONTEXT")]
    pub context: Option<String>,

    /// Namespace to use
    #[arg(short = 'n', long, global = true, env = "KC_NAMESPACE")]
    pub namespace: Option<String>,

    /// Output format
    #[arg(short = 'o', long, global = true, value_enum, default_value = "table")]
    pub output: OutputFormat,

    /// Enable verbose logging
    #[arg(short = 'v', long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Disable colored output
    #[arg(long, global = true)]
    pub no_color: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    #[default]
    Table,
    Json,
    Yaml,
    Wide,
    Name,
}

#[derive(Subcommand)]
pub enum Command {
    // === Resource Listing ===
    /// List pods
    #[command(alias = "po")]
    Pods(ListArgs),

    /// List deployments
    #[command(alias = "deploy")]
    Deployments(ListArgs),

    /// List services
    #[command(alias = "svc")]
    Services(ListArgs),

    /// List configmaps
    #[command(alias = "cm")]
    Configmaps(ListArgs),

    /// List secrets
    Secrets(ListArgs),

    /// List namespaces
    Namespaces(ListArgs),

    /// List nodes
    #[command(alias = "no")]
    Nodes(ListArgs),

    /// List replicasets
    #[command(alias = "rs")]
    Replicasets(ListArgs),

    /// List statefulsets
    #[command(alias = "sts")]
    Statefulsets(ListArgs),

    /// List daemonsets
    #[command(alias = "ds")]
    Daemonsets(ListArgs),

    // === Generic Resource Access ===
    /// Get any resource type
    Get(GetArgs),

    /// Describe resource in detail
    Describe(DescribeArgs),

    // === Pod Operations ===
    /// View pod logs
    Logs(LogsArgs),

    /// Execute command in pod
    Exec(ExecArgs),

    /// Open interactive shell in pod
    Shell(ShellArgs),

    /// Forward local port to pod
    #[command(alias = "pf")]
    PortForward(PortForwardArgs),

    // === Resource Modification ===
    /// Delete resources
    Delete(DeleteArgs),

    /// Apply configuration from file
    Apply(ApplyArgs),

    /// Create resource from file
    Create(ApplyArgs),

    /// Scale deployment/statefulset
    Scale(ScaleArgs),

    /// Restart deployment/statefulset/daemonset
    Restart(RestartArgs),

    // === Context & Namespace ===
    /// List/switch contexts
    #[command(alias = "ctx")]
    Context(ContextArgs),

    /// List/switch namespaces
    Ns(NsArgs),

    // === Completions ===
    /// Generate shell completions
    Completions(CompletionsArgs),

    // === Web UI ===
    /// Start web dashboard
    Ui(UiArgs),
}

#[derive(Args, Clone)]
pub struct ListArgs {
    /// Filter by labels (key=value)
    #[arg(short = 'l', long)]
    pub selector: Option<String>,

    /// Filter by field selector
    #[arg(long)]
    pub field_selector: Option<String>,

    /// Show all namespaces
    #[arg(short = 'A', long)]
    pub all_namespaces: bool,

    /// Show wide output with additional columns
    #[arg(short = 'w', long)]
    pub wide: bool,
}

#[derive(Args)]
pub struct GetArgs {
    /// Resource type (pod, deployment, service, etc.)
    pub resource_type: String,

    /// Resource name (optional, lists all if omitted)
    pub name: Option<String>,

    #[command(flatten)]
    pub list_args: ListArgs,
}

#[derive(Args)]
pub struct DescribeArgs {
    /// Resource type
    pub resource_type: String,

    /// Resource name
    pub name: String,
}

#[derive(Args)]
pub struct LogsArgs {
    /// Pod name (supports fuzzy matching)
    pub pod: String,

    /// Container name
    #[arg(short = 'c', long)]
    pub container: Option<String>,

    /// Follow log output
    #[arg(short = 'f', long)]
    pub follow: bool,

    /// Number of lines to show from the end
    #[arg(long, default_value = "100")]
    pub tail: i64,

    /// Show logs since duration (e.g., 1h, 30m, 10s)
    #[arg(long)]
    pub since: Option<String>,

    /// Show timestamps
    #[arg(long)]
    pub timestamps: bool,

    /// Include previous container logs
    #[arg(short = 'p', long)]
    pub previous: bool,
}

#[derive(Args)]
pub struct ExecArgs {
    /// Pod name
    pub pod: String,

    /// Command to execute
    #[arg(last = true)]
    pub command: Vec<String>,

    /// Container name
    #[arg(short = 'c', long)]
    pub container: Option<String>,

    /// Enable TTY
    #[arg(short = 't', long)]
    pub tty: bool,

    /// Pass stdin
    #[arg(short = 'i', long)]
    pub stdin: bool,
}

#[derive(Args)]
pub struct ShellArgs {
    /// Pod name
    pub pod: String,

    /// Container name
    #[arg(short = 'c', long)]
    pub container: Option<String>,

    /// Shell to use (default: auto-detect bash/sh)
    #[arg(long)]
    pub shell: Option<String>,
}

#[derive(Args)]
pub struct PortForwardArgs {
    /// Pod name
    pub pod: String,

    /// Port mapping (local:remote or just remote)
    pub ports: Vec<String>,

    /// Local address to bind
    #[arg(long, default_value = "127.0.0.1")]
    pub address: String,
}

#[derive(Args)]
pub struct DeleteArgs {
    /// Resource type
    pub resource_type: String,

    /// Resource name(s)
    pub names: Vec<String>,

    /// Skip confirmation
    #[arg(short = 'y', long)]
    pub yes: bool,

    /// Grace period in seconds
    #[arg(long)]
    pub grace_period: Option<i64>,

    /// Force deletion
    #[arg(long)]
    pub force: bool,
}

#[derive(Args)]
pub struct ApplyArgs {
    /// File or directory path
    #[arg(short = 'f', long)]
    pub filename: Vec<String>,

    /// Recursive directory processing
    #[arg(short = 'R', long)]
    pub recursive: bool,

    /// Dry run mode
    #[arg(long)]
    pub dry_run: bool,
}

#[derive(Args)]
pub struct ScaleArgs {
    /// Resource type (deployment, statefulset, replicaset)
    pub resource_type: String,

    /// Resource name
    pub name: String,

    /// Number of replicas
    #[arg(long)]
    pub replicas: i32,
}

#[derive(Args)]
pub struct RestartArgs {
    /// Resource type (deployment, statefulset, daemonset)
    pub resource_type: String,

    /// Resource name
    pub name: String,
}

#[derive(Args)]
pub struct ContextArgs {
    /// Context to switch to (omit to list)
    pub name: Option<String>,
}

#[derive(Args)]
pub struct NsArgs {
    /// Namespace to switch to (omit to list)
    pub name: Option<String>,
}

#[derive(Args)]
pub struct CompletionsArgs {
    /// Shell to generate completions for
    #[arg(value_enum)]
    pub shell: clap_complete::Shell,
}

#[derive(Args)]
pub struct UiArgs {
    /// Port to run the dashboard on
    #[arg(short = 'p', long, default_value = "9090")]
    pub port: u16,

    /// Don't open browser automatically
    #[arg(long)]
    pub no_open: bool,
}
