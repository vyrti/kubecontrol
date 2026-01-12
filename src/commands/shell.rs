//! Shell command implementation - open interactive shell in pod

use crate::cli::{ExecArgs, ShellArgs};
use crate::commands::exec::run_exec;
use crate::error::Result;

/// Run the shell command (wrapper around exec with interactive shell)
pub async fn run_shell(
    context: Option<&str>,
    namespace: Option<&str>,
    args: &ShellArgs,
) -> Result<()> {
    // Default to /bin/sh, try bash if specified
    let shell = args.shell.as_deref().unwrap_or("/bin/sh");

    let exec_args = ExecArgs {
        pod: args.pod.clone(),
        container: args.container.clone(),
        command: vec![shell.to_string()],
        tty: true,
        stdin: true,
    };

    run_exec(context, namespace, &exec_args).await
}
