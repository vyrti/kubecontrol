//! CLI parsing tests for kc command line interface

use clap::Parser;
use kubecontrol::cli::{Cli, Command, OutputFormat};

// ============================================================================
// Basic command parsing tests
// ============================================================================

#[test]
fn test_parse_pods_command() {
    let args = Cli::parse_from(["kc", "pods"]);
    assert!(matches!(args.command, Command::Pods(_)));
}

#[test]
fn test_parse_pods_alias_po() {
    let args = Cli::parse_from(["kc", "po"]);
    assert!(matches!(args.command, Command::Pods(_)));
}

#[test]
fn test_parse_deployments_command() {
    let args = Cli::parse_from(["kc", "deployments"]);
    assert!(matches!(args.command, Command::Deployments(_)));
}

#[test]
fn test_parse_deployments_alias_deploy() {
    let args = Cli::parse_from(["kc", "deploy"]);
    assert!(matches!(args.command, Command::Deployments(_)));
}

#[test]
fn test_parse_services_command() {
    let args = Cli::parse_from(["kc", "services"]);
    assert!(matches!(args.command, Command::Services(_)));
}

#[test]
fn test_parse_services_alias_svc() {
    let args = Cli::parse_from(["kc", "svc"]);
    assert!(matches!(args.command, Command::Services(_)));
}

#[test]
fn test_parse_configmaps_command() {
    let args = Cli::parse_from(["kc", "configmaps"]);
    assert!(matches!(args.command, Command::Configmaps(_)));
}

#[test]
fn test_parse_configmaps_alias_cm() {
    let args = Cli::parse_from(["kc", "cm"]);
    assert!(matches!(args.command, Command::Configmaps(_)));
}

#[test]
fn test_parse_secrets_command() {
    let args = Cli::parse_from(["kc", "secrets"]);
    assert!(matches!(args.command, Command::Secrets(_)));
}

#[test]
fn test_parse_namespaces_command() {
    let args = Cli::parse_from(["kc", "namespaces"]);
    assert!(matches!(args.command, Command::Namespaces(_)));
}

#[test]
fn test_parse_nodes_command() {
    let args = Cli::parse_from(["kc", "nodes"]);
    assert!(matches!(args.command, Command::Nodes(_)));
}

#[test]
fn test_parse_nodes_alias_no() {
    let args = Cli::parse_from(["kc", "no"]);
    assert!(matches!(args.command, Command::Nodes(_)));
}

#[test]
fn test_parse_statefulsets_command() {
    let args = Cli::parse_from(["kc", "statefulsets"]);
    assert!(matches!(args.command, Command::Statefulsets(_)));
}

#[test]
fn test_parse_statefulsets_alias_sts() {
    let args = Cli::parse_from(["kc", "sts"]);
    assert!(matches!(args.command, Command::Statefulsets(_)));
}

#[test]
fn test_parse_daemonsets_command() {
    let args = Cli::parse_from(["kc", "daemonsets"]);
    assert!(matches!(args.command, Command::Daemonsets(_)));
}

#[test]
fn test_parse_daemonsets_alias_ds() {
    let args = Cli::parse_from(["kc", "ds"]);
    assert!(matches!(args.command, Command::Daemonsets(_)));
}

#[test]
fn test_parse_replicasets_command() {
    let args = Cli::parse_from(["kc", "replicasets"]);
    assert!(matches!(args.command, Command::Replicasets(_)));
}

#[test]
fn test_parse_replicasets_alias_rs() {
    let args = Cli::parse_from(["kc", "rs"]);
    assert!(matches!(args.command, Command::Replicasets(_)));
}

// ============================================================================
// Namespace flag tests
// ============================================================================

#[test]
fn test_parse_pods_with_namespace() {
    let args = Cli::parse_from(["kc", "-n", "kube-system", "pods"]);
    assert_eq!(args.namespace, Some("kube-system".to_string()));
    assert!(matches!(args.command, Command::Pods(_)));
}

#[test]
fn test_parse_pods_with_namespace_long_flag() {
    let args = Cli::parse_from(["kc", "--namespace", "kube-system", "pods"]);
    assert_eq!(args.namespace, Some("kube-system".to_string()));
}

#[test]
fn test_parse_pods_all_namespaces() {
    let args = Cli::parse_from(["kc", "pods", "-A"]);
    if let Command::Pods(list_args) = args.command {
        assert!(list_args.all_namespaces);
    } else {
        panic!("Expected Pods command");
    }
}

#[test]
fn test_parse_pods_all_namespaces_long_flag() {
    let args = Cli::parse_from(["kc", "pods", "--all-namespaces"]);
    if let Command::Pods(list_args) = args.command {
        assert!(list_args.all_namespaces);
    } else {
        panic!("Expected Pods command");
    }
}

// ============================================================================
// Output format tests
// ============================================================================

#[test]
fn test_parse_default_output_format() {
    let args = Cli::parse_from(["kc", "pods"]);
    assert_eq!(args.output, OutputFormat::Table);
}

#[test]
fn test_parse_output_json() {
    let args = Cli::parse_from(["kc", "-o", "json", "pods"]);
    assert_eq!(args.output, OutputFormat::Json);
}

#[test]
fn test_parse_output_yaml() {
    let args = Cli::parse_from(["kc", "-o", "yaml", "pods"]);
    assert_eq!(args.output, OutputFormat::Yaml);
}

#[test]
fn test_parse_output_wide() {
    let args = Cli::parse_from(["kc", "-o", "wide", "pods"]);
    assert_eq!(args.output, OutputFormat::Wide);
}

#[test]
fn test_parse_output_name() {
    let args = Cli::parse_from(["kc", "-o", "name", "pods"]);
    assert_eq!(args.output, OutputFormat::Name);
}

#[test]
fn test_parse_output_long_flag() {
    let args = Cli::parse_from(["kc", "--output", "json", "pods"]);
    assert_eq!(args.output, OutputFormat::Json);
}

#[test]
fn test_parse_wide_shortcut() {
    let args = Cli::parse_from(["kc", "pods", "-w"]);
    if let Command::Pods(list_args) = args.command {
        assert!(list_args.wide);
    } else {
        panic!("Expected Pods command");
    }
}

// ============================================================================
// Context flag tests
// ============================================================================

#[test]
fn test_parse_context() {
    let args = Cli::parse_from(["kc", "--context", "my-cluster", "pods"]);
    assert_eq!(args.context, Some("my-cluster".to_string()));
}

// ============================================================================
// Verbose flag tests
// ============================================================================

#[test]
fn test_parse_verbose() {
    let args = Cli::parse_from(["kc", "-v", "pods"]);
    assert_eq!(args.verbose, 1);
}

#[test]
fn test_parse_verbose_double() {
    let args = Cli::parse_from(["kc", "-vv", "pods"]);
    assert_eq!(args.verbose, 2);
}

#[test]
fn test_parse_verbose_triple() {
    let args = Cli::parse_from(["kc", "-vvv", "pods"]);
    assert_eq!(args.verbose, 3);
}

// ============================================================================
// Label selector tests
// ============================================================================

#[test]
fn test_parse_label_selector() {
    let args = Cli::parse_from(["kc", "pods", "-l", "app=nginx"]);
    if let Command::Pods(list_args) = args.command {
        assert_eq!(list_args.selector, Some("app=nginx".to_string()));
    } else {
        panic!("Expected Pods command");
    }
}

#[test]
fn test_parse_label_selector_long() {
    let args = Cli::parse_from(["kc", "pods", "--selector", "app=nginx,env=prod"]);
    if let Command::Pods(list_args) = args.command {
        assert_eq!(list_args.selector, Some("app=nginx,env=prod".to_string()));
    } else {
        panic!("Expected Pods command");
    }
}

#[test]
fn test_parse_field_selector() {
    let args = Cli::parse_from(["kc", "pods", "--field-selector", "status.phase=Running"]);
    if let Command::Pods(list_args) = args.command {
        assert_eq!(list_args.field_selector, Some("status.phase=Running".to_string()));
    } else {
        panic!("Expected Pods command");
    }
}

// ============================================================================
// Logs command tests
// ============================================================================

#[test]
fn test_parse_logs_command() {
    let args = Cli::parse_from(["kc", "logs", "my-pod"]);
    if let Command::Logs(logs_args) = args.command {
        assert_eq!(logs_args.pod, "my-pod");
    } else {
        panic!("Expected Logs command");
    }
}

#[test]
fn test_parse_logs_with_follow() {
    let args = Cli::parse_from(["kc", "logs", "my-pod", "-f"]);
    if let Command::Logs(logs_args) = args.command {
        assert!(logs_args.follow);
    } else {
        panic!("Expected Logs command");
    }
}

#[test]
fn test_parse_logs_with_tail() {
    let args = Cli::parse_from(["kc", "logs", "my-pod", "--tail", "50"]);
    if let Command::Logs(logs_args) = args.command {
        assert_eq!(logs_args.tail, 50);
    } else {
        panic!("Expected Logs command");
    }
}

#[test]
fn test_parse_logs_with_container() {
    let args = Cli::parse_from(["kc", "logs", "my-pod", "-c", "sidecar"]);
    if let Command::Logs(logs_args) = args.command {
        assert_eq!(logs_args.container, Some("sidecar".to_string()));
    } else {
        panic!("Expected Logs command");
    }
}

#[test]
fn test_parse_logs_with_since() {
    let args = Cli::parse_from(["kc", "logs", "my-pod", "--since", "1h"]);
    if let Command::Logs(logs_args) = args.command {
        assert_eq!(logs_args.since, Some("1h".to_string()));
    } else {
        panic!("Expected Logs command");
    }
}

#[test]
fn test_parse_logs_with_timestamps() {
    let args = Cli::parse_from(["kc", "logs", "my-pod", "--timestamps"]);
    if let Command::Logs(logs_args) = args.command {
        assert!(logs_args.timestamps);
    } else {
        panic!("Expected Logs command");
    }
}

#[test]
fn test_parse_logs_with_previous() {
    let args = Cli::parse_from(["kc", "logs", "my-pod", "-p"]);
    if let Command::Logs(logs_args) = args.command {
        assert!(logs_args.previous);
    } else {
        panic!("Expected Logs command");
    }
}

// ============================================================================
// Exec command tests
// ============================================================================

#[test]
fn test_parse_exec_command() {
    let args = Cli::parse_from(["kc", "exec", "my-pod", "--", "/bin/sh"]);
    if let Command::Exec(exec_args) = args.command {
        assert_eq!(exec_args.pod, "my-pod");
        assert_eq!(exec_args.command, vec!["/bin/sh"]);
    } else {
        panic!("Expected Exec command");
    }
}

#[test]
fn test_parse_exec_with_container() {
    let args = Cli::parse_from(["kc", "exec", "my-pod", "-c", "sidecar", "--", "ls", "-la"]);
    if let Command::Exec(exec_args) = args.command {
        assert_eq!(exec_args.container, Some("sidecar".to_string()));
        assert_eq!(exec_args.command, vec!["ls", "-la"]);
    } else {
        panic!("Expected Exec command");
    }
}

#[test]
fn test_parse_exec_with_tty() {
    let args = Cli::parse_from(["kc", "exec", "my-pod", "-t", "--", "/bin/bash"]);
    if let Command::Exec(exec_args) = args.command {
        assert!(exec_args.tty);
    } else {
        panic!("Expected Exec command");
    }
}

#[test]
fn test_parse_exec_with_stdin() {
    let args = Cli::parse_from(["kc", "exec", "my-pod", "-i", "--", "/bin/sh"]);
    if let Command::Exec(exec_args) = args.command {
        assert!(exec_args.stdin);
    } else {
        panic!("Expected Exec command");
    }
}

// ============================================================================
// Scale command tests
// ============================================================================

#[test]
fn test_parse_scale_command() {
    let args = Cli::parse_from(["kc", "scale", "deployment", "nginx", "--replicas=3"]);
    if let Command::Scale(scale_args) = args.command {
        assert_eq!(scale_args.resource_type, "deployment");
        assert_eq!(scale_args.name, "nginx");
        assert_eq!(scale_args.replicas, 3);
    } else {
        panic!("Expected Scale command");
    }
}

#[test]
fn test_parse_scale_statefulset() {
    let args = Cli::parse_from(["kc", "scale", "statefulset", "mysql", "--replicas=5"]);
    if let Command::Scale(scale_args) = args.command {
        assert_eq!(scale_args.resource_type, "statefulset");
        assert_eq!(scale_args.name, "mysql");
        assert_eq!(scale_args.replicas, 5);
    } else {
        panic!("Expected Scale command");
    }
}

// ============================================================================
// Delete command tests
// ============================================================================

#[test]
fn test_parse_delete_command() {
    let args = Cli::parse_from(["kc", "delete", "pod", "my-pod"]);
    if let Command::Delete(delete_args) = args.command {
        assert_eq!(delete_args.resource_type, "pod");
        assert_eq!(delete_args.names, vec!["my-pod"]);
    } else {
        panic!("Expected Delete command");
    }
}

#[test]
fn test_parse_delete_multiple() {
    let args = Cli::parse_from(["kc", "delete", "pod", "pod-1", "pod-2", "pod-3"]);
    if let Command::Delete(delete_args) = args.command {
        assert_eq!(delete_args.names, vec!["pod-1", "pod-2", "pod-3"]);
    } else {
        panic!("Expected Delete command");
    }
}

#[test]
fn test_parse_delete_with_yes() {
    let args = Cli::parse_from(["kc", "delete", "pod", "my-pod", "-y"]);
    if let Command::Delete(delete_args) = args.command {
        assert!(delete_args.yes);
    } else {
        panic!("Expected Delete command");
    }
}

#[test]
fn test_parse_delete_with_force() {
    let args = Cli::parse_from(["kc", "delete", "pod", "my-pod", "--force"]);
    if let Command::Delete(delete_args) = args.command {
        assert!(delete_args.force);
    } else {
        panic!("Expected Delete command");
    }
}

#[test]
fn test_parse_delete_with_grace_period() {
    let args = Cli::parse_from(["kc", "delete", "pod", "my-pod", "--grace-period", "30"]);
    if let Command::Delete(delete_args) = args.command {
        assert_eq!(delete_args.grace_period, Some(30));
    } else {
        panic!("Expected Delete command");
    }
}

// ============================================================================
// Context command tests
// ============================================================================

#[test]
fn test_parse_context_list() {
    let args = Cli::parse_from(["kc", "context"]);
    if let Command::Context(ctx_args) = args.command {
        assert!(ctx_args.name.is_none());
    } else {
        panic!("Expected Context command");
    }
}

#[test]
fn test_parse_context_switch() {
    let args = Cli::parse_from(["kc", "context", "my-cluster"]);
    if let Command::Context(ctx_args) = args.command {
        assert_eq!(ctx_args.name, Some("my-cluster".to_string()));
    } else {
        panic!("Expected Context command");
    }
}

#[test]
fn test_parse_context_alias_ctx() {
    let args = Cli::parse_from(["kc", "ctx"]);
    assert!(matches!(args.command, Command::Context(_)));
}

// ============================================================================
// Namespace command tests
// ============================================================================

#[test]
fn test_parse_ns_list() {
    let args = Cli::parse_from(["kc", "ns"]);
    if let Command::Ns(ns_args) = args.command {
        assert!(ns_args.name.is_none());
    } else {
        panic!("Expected Ns command");
    }
}

#[test]
fn test_parse_ns_switch() {
    let args = Cli::parse_from(["kc", "ns", "kube-system"]);
    if let Command::Ns(ns_args) = args.command {
        assert_eq!(ns_args.name, Some("kube-system".to_string()));
    } else {
        panic!("Expected Ns command");
    }
}

// ============================================================================
// UI command tests
// ============================================================================

#[test]
fn test_parse_ui_default() {
    let args = Cli::parse_from(["kc", "ui"]);
    if let Command::Ui(ui_args) = args.command {
        assert_eq!(ui_args.port, 9090);
        assert!(!ui_args.no_open);
    } else {
        panic!("Expected Ui command");
    }
}

#[test]
fn test_parse_ui_custom_port() {
    let args = Cli::parse_from(["kc", "ui", "-p", "8080"]);
    if let Command::Ui(ui_args) = args.command {
        assert_eq!(ui_args.port, 8080);
    } else {
        panic!("Expected Ui command");
    }
}

#[test]
fn test_parse_ui_no_open() {
    let args = Cli::parse_from(["kc", "ui", "--no-open"]);
    if let Command::Ui(ui_args) = args.command {
        assert!(ui_args.no_open);
    } else {
        panic!("Expected Ui command");
    }
}

// ============================================================================
// Get command tests
// ============================================================================

#[test]
fn test_parse_get_pods() {
    let args = Cli::parse_from(["kc", "get", "pods"]);
    if let Command::Get(get_args) = args.command {
        assert_eq!(get_args.resource_type, "pods");
        assert!(get_args.name.is_none());
    } else {
        panic!("Expected Get command");
    }
}

#[test]
fn test_parse_get_pod_by_name() {
    let args = Cli::parse_from(["kc", "get", "pod", "my-pod"]);
    if let Command::Get(get_args) = args.command {
        assert_eq!(get_args.resource_type, "pod");
        assert_eq!(get_args.name, Some("my-pod".to_string()));
    } else {
        panic!("Expected Get command");
    }
}

// ============================================================================
// Apply command tests
// ============================================================================

#[test]
fn test_parse_apply_command() {
    let args = Cli::parse_from(["kc", "apply", "-f", "deployment.yaml"]);
    if let Command::Apply(apply_args) = args.command {
        assert_eq!(apply_args.filename, vec!["deployment.yaml"]);
    } else {
        panic!("Expected Apply command");
    }
}

#[test]
fn test_parse_apply_multiple_files() {
    let args = Cli::parse_from(["kc", "apply", "-f", "dep.yaml", "-f", "svc.yaml"]);
    if let Command::Apply(apply_args) = args.command {
        assert_eq!(apply_args.filename, vec!["dep.yaml", "svc.yaml"]);
    } else {
        panic!("Expected Apply command");
    }
}

#[test]
fn test_parse_apply_dry_run() {
    let args = Cli::parse_from(["kc", "apply", "-f", "dep.yaml", "--dry-run"]);
    if let Command::Apply(apply_args) = args.command {
        assert!(apply_args.dry_run);
    } else {
        panic!("Expected Apply command");
    }
}

// ============================================================================
// Restart command tests
// ============================================================================

#[test]
fn test_parse_restart_command() {
    let args = Cli::parse_from(["kc", "restart", "deployment", "nginx"]);
    if let Command::Restart(restart_args) = args.command {
        assert_eq!(restart_args.resource_type, "deployment");
        assert_eq!(restart_args.name, "nginx");
    } else {
        panic!("Expected Restart command");
    }
}

// ============================================================================
// Shell command tests
// ============================================================================

#[test]
fn test_parse_shell_command() {
    let args = Cli::parse_from(["kc", "shell", "my-pod"]);
    if let Command::Shell(shell_args) = args.command {
        assert_eq!(shell_args.pod, "my-pod");
    } else {
        panic!("Expected Shell command");
    }
}

#[test]
fn test_parse_shell_with_container() {
    let args = Cli::parse_from(["kc", "shell", "my-pod", "-c", "sidecar"]);
    if let Command::Shell(shell_args) = args.command {
        assert_eq!(shell_args.container, Some("sidecar".to_string()));
    } else {
        panic!("Expected Shell command");
    }
}

// ============================================================================
// Port-forward command tests
// ============================================================================

#[test]
fn test_parse_port_forward_command() {
    let args = Cli::parse_from(["kc", "port-forward", "my-pod", "8080:80"]);
    if let Command::PortForward(pf_args) = args.command {
        assert_eq!(pf_args.pod, "my-pod");
        assert_eq!(pf_args.ports, vec!["8080:80"]);
    } else {
        panic!("Expected PortForward command");
    }
}

#[test]
fn test_parse_port_forward_alias_pf() {
    let args = Cli::parse_from(["kc", "pf", "my-pod", "8080:80"]);
    assert!(matches!(args.command, Command::PortForward(_)));
}

#[test]
fn test_parse_port_forward_multiple_ports() {
    let args = Cli::parse_from(["kc", "pf", "my-pod", "8080:80", "9090:9090"]);
    if let Command::PortForward(pf_args) = args.command {
        assert_eq!(pf_args.ports, vec!["8080:80", "9090:9090"]);
    } else {
        panic!("Expected PortForward command");
    }
}

// ============================================================================
// No color flag test
// ============================================================================

#[test]
fn test_parse_no_color() {
    let args = Cli::parse_from(["kc", "--no-color", "pods"]);
    assert!(args.no_color);
}

// ============================================================================
// Describe command tests
// ============================================================================

#[test]
fn test_parse_describe_command() {
    let args = Cli::parse_from(["kc", "describe", "pod", "my-pod"]);
    if let Command::Describe(describe_args) = args.command {
        assert_eq!(describe_args.resource_type, "pod");
        assert_eq!(describe_args.name, "my-pod");
    } else {
        panic!("Expected Describe command");
    }
}

// ============================================================================
// OutputFormat tests
// ============================================================================

#[test]
fn test_output_format_default() {
    assert_eq!(OutputFormat::default(), OutputFormat::Table);
}

#[test]
fn test_output_format_clone() {
    let format = OutputFormat::Json;
    let cloned = format.clone();
    assert_eq!(format, cloned);
}

#[test]
fn test_output_format_debug() {
    let format = OutputFormat::Yaml;
    let debug = format!("{:?}", format);
    assert_eq!(debug, "Yaml");
}

// ============================================================================
// Version command tests
// ============================================================================

#[test]
fn test_parse_version_command() {
    let args = Cli::parse_from(["kc", "version"]);
    assert!(matches!(args.command, Command::Version(_)));
}

#[test]
fn test_parse_version_alias_v() {
    let args = Cli::parse_from(["kc", "v"]);
    assert!(matches!(args.command, Command::Version(_)));
}

#[test]
fn test_parse_version_extended() {
    let args = Cli::parse_from(["kc", "version", "--extended"]);
    if let Command::Version(version_args) = args.command {
        assert!(version_args.extended);
    } else {
        panic!("Expected Version command");
    }
}

#[test]
fn test_parse_version_client() {
    let args = Cli::parse_from(["kc", "version", "--client"]);
    if let Command::Version(version_args) = args.command {
        assert!(version_args.client);
    } else {
        panic!("Expected Version command");
    }
}

#[test]
fn test_parse_version_both_flags() {
    let args = Cli::parse_from(["kc", "version", "--extended", "--client"]);
    if let Command::Version(version_args) = args.command {
        assert!(version_args.extended);
        assert!(version_args.client);
    } else {
        panic!("Expected Version command");
    }
}
