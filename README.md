# kc - Kubernetes Control

A fast, user-friendly Kubernetes CLI tool written in Rust.

## Features

- **Fast** - Built in Rust with async I/O for maximum performance
- **User-friendly** - Intuitive commands with short aliases
- **Multi-context** - Seamless switching between Kubernetes contexts
- **Fuzzy matching** - Find resources quickly with partial names
- **Multiple output formats** - Table, JSON, YAML, wide, and name-only
- **Web dashboard** - Built-in web UI for cluster visualization
- **Caching** - Smart caching layer for faster repeated queries

## Installation

### From Source

```bash
git clone https://github.com/yourusername/kubecontrol.git
cd kubecontrol
cargo build --release
cp target/release/kc /usr/local/bin/
```

### Shell Completions

```bash
# Bash
kc completions bash > /etc/bash_completion.d/kc

# Zsh
kc completions zsh > ~/.zfunc/_kc

# Fish
kc completions fish > ~/.config/fish/completions/kc.fish

# PowerShell
kc completions powershell > $HOME\Documents\PowerShell\Modules\kc.ps1
```

## Quick Start

```bash
# List pods in current namespace
kc pods

# List pods in all namespaces
kc pods -A

# List pods with wide output
kc pods -w

# List deployments
kc deploy

# List services
kc svc

# View pod logs
kc logs <pod-name>

# Follow logs
kc logs <pod-name> -f

# Execute command in pod
kc exec <pod-name> -- /bin/sh

# Open shell in pod
kc shell <pod-name>

# Port forward
kc pf <pod-name> 8080:80

# Switch context
kc ctx <context-name>

# Switch namespace
kc ns <namespace>

# Start web dashboard
kc ui
```

## Commands

### Resource Listing

| Command | Alias | Description |
|---------|-------|-------------|
| `kc pods` | `po` | List pods |
| `kc deployments` | `deploy` | List deployments |
| `kc services` | `svc` | List services |
| `kc configmaps` | `cm` | List configmaps |
| `kc secrets` | | List secrets |
| `kc namespaces` | | List namespaces |
| `kc nodes` | `no` | List nodes |
| `kc replicasets` | `rs` | List replicasets |
| `kc statefulsets` | `sts` | List statefulsets |
| `kc daemonsets` | `ds` | List daemonsets |

### Generic Resource Access

| Command | Description |
|---------|-------------|
| `kc get <type> [name]` | Get any resource type |
| `kc describe <type> <name>` | Describe resource in detail |

### Pod Operations

| Command | Alias | Description |
|---------|-------|-------------|
| `kc logs <pod>` | | View pod logs |
| `kc exec <pod> -- <cmd>` | | Execute command in pod |
| `kc shell <pod>` | | Open interactive shell |
| `kc port-forward <pod> <ports>` | `pf` | Forward ports to pod |

### Resource Modification

| Command | Description |
|---------|-------------|
| `kc delete <type> <name>` | Delete resources |
| `kc apply -f <file>` | Apply configuration |
| `kc create -f <file>` | Create resource |
| `kc scale <type> <name> --replicas=N` | Scale deployment/statefulset |
| `kc restart <type> <name>` | Restart deployment/statefulset |

### Context & Namespace

| Command | Alias | Description |
|---------|-------|-------------|
| `kc context` | `ctx` | List/switch contexts |
| `kc ns` | | List/switch namespaces |

### Web UI

| Command | Description |
|---------|-------------|
| `kc ui` | Start web dashboard |
| `kc ui -p 8080` | Start on custom port |
| `kc ui --no-open` | Don't auto-open browser |

## Global Options

| Option | Short | Description |
|--------|-------|-------------|
| `--context` | `-c` | Kubernetes context to use |
| `--namespace` | `-n` | Namespace to use |
| `--output` | `-o` | Output format: table, json, yaml, wide, name |
| `--verbose` | `-v` | Enable verbose logging (-vv for debug) |
| `--no-color` | | Disable colored output |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `KC_CONTEXT` | Default Kubernetes context |
| `KC_NAMESPACE` | Default namespace |
| `KUBECONFIG` | Path to kubeconfig file |

## Output Formats

```bash
# Table (default)
kc pods

# Wide table with additional columns
kc pods -o wide
kc pods -w

# JSON output
kc pods -o json

# YAML output
kc pods -o yaml

# Names only
kc pods -o name
```

## Filtering

```bash
# Filter by label selector
kc pods -l app=nginx

# Filter by field selector
kc pods --field-selector status.phase=Running

# All namespaces
kc pods -A
```

## Web Dashboard

The built-in web dashboard provides a visual interface for your cluster:

```bash
kc ui
```

Features:
- Real-time pod, deployment, service, node views
- Namespace filtering
- Pod log viewing
- Auto-refresh every 30 seconds
- Dark mode UI

Default URL: `http://127.0.0.1:9090`

## Build Profiles

```bash
# Development (fast compile, slow runtime)
cargo build

# Release (slow compile, fast runtime)
cargo build --release

# Minimum binary size
cargo build --profile release-small

# For profiling
cargo build --profile profiling
```

## Project Structure

```
src/
├── main.rs           # Entry point
├── lib.rs            # Library root
├── cli/              # CLI definitions (clap)
├── client/           # Kubernetes client
├── commands/         # Command implementations
├── config/           # App configuration
├── error/            # Error types
├── output/           # Output formatting
├── resources/        # Kubernetes resource types
└── web/              # Web dashboard
    ├── assets.rs     # Embedded frontend
    ├── handlers.rs   # API handlers
    ├── server.rs     # Axum server
    └── websocket.rs  # WebSocket handlers
```

## Requirements

- Rust 1.75+ (for building)
- Kubernetes cluster access
- Valid kubeconfig file

## Kubernetes Version Support

This tool supports Kubernetes API version **1.34**.

## License

Dual-licensed under MIT or Apache-2.0, at your option.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. DCO required.
