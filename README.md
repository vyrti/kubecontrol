# kc - Kubernetes Control

A fast, user-friendly Kubernetes CLI tool written in Rust.

## Features

- **Fast** - Built in Rust with async I/O for maximum performance
- **User-friendly** - Intuitive commands with short aliases
- **Multi-context** - Seamless switching between Kubernetes contexts
- **Multi-cloud** - Supports AWS EKS, GCP GKE, Azure AKS, OpenShift, RKE/RKE2, K3s, and more
- **Fuzzy matching** - Find resources quickly with partial names
- **Multiple output formats** - Table, JSON, YAML, wide, and name-only
- **Web dashboard** - Built-in web UI for cluster visualization
- **Debugging suite** - Comprehensive diagnostics for cluster issues
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

### Cluster Information

| Command | Alias | Description |
|---------|-------|-------------|
| `kc version` | `v` | Show cluster version and platform info |
| `kc version --extended` | | Show extended cluster information |
| `kc version --client` | | Show client version only |

### Web UI

| Command | Description |
|---------|-------------|
| `kc ui` | Start web dashboard |
| `kc ui -p 8080` | Start on custom port |
| `kc ui --no-open` | Don't auto-open browser |

### Debugging

| Command | Description |
|---------|-------------|
| `kc debug all` | Run all diagnostic checks |
| `kc debug dns` | DNS debugging (CoreDNS health, resolution) |
| `kc debug network` | Network connectivity diagnostics |
| `kc debug pod <name>` | Pod-specific diagnostics |
| `kc debug node <name>` | Node diagnostics |
| `kc debug deploy <name>` | Deployment analysis |
| `kc debug svc <name>` | Service connectivity check |
| `kc debug storage` | Storage diagnostics (PVC/PV issues) |
| `kc debug security` | Security audit |
| `kc debug resources` | Resource analysis |
| `kc debug events` | Event correlation |
| `kc debug ingress` | Ingress/load balancer debugging |
| `kc debug cluster` | Cluster-wide health check |

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

## Multi-Cloud Support

kc automatically detects your cloud provider and Kubernetes distribution:

### Supported Cloud Providers

| Provider | Detection Method |
|----------|-----------------|
| AWS | EKS node labels, `aws://` provider ID |
| Google Cloud | GKE node labels, `gce://` provider ID |
| Microsoft Azure | AKS node labels, `azure://` provider ID |
| DigitalOcean | DOKS labels, `digitalocean://` provider ID |
| Oracle Cloud | OKE labels, `oci://` provider ID |
| IBM Cloud | IKS labels, `ibm://` provider ID |
| Alibaba Cloud | ACK labels, `alicloud://` provider ID |

### Supported Distributions

| Distribution | Detection Method |
|--------------|-----------------|
| Amazon EKS | `+eks` in version, EKS node labels |
| Google GKE | `-gke.` in version, GKE node labels |
| Azure AKS | AKS node labels |
| Red Hat OpenShift | OpenShift API groups |
| Rancher RKE | RKE annotations |
| Rancher RKE2 | `+rke2` in version |
| Rancher K3s | `+k3s` in version |
| Kubeadm | `kubeadm-config` ConfigMap |
| MicroK8s | MicroK8s labels |
| Kind | Kind labels |
| Minikube | Minikube labels |
| Docker Desktop | Node name contains `docker-desktop` |

### Platform-Specific Debugging

For cloud-managed clusters, additional platform-specific diagnostics are available:

```bash
# GKE-specific checks (Workload Identity, Autopilot, VPC-native networking)
kc debug gke

# AKS-specific checks (Azure AD, Azure CNI, Virtual Nodes)
kc debug aks
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
- Cluster health scanning
- Debug panel for diagnostics
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
│   └── version.rs    # Version command with cluster info
├── config/           # App configuration
├── debug/            # Debugging suite
│   ├── cloud.rs      # Cloud detection (AWS, GCP, Azure, etc.)
│   ├── gcp.rs        # GKE-specific diagnostics
│   ├── azure.rs      # AKS-specific diagnostics
│   ├── pod.rs        # Pod diagnostics
│   ├── node.rs       # Node diagnostics (SRE-level)
│   ├── dns.rs        # DNS debugging
│   ├── network.rs    # Network connectivity
│   ├── storage.rs    # Storage diagnostics
│   ├── security.rs   # Security audit
│   └── ...           # Other debug modules
├── error/            # Error types
├── output/           # Output formatting
├── resources/        # Kubernetes resource types
└── web/              # Web dashboard
    ├── assets.rs     # Embedded frontend
    ├── handlers.rs   # API handlers
    ├── server.rs     # Axum server
    └── websocket.rs  # WebSocket handlers
```

## Testing

### Run Unit Tests

Unit tests run without requiring a Kubernetes cluster:

```bash
cargo test
```

### Run Integration Tests (requires Kubernetes cluster)

Integration tests connect to a real Kubernetes cluster. Ensure you have:
- A valid kubeconfig file
- Access to a Kubernetes cluster
- The default context points to a test cluster (not production!)

```bash
# Run all integration tests
cargo test -- --ignored

# Run specific integration test module
cargo test integration::pods_test -- --ignored

# Run a specific test
cargo test test_list_pods_kube_system -- --ignored
```

### Run All Tests

```bash
# Unit tests followed by integration tests
cargo test && cargo test -- --ignored
```

### Test Structure

```
tests/
├── common/
│   └── mod.rs              # Shared test utilities and mock helpers
├── unit/
│   ├── traits_test.rs      # humanize_duration, status_category tests
│   ├── output_test.rs      # format_table, format_json, format_yaml tests
│   ├── registry_test.rs    # ResourceRegistry lookup tests
│   ├── resources_test.rs   # Resource trait implementation tests
│   ├── error_test.rs       # Error type tests
│   └── cloud_test.rs       # Cloud detection tests
├── integration/
│   ├── client_test.rs      # Real cluster: client creation, context switching
│   ├── pods_test.rs        # Real cluster: pod operations
│   ├── deployments_test.rs # Real cluster: deployment operations
│   ├── services_test.rs    # Real cluster: service operations
│   ├── configmaps_test.rs  # Real cluster: configmap operations
│   ├── nodes_test.rs       # Real cluster: node operations
│   └── web_api_test.rs     # Real cluster: web API endpoint tests
└── cli_test.rs             # CLI parsing tests (includes version command)
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
