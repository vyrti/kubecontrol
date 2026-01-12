# kc - Kubernetes Control

A fast, user-friendly Kubernetes CLI tool written in Rust.

## Features

- **Fast** - Built in Rust with async I/O for maximum performance
- **User-friendly** - Intuitive commands with short aliases
- **Fuzzy matching** - Partial name matching for quick resource access
- **In-memory caching** - Fast repeated queries with 30-second TTL
- **Multi-context** - Seamless switching between Kubernetes contexts
- **Multi-cloud** - Supports AWS EKS, GCP GKE, Azure AKS, OpenShift, RKE/RKE2, K3s, and more
- **Multiple output formats** - Table, JSON, YAML, wide, and name-only
- **Web dashboard** - Built-in web UI for cluster visualization
- **Debugging suite** - Comprehensive diagnostics for cluster issues

## Installation

### From Source

```bash
git clone https://github.com/yourusername/kubecontrol.git
cd kubecontrol
cargo build
cp target/debug/kc /usr/local/bin/
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

# Get a specific resource
kc get pod nginx

# Describe a resource
kc describe pod nginx

# View pod logs
kc logs nginx

# Follow logs in real-time
kc logs -f nginx

# Execute command in pod
kc exec nginx -- ls /

# Open interactive shell in pod
kc shell nginx

# Port forward to a pod
kc pf nginx 8080:80

# Scale a deployment
kc scale deploy nginx --replicas=3

# Restart a deployment
kc restart deploy nginx

# Delete a resource
kc delete pod nginx

# Apply a manifest
kc apply -f deployment.yaml

# Create from manifest
kc create -f pod.yaml

# Switch context
kc ctx <context-name>

# Switch namespace
kc ns <namespace>

# Start web dashboard
kc ui

# Show cluster version and info
kc version

# Run cluster diagnostics
kc debug all
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

| Command | Alias | Description |
|---------|-------|-------------|
| `kc get <type>` | | List resources of a type |
| `kc get <type> <name>` | | Get a specific resource |
| `kc describe <type> <name>` | `desc` | Show detailed resource info |

### Logs & Execution

| Command | Alias | Description |
|---------|-------|-------------|
| `kc logs <pod>` | | View pod logs |
| `kc logs -f <pod>` | | Follow logs in real-time |
| `kc logs --tail=100 <pod>` | | Last N lines |
| `kc logs --since=1h <pod>` | | Logs from last duration |
| `kc logs -c <container> <pod>` | | Logs from specific container |
| `kc logs -p <pod>` | | Previous container logs |
| `kc exec <pod> -- <cmd>` | | Execute command in pod |
| `kc exec -it <pod> -- <cmd>` | | Interactive exec with TTY |
| `kc shell <pod>` | `sh` | Open interactive shell |

### Port Forwarding

| Command | Alias | Description |
|---------|-------|-------------|
| `kc port-forward <pod> <ports>` | `pf` | Forward ports to pod |
| `kc pf nginx 8080:80` | | Forward local 8080 to pod 80 |
| `kc pf nginx 8080` | | Forward local 8080 to pod 8080 |
| `kc pf --address 0.0.0.0 nginx 8080:80` | | Bind to all interfaces |

### Resource Management

| Command | Alias | Description |
|---------|-------|-------------|
| `kc delete <type> <name>` | `del` | Delete a resource |
| `kc delete -y <type> <name>` | | Delete without confirmation |
| `kc delete --force <type> <name>` | | Force delete (grace period=0) |
| `kc apply -f <file>` | | Apply manifest file |
| `kc apply -f -` | | Apply from stdin |
| `kc apply --dry-run -f <file>` | | Dry-run apply |
| `kc create -f <file>` | | Create from manifest |

### Scaling & Rollouts

| Command | Alias | Description |
|---------|-------|-------------|
| `kc scale <type> <name> --replicas=N` | | Scale replicas |
| `kc scale deploy nginx --replicas=3` | | Scale deployment |
| `kc scale sts redis --replicas=5` | | Scale statefulset |
| `kc restart <type> <name>` | | Rolling restart |
| `kc restart deploy nginx` | | Restart deployment |
| `kc restart sts redis` | | Restart statefulset |
| `kc restart ds fluentd` | | Restart daemonset |

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
| `--context` | | Kubernetes context to use |
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

## Fuzzy Matching

kc supports fuzzy matching for resource names, making it easier to work with long resource names:

```bash
# Instead of typing the full name
kc logs nginx-deployment-7b4c5d6f8-x2k9m

# You can use a partial match
kc logs nginx

# Fuzzy matching works for many commands
kc describe pod ngx
kc exec redis -- redis-cli
kc shell post  # matches postgres-db-0
```

The fuzzy matcher will:
- Try an exact match first
- Fall back to fuzzy matching if no exact match
- Return an error if the match is ambiguous (multiple similar names)

## Caching

kc includes an in-memory cache to speed up repeated queries:

- Cache TTL: 30 seconds
- Automatically caches list operations
- Cache is invalidated on mutations (delete, scale, etc.)

The cache significantly improves performance for workflows involving multiple queries.

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
├── cache/            # In-memory caching
├── cli/              # CLI definitions (clap)
├── client/           # Kubernetes client
├── commands/         # Command implementations
│   ├── apply.rs      # Apply/create commands
│   ├── delete.rs     # Delete command
│   ├── describe.rs   # Describe command
│   ├── exec.rs       # Exec command
│   ├── get.rs        # Generic get command
│   ├── logs.rs       # Logs command
│   ├── portforward.rs# Port-forward command
│   ├── restart.rs    # Restart command
│   ├── scale.rs      # Scale command
│   ├── shell.rs      # Shell command
│   └── version.rs    # Version command
├── config/           # App configuration
├── debug/            # Debugging suite
│   ├── cloud.rs      # Cloud detection
│   ├── gcp.rs        # GKE-specific diagnostics
│   ├── azure.rs      # AKS-specific diagnostics
│   ├── pod.rs        # Pod diagnostics
│   ├── node.rs       # Node diagnostics
│   ├── dns.rs        # DNS debugging
│   ├── network.rs    # Network connectivity
│   ├── storage.rs    # Storage diagnostics
│   ├── security.rs   # Security audit
│   └── ...           # Other debug modules
├── error/            # Error types
├── fuzzy/            # Fuzzy matching
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
