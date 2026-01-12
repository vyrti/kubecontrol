//! Cloud provider detection and cluster information
//!
//! Detects cloud providers (AWS, GCP, Azure) and Kubernetes distributions
//! (EKS, GKE, AKS, OpenShift, RKE, RKE2, K3s, kubeadm).

use k8s_openapi::api::core::v1::{ConfigMap, Node, Pod};
use kube::{api::ListParams, Api, Client};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::error::KcError;

/// Cloud provider hosting the Kubernetes cluster
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CloudProvider {
    AWS,
    GCP,
    Azure,
    DigitalOcean,
    Oracle,
    IBM,
    Alibaba,
    Hetzner,
    Linode,
    Civo,
    Vultr,
    Scaleway,
    Exoscale,
    OnPremise,
}

impl std::fmt::Display for CloudProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CloudProvider::AWS => write!(f, "Amazon Web Services"),
            CloudProvider::GCP => write!(f, "Google Cloud Platform"),
            CloudProvider::Azure => write!(f, "Microsoft Azure"),
            CloudProvider::DigitalOcean => write!(f, "DigitalOcean"),
            CloudProvider::Oracle => write!(f, "Oracle Cloud"),
            CloudProvider::IBM => write!(f, "IBM Cloud"),
            CloudProvider::Alibaba => write!(f, "Alibaba Cloud"),
            CloudProvider::Hetzner => write!(f, "Hetzner Cloud"),
            CloudProvider::Linode => write!(f, "Linode (Akamai)"),
            CloudProvider::Civo => write!(f, "Civo"),
            CloudProvider::Vultr => write!(f, "Vultr"),
            CloudProvider::Scaleway => write!(f, "Scaleway"),
            CloudProvider::Exoscale => write!(f, "Exoscale"),
            CloudProvider::OnPremise => write!(f, "On-Premise"),
        }
    }
}

/// Kubernetes distribution/platform
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum KubernetesDistribution {
    // Major cloud managed services
    EKS,
    GKE,
    AKS,
    DOKS,       // DigitalOcean Kubernetes
    OKE,        // Oracle Kubernetes Engine
    IKS,        // IBM Kubernetes Service
    ACK,        // Alibaba Container Service
    LKE,        // Linode Kubernetes Engine
    CivoK8s,    // Civo managed Kubernetes
    HetznerK8s, // Hetzner managed Kubernetes
    // Self-hosted / Enterprise
    OpenShift,
    RKE,
    RKE2,
    K3s,
    K0s,
    Kubeadm,
    TanzuTKG, // VMware Tanzu Kubernetes Grid
    Talos,    // Talos Linux
    // Local development
    MicroK8s,
    Kind,
    Minikube,
    DockerDesktop,
    RancherDesktop,
    // Unknown
    Unknown,
}

impl std::fmt::Display for KubernetesDistribution {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KubernetesDistribution::EKS => write!(f, "Amazon EKS"),
            KubernetesDistribution::GKE => write!(f, "Google GKE"),
            KubernetesDistribution::AKS => write!(f, "Azure AKS"),
            KubernetesDistribution::DOKS => write!(f, "DigitalOcean Kubernetes"),
            KubernetesDistribution::OKE => write!(f, "Oracle Kubernetes Engine"),
            KubernetesDistribution::IKS => write!(f, "IBM Kubernetes Service"),
            KubernetesDistribution::ACK => write!(f, "Alibaba Container Service"),
            KubernetesDistribution::LKE => write!(f, "Linode LKE"),
            KubernetesDistribution::CivoK8s => write!(f, "Civo Kubernetes"),
            KubernetesDistribution::HetznerK8s => write!(f, "Hetzner Kubernetes"),
            KubernetesDistribution::OpenShift => write!(f, "Red Hat OpenShift"),
            KubernetesDistribution::RKE => write!(f, "Rancher RKE"),
            KubernetesDistribution::RKE2 => write!(f, "Rancher RKE2"),
            KubernetesDistribution::K3s => write!(f, "Rancher K3s"),
            KubernetesDistribution::K0s => write!(f, "k0s"),
            KubernetesDistribution::Kubeadm => write!(f, "Kubeadm"),
            KubernetesDistribution::TanzuTKG => write!(f, "VMware Tanzu (TKG)"),
            KubernetesDistribution::Talos => write!(f, "Talos Linux"),
            KubernetesDistribution::MicroK8s => write!(f, "MicroK8s"),
            KubernetesDistribution::Kind => write!(f, "Kind"),
            KubernetesDistribution::Minikube => write!(f, "Minikube"),
            KubernetesDistribution::DockerDesktop => write!(f, "Docker Desktop"),
            KubernetesDistribution::RancherDesktop => write!(f, "Rancher Desktop"),
            KubernetesDistribution::Unknown => write!(f, "Unknown"),
        }
    }
}

/// Node summary information
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NodeSummary {
    pub total: usize,
    pub ready: usize,
    pub control_plane: usize,
    pub workers: usize,
    pub architectures: Vec<String>,
    pub instance_types: HashMap<String, usize>,
    pub os_images: HashMap<String, usize>,
}

/// Component version information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComponentVersion {
    pub name: String,
    pub version: String,
    pub status: String,
}

/// Comprehensive cluster information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClusterInfo {
    /// Kubernetes version
    pub kubernetes_version: String,
    /// Detected Kubernetes distribution
    pub platform: KubernetesDistribution,
    /// Cloud provider (if any)
    pub cloud_provider: Option<CloudProvider>,
    /// Cloud region
    pub region: Option<String>,
    /// Availability zone
    pub zone: Option<String>,
    /// Cluster name (if detectable)
    pub cluster_name: Option<String>,
    /// Cluster ID (if available)
    pub cluster_id: Option<String>,
    /// API server URL
    pub api_server_url: String,
    /// Node summary
    pub nodes: NodeSummary,
    /// Component versions
    pub components: Vec<ComponentVersion>,
    /// Additional platform-specific metadata
    pub metadata: HashMap<String, String>,
}

impl ClusterInfo {
    /// Check if this is a managed Kubernetes service
    pub fn is_managed(&self) -> bool {
        matches!(
            self.platform,
            KubernetesDistribution::EKS
                | KubernetesDistribution::GKE
                | KubernetesDistribution::AKS
                | KubernetesDistribution::DOKS
                | KubernetesDistribution::OKE
                | KubernetesDistribution::IKS
                | KubernetesDistribution::ACK
                | KubernetesDistribution::LKE
                | KubernetesDistribution::CivoK8s
                | KubernetesDistribution::HetznerK8s
        )
    }
}

/// Detect cloud provider from node information
pub fn detect_cloud_provider(nodes: &[Node]) -> Option<CloudProvider> {
    for node in nodes {
        let labels = node.metadata.labels.as_ref();
        let annotations = node.metadata.annotations.as_ref();

        // Check provider ID from spec if available
        if let Some(spec) = &node.spec {
            if let Some(provider_id) = &spec.provider_id {
                // Major cloud providers
                if provider_id.starts_with("aws://") {
                    return Some(CloudProvider::AWS);
                }
                if provider_id.starts_with("gce://") {
                    return Some(CloudProvider::GCP);
                }
                if provider_id.starts_with("azure://") {
                    return Some(CloudProvider::Azure);
                }
                if provider_id.starts_with("digitalocean://") {
                    return Some(CloudProvider::DigitalOcean);
                }
                if provider_id.starts_with("oci://") {
                    return Some(CloudProvider::Oracle);
                }
                if provider_id.starts_with("ibm://") {
                    return Some(CloudProvider::IBM);
                }
                if provider_id.starts_with("alicloud://") {
                    return Some(CloudProvider::Alibaba);
                }
                // Additional cloud providers
                if provider_id.starts_with("hcloud://") {
                    return Some(CloudProvider::Hetzner);
                }
                if provider_id.starts_with("linode://") {
                    return Some(CloudProvider::Linode);
                }
                if provider_id.starts_with("civo://") {
                    return Some(CloudProvider::Civo);
                }
                if provider_id.starts_with("vultr://") {
                    return Some(CloudProvider::Vultr);
                }
                if provider_id.starts_with("scaleway://") {
                    return Some(CloudProvider::Scaleway);
                }
                if provider_id.starts_with("exoscale://") {
                    return Some(CloudProvider::Exoscale);
                }
            }
        }

        // Check labels for cloud-specific indicators
        if let Some(labels) = labels {
            // AWS EKS
            if labels.contains_key("eks.amazonaws.com/nodegroup") {
                return Some(CloudProvider::AWS);
            }
            if labels.get("node.kubernetes.io/instance-type").map(|v| v.starts_with("m5.") || v.starts_with("t3.") || v.starts_with("c5.") || v.starts_with("r5.")).unwrap_or(false) {
                return Some(CloudProvider::AWS);
            }

            // GCP GKE
            if labels.contains_key("cloud.google.com/gke-nodepool") {
                return Some(CloudProvider::GCP);
            }
            if labels.contains_key("cloud.google.com/gke-os-distribution") {
                return Some(CloudProvider::GCP);
            }

            // Azure AKS
            if labels.contains_key("kubernetes.azure.com/agentpool") {
                return Some(CloudProvider::Azure);
            }
            if labels.contains_key("kubernetes.azure.com/cluster") {
                return Some(CloudProvider::Azure);
            }
        }

        // Check annotations
        if let Some(annotations) = annotations {
            // AWS
            if annotations.keys().any(|k| k.contains("eks.amazonaws.com")) {
                return Some(CloudProvider::AWS);
            }

            // Azure
            if annotations.keys().any(|k| k.contains("kubernetes.azure.com")) {
                return Some(CloudProvider::Azure);
            }
        }
    }

    None
}

/// Detect Kubernetes distribution from cluster information
pub async fn detect_distribution(
    client: &Client,
    nodes: &[Node],
    server_version: &str,
) -> KubernetesDistribution {
    // Check server version string for distribution hints
    let version_lower = server_version.to_lowercase();

    if version_lower.contains("+eks") || version_lower.contains("-eks") {
        return KubernetesDistribution::EKS;
    }
    if version_lower.contains("-gke.") {
        return KubernetesDistribution::GKE;
    }
    if version_lower.contains("+rke2") || version_lower.contains("-rke2") {
        return KubernetesDistribution::RKE2;
    }
    if version_lower.contains("+k3s") || version_lower.contains("-k3s") {
        return KubernetesDistribution::K3s;
    }
    if version_lower.contains("+k0s") || version_lower.contains("-k0s") {
        return KubernetesDistribution::K0s;
    }

    // Check for Talos from OS image (before label checks)
    for node in nodes {
        if let Some(status) = &node.status {
            if let Some(node_info) = &status.node_info {
                // Talos Linux detection via osImage
                if node_info.os_image.contains("Talos") {
                    return KubernetesDistribution::Talos;
                }
                // Also check kernel version for Talos
                if node_info.kernel_version.ends_with("-talos") {
                    return KubernetesDistribution::Talos;
                }
            }
        }
    }

    // Check node labels and annotations
    for node in nodes {
        if let Some(labels) = &node.metadata.labels {
            // EKS
            if labels.contains_key("eks.amazonaws.com/nodegroup") {
                return KubernetesDistribution::EKS;
            }

            // GKE
            if labels.contains_key("cloud.google.com/gke-nodepool") {
                return KubernetesDistribution::GKE;
            }

            // AKS
            if labels.contains_key("kubernetes.azure.com/agentpool") {
                return KubernetesDistribution::AKS;
            }

            // RKE
            if labels.contains_key("rke.cattle.io/machine") {
                return KubernetesDistribution::RKE;
            }

            // VMware Tanzu TKG
            if labels.keys().any(|k| k.starts_with("run.tanzu.vmware.com/")) {
                return KubernetesDistribution::TanzuTKG;
            }

            // k0s via labels
            if labels.keys().any(|k| k.starts_with("k0sproject.io/")) {
                return KubernetesDistribution::K0s;
            }

            // MicroK8s
            if labels.get("microk8s.io/cluster").is_some() {
                return KubernetesDistribution::MicroK8s;
            }

            // Minikube
            if labels.get("minikube.k8s.io/name").is_some() {
                return KubernetesDistribution::Minikube;
            }

            // Kind
            if labels.get("io.x-k8s.kind.cluster").is_some() {
                return KubernetesDistribution::Kind;
            }
        }

        if let Some(annotations) = &node.metadata.annotations {
            // RKE
            if annotations.contains_key("rke.cattle.io/external-ip") {
                return KubernetesDistribution::RKE;
            }
        }
    }

    // Check for OpenShift by looking for OpenShift-specific resources
    if is_openshift(client).await {
        return KubernetesDistribution::OpenShift;
    }

    // Check for kubeadm by looking for kubeadm ConfigMap
    if is_kubeadm(client).await {
        return KubernetesDistribution::Kubeadm;
    }

    // Check for local development distributions by node name
    for node in nodes {
        if let Some(name) = &node.metadata.name {
            if name.contains("docker-desktop") {
                return KubernetesDistribution::DockerDesktop;
            }
            if name.contains("rancher-desktop") {
                return KubernetesDistribution::RancherDesktop;
            }
        }
    }

    // Check for managed Kubernetes based on cloud provider
    let cloud_provider = detect_cloud_provider(nodes);
    match cloud_provider {
        Some(CloudProvider::Linode) => return KubernetesDistribution::LKE,
        Some(CloudProvider::Civo) => return KubernetesDistribution::CivoK8s,
        Some(CloudProvider::Hetzner) => return KubernetesDistribution::HetznerK8s,
        _ => {}
    }

    KubernetesDistribution::Unknown
}

/// Check if cluster is OpenShift
async fn is_openshift(client: &Client) -> bool {
    // Try to access OpenShift's ClusterVersion API by checking for OpenShift-specific CRDs
    // OpenShift clusters have the config.openshift.io API group
    use kube::discovery::Discovery;

    if let Ok(discovery) = Discovery::new(client.clone()).run().await {
        for group in discovery.groups() {
            if group.name() == "config.openshift.io" {
                return true;
            }
        }
    }
    false
}

/// Check if cluster was created with kubeadm
async fn is_kubeadm(client: &Client) -> bool {
    let configmaps: Api<ConfigMap> = Api::namespaced(client.clone(), "kube-system");
    configmaps.get("kubeadm-config").await.is_ok()
}

/// Detect container-optimized OS from node information
pub fn detect_container_os(nodes: &[Node]) -> Option<String> {
    for node in nodes {
        if let Some(status) = &node.status {
            if let Some(node_info) = &status.node_info {
                let os_image = &node_info.os_image;

                // Talos Linux
                if os_image.contains("Talos") {
                    return Some("Talos Linux".to_string());
                }
                // Flatcar Container Linux
                if os_image.contains("Flatcar") {
                    return Some("Flatcar Container Linux".to_string());
                }
                // AWS Bottlerocket
                if os_image.contains("Bottlerocket") {
                    return Some("Bottlerocket".to_string());
                }
                // Google Container-Optimized OS
                if os_image.contains("Container-Optimized OS") {
                    return Some("Container-Optimized OS (Google)".to_string());
                }
                // Red Hat CoreOS (OpenShift)
                if os_image.contains("CoreOS") || os_image.contains("RHCOS") {
                    return Some("Red Hat CoreOS".to_string());
                }
            }
        }
    }
    None
}

/// Extract region from node information
pub fn extract_region(nodes: &[Node]) -> Option<String> {
    for node in nodes {
        if let Some(labels) = &node.metadata.labels {
            // Standard topology label
            if let Some(region) = labels.get("topology.kubernetes.io/region") {
                return Some(region.clone());
            }
            // Legacy label
            if let Some(region) = labels.get("failure-domain.beta.kubernetes.io/region") {
                return Some(region.clone());
            }
        }
    }
    None
}

/// Extract zone from node information
pub fn extract_zone(nodes: &[Node]) -> Option<String> {
    for node in nodes {
        if let Some(labels) = &node.metadata.labels {
            // Standard topology label
            if let Some(zone) = labels.get("topology.kubernetes.io/zone") {
                return Some(zone.clone());
            }
            // Legacy label
            if let Some(zone) = labels.get("failure-domain.beta.kubernetes.io/zone") {
                return Some(zone.clone());
            }
        }
    }
    None
}

/// Extract cluster name from various sources
pub fn extract_cluster_name(nodes: &[Node], cloud_provider: Option<&CloudProvider>) -> Option<String> {
    for node in nodes {
        if let Some(labels) = &node.metadata.labels {
            // EKS cluster name
            if let Some(name) = labels.get("alpha.eksctl.io/cluster-name") {
                return Some(name.clone());
            }

            // AKS cluster name
            if let Some(name) = labels.get("kubernetes.azure.com/cluster") {
                return Some(name.clone());
            }
        }

        if let Some(annotations) = &node.metadata.annotations {
            // RKE cluster name
            if let Some(name) = annotations.get("rke.cattle.io/cluster-name") {
                return Some(name.clone());
            }
        }
    }

    // Try to extract from API server URL for GKE
    // GKE URLs often contain the cluster name

    None
}

/// Build node summary from node list
pub fn build_node_summary(nodes: &[Node]) -> NodeSummary {
    let mut summary = NodeSummary {
        total: nodes.len(),
        ..Default::default()
    };

    let mut architectures = std::collections::HashSet::new();

    for node in nodes {
        // Check if ready
        if let Some(status) = &node.status {
            if let Some(conditions) = &status.conditions {
                for condition in conditions {
                    if condition.type_ == "Ready" && condition.status == "True" {
                        summary.ready += 1;
                        break;
                    }
                }
            }

            // Get architecture
            if let Some(node_info) = &status.node_info {
                architectures.insert(node_info.architecture.clone());

                // Count OS images
                *summary.os_images.entry(node_info.os_image.clone()).or_insert(0) += 1;
            }
        }

        // Check if control plane
        if let Some(labels) = &node.metadata.labels {
            if labels.contains_key("node-role.kubernetes.io/control-plane")
                || labels.contains_key("node-role.kubernetes.io/master")
            {
                summary.control_plane += 1;
            } else {
                summary.workers += 1;
            }

            // Count instance types
            if let Some(instance_type) = labels.get("node.kubernetes.io/instance-type") {
                *summary.instance_types.entry(instance_type.clone()).or_insert(0) += 1;
            } else if let Some(instance_type) = labels.get("beta.kubernetes.io/instance-type") {
                *summary.instance_types.entry(instance_type.clone()).or_insert(0) += 1;
            }
        }
    }

    summary.architectures = architectures.into_iter().collect();
    summary
}

/// Get component versions from cluster
pub async fn get_component_versions(client: &Client) -> Vec<ComponentVersion> {
    let mut components = Vec::new();

    // Get CoreDNS version
    let pods: Api<Pod> = Api::namespaced(client.clone(), "kube-system");
    if let Ok(coredns_pods) = pods.list(&ListParams::default().labels("k8s-app=kube-dns")).await {
        for pod in coredns_pods {
            if let Some(spec) = pod.spec {
                for container in spec.containers {
                    if container.name.contains("coredns") {
                        let version = container.image.unwrap_or_default();
                        let version = version.split(':').last().unwrap_or("unknown").to_string();
                        let status = pod.status.as_ref()
                            .and_then(|s| s.phase.clone())
                            .unwrap_or_else(|| "Unknown".to_string());
                        components.push(ComponentVersion {
                            name: "CoreDNS".to_string(),
                            version,
                            status,
                        });
                        break;
                    }
                }
            }
            break; // Only need first pod
        }
    }

    // Get kube-proxy version
    if let Ok(kube_proxy_pods) = pods.list(&ListParams::default().labels("k8s-app=kube-proxy")).await {
        for pod in kube_proxy_pods {
            if let Some(spec) = pod.spec {
                for container in spec.containers {
                    if container.name.contains("kube-proxy") {
                        let version = container.image.unwrap_or_default();
                        let version = version.split(':').last().unwrap_or("unknown").to_string();
                        let status = pod.status.as_ref()
                            .and_then(|s| s.phase.clone())
                            .unwrap_or_else(|| "Unknown".to_string());
                        components.push(ComponentVersion {
                            name: "kube-proxy".to_string(),
                            version,
                            status,
                        });
                        break;
                    }
                }
            }
            break;
        }
    }

    components
}

/// Get comprehensive cluster information
pub async fn get_cluster_info(client: &Client) -> Result<ClusterInfo, KcError> {
    // Get server version
    let version_info = client.apiserver_version().await
        .map_err(|e| KcError::Config(e.to_string()))?;
    let kubernetes_version = format!("v{}.{}", version_info.major, version_info.minor);
    let full_version = version_info.git_version.clone();

    // Get nodes
    let nodes_api: Api<Node> = Api::all(client.clone());
    let nodes: Vec<Node> = nodes_api.list(&ListParams::default()).await
        .map_err(|e| KcError::Config(e.to_string()))?
        .items;

    // Detect cloud provider
    let cloud_provider = detect_cloud_provider(&nodes);

    // Detect distribution
    let platform = detect_distribution(client, &nodes, &full_version).await;

    // Extract region and zone
    let region = extract_region(&nodes);
    let zone = extract_zone(&nodes);

    // Extract cluster name
    let cluster_name = extract_cluster_name(&nodes, cloud_provider.as_ref());

    // Build node summary
    let node_summary = build_node_summary(&nodes);

    // Get component versions
    let components = get_component_versions(client).await;

    // Get API server URL from client config
    let api_server_url = client.default_namespace().to_string(); // Placeholder, will need proper extraction

    // Build metadata
    let mut metadata = HashMap::new();
    metadata.insert("server_version".to_string(), full_version);

    // Add container runtime info from first node
    if let Some(node) = nodes.first() {
        if let Some(status) = &node.status {
            if let Some(node_info) = &status.node_info {
                metadata.insert("container_runtime".to_string(), node_info.container_runtime_version.clone());
                metadata.insert("kubelet_version".to_string(), node_info.kubelet_version.clone());
                metadata.insert("kernel_version".to_string(), node_info.kernel_version.clone());
            }
        }
    }

    // Detect container-optimized OS
    if let Some(container_os) = detect_container_os(&nodes) {
        metadata.insert("container_os".to_string(), container_os);
    }

    Ok(ClusterInfo {
        kubernetes_version,
        platform,
        cloud_provider,
        region,
        zone,
        cluster_name,
        cluster_id: None,
        api_server_url,
        nodes: node_summary,
        components,
        metadata,
    })
}

/// Check if the cluster is running on a specific cloud provider
pub fn is_cloud_provider(nodes: &[Node], provider: CloudProvider) -> bool {
    detect_cloud_provider(nodes) == Some(provider)
}

/// Check if the cluster is a specific distribution
pub async fn is_distribution(
    client: &Client,
    nodes: &[Node],
    server_version: &str,
    distribution: KubernetesDistribution,
) -> bool {
    detect_distribution(client, nodes, server_version).await == distribution
}
