//! Cloud detection unit tests
//!
//! Tests for cloud provider and Kubernetes distribution detection.

use k8s_openapi::api::core::v1::Node;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kubecontrol::debug::cloud::{
    CloudProvider, KubernetesDistribution, detect_cloud_provider, extract_region, extract_zone,
};
use std::collections::BTreeMap;

// ============================================================================
// Helper functions to create mock nodes
// ============================================================================

fn create_node_with_labels(name: &str, labels: BTreeMap<String, String>) -> Node {
    Node {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        ..Default::default()
    }
}

fn create_node_with_provider_id(name: &str, provider_id: &str) -> Node {
    Node {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            ..Default::default()
        },
        spec: Some(k8s_openapi::api::core::v1::NodeSpec {
            provider_id: Some(provider_id.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    }
}

// ============================================================================
// CloudProvider enum tests
// ============================================================================

#[test]
fn test_cloud_provider_display_aws() {
    assert_eq!(format!("{}", CloudProvider::AWS), "Amazon Web Services");
}

#[test]
fn test_cloud_provider_display_gcp() {
    assert_eq!(format!("{}", CloudProvider::GCP), "Google Cloud Platform");
}

#[test]
fn test_cloud_provider_display_azure() {
    assert_eq!(format!("{}", CloudProvider::Azure), "Microsoft Azure");
}

#[test]
fn test_cloud_provider_display_digital_ocean() {
    assert_eq!(format!("{}", CloudProvider::DigitalOcean), "DigitalOcean");
}

#[test]
fn test_cloud_provider_display_on_premise() {
    assert_eq!(format!("{}", CloudProvider::OnPremise), "On-Premise");
}

#[test]
fn test_cloud_provider_equality() {
    assert_eq!(CloudProvider::AWS, CloudProvider::AWS);
    assert_ne!(CloudProvider::AWS, CloudProvider::GCP);
}

#[test]
fn test_cloud_provider_clone() {
    let provider = CloudProvider::Azure;
    let cloned = provider.clone();
    assert_eq!(provider, cloned);
}

// ============================================================================
// KubernetesDistribution enum tests
// ============================================================================

#[test]
fn test_distribution_display_eks() {
    assert_eq!(format!("{}", KubernetesDistribution::EKS), "Amazon EKS");
}

#[test]
fn test_distribution_display_gke() {
    assert_eq!(format!("{}", KubernetesDistribution::GKE), "Google GKE");
}

#[test]
fn test_distribution_display_aks() {
    assert_eq!(format!("{}", KubernetesDistribution::AKS), "Azure AKS");
}

#[test]
fn test_distribution_display_openshift() {
    assert_eq!(format!("{}", KubernetesDistribution::OpenShift), "Red Hat OpenShift");
}

#[test]
fn test_distribution_display_rke() {
    assert_eq!(format!("{}", KubernetesDistribution::RKE), "Rancher RKE");
}

#[test]
fn test_distribution_display_rke2() {
    assert_eq!(format!("{}", KubernetesDistribution::RKE2), "Rancher RKE2");
}

#[test]
fn test_distribution_display_k3s() {
    assert_eq!(format!("{}", KubernetesDistribution::K3s), "Rancher K3s");
}

#[test]
fn test_distribution_display_kubeadm() {
    assert_eq!(format!("{}", KubernetesDistribution::Kubeadm), "Kubeadm");
}

#[test]
fn test_distribution_display_unknown() {
    assert_eq!(format!("{}", KubernetesDistribution::Unknown), "Unknown");
}

#[test]
fn test_distribution_equality() {
    assert_eq!(KubernetesDistribution::EKS, KubernetesDistribution::EKS);
    assert_ne!(KubernetesDistribution::EKS, KubernetesDistribution::GKE);
}

// ============================================================================
// Cloud provider detection tests
// ============================================================================

#[test]
fn test_detect_aws_from_eks_label() {
    let mut labels = BTreeMap::new();
    labels.insert("eks.amazonaws.com/nodegroup".to_string(), "my-nodegroup".to_string());

    let nodes = vec![create_node_with_labels("node-1", labels)];
    let provider = detect_cloud_provider(&nodes);

    assert_eq!(provider, Some(CloudProvider::AWS));
}

#[test]
fn test_detect_aws_from_provider_id() {
    let nodes = vec![create_node_with_provider_id("node-1", "aws:///us-west-2a/i-1234567890")];
    let provider = detect_cloud_provider(&nodes);

    assert_eq!(provider, Some(CloudProvider::AWS));
}

#[test]
fn test_detect_gcp_from_gke_label() {
    let mut labels = BTreeMap::new();
    labels.insert("cloud.google.com/gke-nodepool".to_string(), "default-pool".to_string());

    let nodes = vec![create_node_with_labels("gke-node", labels)];
    let provider = detect_cloud_provider(&nodes);

    assert_eq!(provider, Some(CloudProvider::GCP));
}

#[test]
fn test_detect_gcp_from_provider_id() {
    let nodes = vec![create_node_with_provider_id("node-1", "gce://my-project/us-central1-a/gke-node")];
    let provider = detect_cloud_provider(&nodes);

    assert_eq!(provider, Some(CloudProvider::GCP));
}

#[test]
fn test_detect_azure_from_aks_label() {
    let mut labels = BTreeMap::new();
    labels.insert("kubernetes.azure.com/agentpool".to_string(), "nodepool1".to_string());

    let nodes = vec![create_node_with_labels("aks-node", labels)];
    let provider = detect_cloud_provider(&nodes);

    assert_eq!(provider, Some(CloudProvider::Azure));
}

#[test]
fn test_detect_azure_from_provider_id() {
    let nodes = vec![create_node_with_provider_id(
        "node-1",
        "azure:///subscriptions/xxx/resourceGroups/xxx/providers/Microsoft.Compute/virtualMachines/aks-node",
    )];
    let provider = detect_cloud_provider(&nodes);

    assert_eq!(provider, Some(CloudProvider::Azure));
}

#[test]
fn test_detect_no_provider_for_vanilla_cluster() {
    let nodes = vec![create_node_with_labels("node-1", BTreeMap::new())];
    let provider = detect_cloud_provider(&nodes);

    assert_eq!(provider, None);
}

#[test]
fn test_detect_no_provider_for_empty_nodes() {
    let nodes: Vec<Node> = vec![];
    let provider = detect_cloud_provider(&nodes);

    assert_eq!(provider, None);
}

// ============================================================================
// Region extraction tests
// ============================================================================

#[test]
fn test_extract_region_from_topology_label() {
    let mut labels = BTreeMap::new();
    labels.insert("topology.kubernetes.io/region".to_string(), "us-west-2".to_string());

    let nodes = vec![create_node_with_labels("node-1", labels)];
    let region = extract_region(&nodes);

    assert_eq!(region, Some("us-west-2".to_string()));
}

#[test]
fn test_extract_region_from_legacy_label() {
    let mut labels = BTreeMap::new();
    labels.insert("failure-domain.beta.kubernetes.io/region".to_string(), "eu-west-1".to_string());

    let nodes = vec![create_node_with_labels("node-1", labels)];
    let region = extract_region(&nodes);

    assert_eq!(region, Some("eu-west-1".to_string()));
}

#[test]
fn test_extract_region_none_when_missing() {
    let nodes = vec![create_node_with_labels("node-1", BTreeMap::new())];
    let region = extract_region(&nodes);

    assert_eq!(region, None);
}

// ============================================================================
// Zone extraction tests
// ============================================================================

#[test]
fn test_extract_zone_from_topology_label() {
    let mut labels = BTreeMap::new();
    labels.insert("topology.kubernetes.io/zone".to_string(), "us-west-2a".to_string());

    let nodes = vec![create_node_with_labels("node-1", labels)];
    let zone = extract_zone(&nodes);

    assert_eq!(zone, Some("us-west-2a".to_string()));
}

#[test]
fn test_extract_zone_from_legacy_label() {
    let mut labels = BTreeMap::new();
    labels.insert("failure-domain.beta.kubernetes.io/zone".to_string(), "us-east-1a".to_string());

    let nodes = vec![create_node_with_labels("node-1", labels)];
    let zone = extract_zone(&nodes);

    assert_eq!(zone, Some("us-east-1a".to_string()));
}

#[test]
fn test_extract_zone_none_when_missing() {
    let nodes = vec![create_node_with_labels("node-1", BTreeMap::new())];
    let zone = extract_zone(&nodes);

    assert_eq!(zone, None);
}

// ============================================================================
// Serialization tests
// ============================================================================

#[test]
fn test_cloud_provider_json_serialization() {
    let provider = CloudProvider::AWS;
    let json = serde_json::to_string(&provider).unwrap();
    assert_eq!(json, "\"aws\"");
}

#[test]
fn test_cloud_provider_json_deserialization() {
    let provider: CloudProvider = serde_json::from_str("\"gcp\"").unwrap();
    assert_eq!(provider, CloudProvider::GCP);
}

#[test]
fn test_distribution_json_serialization() {
    let dist = KubernetesDistribution::EKS;
    let json = serde_json::to_string(&dist).unwrap();
    assert_eq!(json, "\"eks\"");
}

#[test]
fn test_distribution_json_deserialization() {
    let dist: KubernetesDistribution = serde_json::from_str("\"aks\"").unwrap();
    assert_eq!(dist, KubernetesDistribution::AKS);
}

// ============================================================================
// Additional cloud provider detection tests
// ============================================================================

#[test]
fn test_detect_digitalocean_from_provider_id() {
    let nodes = vec![create_node_with_provider_id("node-1", "digitalocean://123456789")];
    let provider = detect_cloud_provider(&nodes);

    assert_eq!(provider, Some(CloudProvider::DigitalOcean));
}

#[test]
fn test_detect_oracle_from_provider_id() {
    let nodes = vec![create_node_with_provider_id("node-1", "oci://ocid1.instance.oc1.iad.xxx")];
    let provider = detect_cloud_provider(&nodes);

    assert_eq!(provider, Some(CloudProvider::Oracle));
}

#[test]
fn test_detect_ibm_from_provider_id() {
    let nodes = vec![create_node_with_provider_id("node-1", "ibm://xxx-cluster/xxx-worker")];
    let provider = detect_cloud_provider(&nodes);

    assert_eq!(provider, Some(CloudProvider::IBM));
}

#[test]
fn test_detect_alibaba_from_provider_id() {
    let nodes = vec![create_node_with_provider_id("node-1", "alicloud://cn-hangzhou/i-xxx")];
    let provider = detect_cloud_provider(&nodes);

    assert_eq!(provider, Some(CloudProvider::Alibaba));
}

#[test]
fn test_cloud_provider_display_oracle() {
    assert_eq!(format!("{}", CloudProvider::Oracle), "Oracle Cloud");
}

#[test]
fn test_cloud_provider_display_ibm() {
    assert_eq!(format!("{}", CloudProvider::IBM), "IBM Cloud");
}

#[test]
fn test_cloud_provider_display_alibaba() {
    assert_eq!(format!("{}", CloudProvider::Alibaba), "Alibaba Cloud");
}

// ============================================================================
// Additional distribution tests
// ============================================================================

#[test]
fn test_distribution_display_microk8s() {
    assert_eq!(format!("{}", KubernetesDistribution::MicroK8s), "MicroK8s");
}

#[test]
fn test_distribution_display_kind() {
    assert_eq!(format!("{}", KubernetesDistribution::Kind), "Kind");
}

#[test]
fn test_distribution_display_minikube() {
    assert_eq!(format!("{}", KubernetesDistribution::Minikube), "Minikube");
}

#[test]
fn test_distribution_display_docker_desktop() {
    assert_eq!(format!("{}", KubernetesDistribution::DockerDesktop), "Docker Desktop");
}

#[test]
fn test_distribution_display_doks() {
    assert_eq!(format!("{}", KubernetesDistribution::DOKS), "DigitalOcean Kubernetes");
}

#[test]
fn test_distribution_display_oke() {
    assert_eq!(format!("{}", KubernetesDistribution::OKE), "Oracle Kubernetes Engine");
}

#[test]
fn test_distribution_display_iks() {
    assert_eq!(format!("{}", KubernetesDistribution::IKS), "IBM Kubernetes Service");
}

#[test]
fn test_distribution_display_ack() {
    assert_eq!(format!("{}", KubernetesDistribution::ACK), "Alibaba Container Service");
}

// ============================================================================
// Cluster name extraction tests
// ============================================================================

use kubecontrol::debug::cloud::extract_cluster_name;

fn create_node_with_labels_and_annotations(
    name: &str,
    labels: BTreeMap<String, String>,
    annotations: BTreeMap<String, String>,
) -> Node {
    Node {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(labels),
            annotations: Some(annotations),
            ..Default::default()
        },
        ..Default::default()
    }
}

#[test]
fn test_extract_cluster_name_from_eksctl() {
    let mut labels = BTreeMap::new();
    labels.insert("alpha.eksctl.io/cluster-name".to_string(), "my-eks-cluster".to_string());

    let nodes = vec![create_node_with_labels("node-1", labels)];
    let name = extract_cluster_name(&nodes, Some(&CloudProvider::AWS));

    assert_eq!(name, Some("my-eks-cluster".to_string()));
}

#[test]
fn test_extract_cluster_name_from_aks() {
    let mut labels = BTreeMap::new();
    labels.insert("kubernetes.azure.com/cluster".to_string(), "my-aks-cluster".to_string());

    let nodes = vec![create_node_with_labels("node-1", labels)];
    let name = extract_cluster_name(&nodes, Some(&CloudProvider::Azure));

    assert_eq!(name, Some("my-aks-cluster".to_string()));
}

#[test]
fn test_extract_cluster_name_from_rke() {
    let labels = BTreeMap::new();
    let mut annotations = BTreeMap::new();
    annotations.insert("rke.cattle.io/cluster-name".to_string(), "my-rke-cluster".to_string());

    let nodes = vec![create_node_with_labels_and_annotations("node-1", labels, annotations)];
    let name = extract_cluster_name(&nodes, None);

    assert_eq!(name, Some("my-rke-cluster".to_string()));
}

#[test]
fn test_extract_cluster_name_none_when_missing() {
    let nodes = vec![create_node_with_labels("node-1", BTreeMap::new())];
    let name = extract_cluster_name(&nodes, None);

    assert_eq!(name, None);
}

// ============================================================================
// Node summary tests
// ============================================================================

use kubecontrol::debug::cloud::build_node_summary;
use k8s_openapi::api::core::v1::{NodeCondition, NodeSpec, NodeStatus, NodeSystemInfo};

fn create_full_node(
    name: &str,
    labels: BTreeMap<String, String>,
    is_ready: bool,
    architecture: &str,
    os_image: &str,
) -> Node {
    Node {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(labels),
            ..Default::default()
        },
        spec: Some(NodeSpec::default()),
        status: Some(NodeStatus {
            conditions: Some(vec![NodeCondition {
                type_: "Ready".to_string(),
                status: if is_ready { "True".to_string() } else { "False".to_string() },
                ..Default::default()
            }]),
            node_info: Some(NodeSystemInfo {
                architecture: architecture.to_string(),
                os_image: os_image.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        }),
    }
}

#[test]
fn test_build_node_summary_single_node() {
    let labels = BTreeMap::new();
    let nodes = vec![create_full_node("node-1", labels, true, "amd64", "Ubuntu 22.04")];

    let summary = build_node_summary(&nodes);

    assert_eq!(summary.total, 1);
    assert_eq!(summary.ready, 1);
    assert_eq!(summary.workers, 1);
    assert_eq!(summary.control_plane, 0);
    assert!(summary.architectures.contains(&"amd64".to_string()));
}

#[test]
fn test_build_node_summary_multiple_nodes() {
    let mut cp_labels = BTreeMap::new();
    cp_labels.insert("node-role.kubernetes.io/control-plane".to_string(), "".to_string());

    let worker_labels = BTreeMap::new();

    let nodes = vec![
        create_full_node("cp-1", cp_labels.clone(), true, "amd64", "Ubuntu 22.04"),
        create_full_node("worker-1", worker_labels.clone(), true, "amd64", "Ubuntu 22.04"),
        create_full_node("worker-2", worker_labels.clone(), true, "amd64", "Ubuntu 22.04"),
        create_full_node("worker-3", worker_labels, false, "amd64", "Ubuntu 22.04"),
    ];

    let summary = build_node_summary(&nodes);

    assert_eq!(summary.total, 4);
    assert_eq!(summary.ready, 3);
    assert_eq!(summary.control_plane, 1);
    assert_eq!(summary.workers, 3);
}

#[test]
fn test_build_node_summary_mixed_architectures() {
    let nodes = vec![
        create_full_node("node-1", BTreeMap::new(), true, "amd64", "Ubuntu 22.04"),
        create_full_node("node-2", BTreeMap::new(), true, "arm64", "Ubuntu 22.04"),
    ];

    let summary = build_node_summary(&nodes);

    assert_eq!(summary.architectures.len(), 2);
    assert!(summary.architectures.contains(&"amd64".to_string()));
    assert!(summary.architectures.contains(&"arm64".to_string()));
}

#[test]
fn test_build_node_summary_with_instance_types() {
    let mut labels1 = BTreeMap::new();
    labels1.insert("node.kubernetes.io/instance-type".to_string(), "m5.large".to_string());

    let mut labels2 = BTreeMap::new();
    labels2.insert("node.kubernetes.io/instance-type".to_string(), "m5.xlarge".to_string());

    let mut labels3 = BTreeMap::new();
    labels3.insert("node.kubernetes.io/instance-type".to_string(), "m5.large".to_string());

    let nodes = vec![
        create_full_node("node-1", labels1, true, "amd64", "Ubuntu"),
        create_full_node("node-2", labels2, true, "amd64", "Ubuntu"),
        create_full_node("node-3", labels3, true, "amd64", "Ubuntu"),
    ];

    let summary = build_node_summary(&nodes);

    assert_eq!(summary.instance_types.get("m5.large"), Some(&2));
    assert_eq!(summary.instance_types.get("m5.xlarge"), Some(&1));
}

#[test]
fn test_build_node_summary_empty_nodes() {
    let nodes: Vec<Node> = vec![];
    let summary = build_node_summary(&nodes);

    assert_eq!(summary.total, 0);
    assert_eq!(summary.ready, 0);
    assert_eq!(summary.control_plane, 0);
    assert_eq!(summary.workers, 0);
}

#[test]
fn test_build_node_summary_os_images() {
    let nodes = vec![
        create_full_node("node-1", BTreeMap::new(), true, "amd64", "Ubuntu 22.04"),
        create_full_node("node-2", BTreeMap::new(), true, "amd64", "Amazon Linux 2"),
        create_full_node("node-3", BTreeMap::new(), true, "amd64", "Ubuntu 22.04"),
    ];

    let summary = build_node_summary(&nodes);

    assert_eq!(summary.os_images.get("Ubuntu 22.04"), Some(&2));
    assert_eq!(summary.os_images.get("Amazon Linux 2"), Some(&1));
}

// ============================================================================
// is_cloud_provider tests
// ============================================================================

use kubecontrol::debug::cloud::is_cloud_provider;

#[test]
fn test_is_cloud_provider_aws_true() {
    let mut labels = BTreeMap::new();
    labels.insert("eks.amazonaws.com/nodegroup".to_string(), "ng".to_string());

    let nodes = vec![create_node_with_labels("node-1", labels)];

    assert!(is_cloud_provider(&nodes, CloudProvider::AWS));
}

#[test]
fn test_is_cloud_provider_aws_false() {
    let mut labels = BTreeMap::new();
    labels.insert("cloud.google.com/gke-nodepool".to_string(), "pool".to_string());

    let nodes = vec![create_node_with_labels("node-1", labels)];

    assert!(!is_cloud_provider(&nodes, CloudProvider::AWS));
}

#[test]
fn test_is_cloud_provider_gcp_true() {
    let mut labels = BTreeMap::new();
    labels.insert("cloud.google.com/gke-nodepool".to_string(), "pool".to_string());

    let nodes = vec![create_node_with_labels("node-1", labels)];

    assert!(is_cloud_provider(&nodes, CloudProvider::GCP));
}

#[test]
fn test_is_cloud_provider_azure_true() {
    let mut labels = BTreeMap::new();
    labels.insert("kubernetes.azure.com/agentpool".to_string(), "pool".to_string());

    let nodes = vec![create_node_with_labels("node-1", labels)];

    assert!(is_cloud_provider(&nodes, CloudProvider::Azure));
}

// ============================================================================
// ClusterInfo::is_managed tests
// ============================================================================

use kubecontrol::debug::cloud::{ClusterInfo, NodeSummary};
use std::collections::HashMap;

fn create_cluster_info(distribution: KubernetesDistribution) -> ClusterInfo {
    ClusterInfo {
        kubernetes_version: "v1.28".to_string(),
        platform: distribution,
        cloud_provider: None,
        region: None,
        zone: None,
        cluster_name: None,
        cluster_id: None,
        api_server_url: "https://kubernetes.default.svc".to_string(),
        nodes: NodeSummary::default(),
        components: vec![],
        metadata: HashMap::new(),
    }
}

#[test]
fn test_cluster_info_is_managed_eks() {
    let info = create_cluster_info(KubernetesDistribution::EKS);
    assert!(info.is_managed());
}

#[test]
fn test_cluster_info_is_managed_gke() {
    let info = create_cluster_info(KubernetesDistribution::GKE);
    assert!(info.is_managed());
}

#[test]
fn test_cluster_info_is_managed_aks() {
    let info = create_cluster_info(KubernetesDistribution::AKS);
    assert!(info.is_managed());
}

#[test]
fn test_cluster_info_is_managed_doks() {
    let info = create_cluster_info(KubernetesDistribution::DOKS);
    assert!(info.is_managed());
}

#[test]
fn test_cluster_info_is_managed_oke() {
    let info = create_cluster_info(KubernetesDistribution::OKE);
    assert!(info.is_managed());
}

#[test]
fn test_cluster_info_is_managed_iks() {
    let info = create_cluster_info(KubernetesDistribution::IKS);
    assert!(info.is_managed());
}

#[test]
fn test_cluster_info_is_managed_ack() {
    let info = create_cluster_info(KubernetesDistribution::ACK);
    assert!(info.is_managed());
}

#[test]
fn test_cluster_info_is_not_managed_kubeadm() {
    let info = create_cluster_info(KubernetesDistribution::Kubeadm);
    assert!(!info.is_managed());
}

#[test]
fn test_cluster_info_is_not_managed_rke() {
    let info = create_cluster_info(KubernetesDistribution::RKE);
    assert!(!info.is_managed());
}

#[test]
fn test_cluster_info_is_not_managed_k3s() {
    let info = create_cluster_info(KubernetesDistribution::K3s);
    assert!(!info.is_managed());
}

#[test]
fn test_cluster_info_is_not_managed_kind() {
    let info = create_cluster_info(KubernetesDistribution::Kind);
    assert!(!info.is_managed());
}

#[test]
fn test_cluster_info_is_not_managed_unknown() {
    let info = create_cluster_info(KubernetesDistribution::Unknown);
    assert!(!info.is_managed());
}

// ============================================================================
// New cloud provider display tests (Hetzner, Linode, Civo, Vultr, Scaleway, Exoscale)
// ============================================================================

#[test]
fn test_cloud_provider_display_hetzner() {
    assert_eq!(format!("{}", CloudProvider::Hetzner), "Hetzner Cloud");
}

#[test]
fn test_cloud_provider_display_linode() {
    assert_eq!(format!("{}", CloudProvider::Linode), "Linode (Akamai)");
}

#[test]
fn test_cloud_provider_display_civo() {
    assert_eq!(format!("{}", CloudProvider::Civo), "Civo");
}

#[test]
fn test_cloud_provider_display_vultr() {
    assert_eq!(format!("{}", CloudProvider::Vultr), "Vultr");
}

#[test]
fn test_cloud_provider_display_scaleway() {
    assert_eq!(format!("{}", CloudProvider::Scaleway), "Scaleway");
}

#[test]
fn test_cloud_provider_display_exoscale() {
    assert_eq!(format!("{}", CloudProvider::Exoscale), "Exoscale");
}

// ============================================================================
// New cloud provider detection tests (from provider ID)
// ============================================================================

#[test]
fn test_detect_hetzner_from_provider_id() {
    let nodes = vec![create_node_with_provider_id("node-1", "hcloud://12345678")];
    let provider = detect_cloud_provider(&nodes);

    assert_eq!(provider, Some(CloudProvider::Hetzner));
}

#[test]
fn test_detect_linode_from_provider_id() {
    let nodes = vec![create_node_with_provider_id("node-1", "linode://12345678")];
    let provider = detect_cloud_provider(&nodes);

    assert_eq!(provider, Some(CloudProvider::Linode));
}

#[test]
fn test_detect_civo_from_provider_id() {
    let nodes = vec![create_node_with_provider_id("node-1", "civo://abc123-def456")];
    let provider = detect_cloud_provider(&nodes);

    assert_eq!(provider, Some(CloudProvider::Civo));
}

#[test]
fn test_detect_vultr_from_provider_id() {
    let nodes = vec![create_node_with_provider_id("node-1", "vultr://abc123-def456")];
    let provider = detect_cloud_provider(&nodes);

    assert_eq!(provider, Some(CloudProvider::Vultr));
}

#[test]
fn test_detect_scaleway_from_provider_id() {
    let nodes = vec![create_node_with_provider_id("node-1", "scaleway://instance/fr-par-1/abc123")];
    let provider = detect_cloud_provider(&nodes);

    assert_eq!(provider, Some(CloudProvider::Scaleway));
}

#[test]
fn test_detect_exoscale_from_provider_id() {
    let nodes = vec![create_node_with_provider_id("node-1", "exoscale://abc123-def456")];
    let provider = detect_cloud_provider(&nodes);

    assert_eq!(provider, Some(CloudProvider::Exoscale));
}

// ============================================================================
// New distribution display tests
// ============================================================================

#[test]
fn test_distribution_display_k0s() {
    assert_eq!(format!("{}", KubernetesDistribution::K0s), "k0s");
}

#[test]
fn test_distribution_display_talos() {
    assert_eq!(format!("{}", KubernetesDistribution::Talos), "Talos Linux");
}

#[test]
fn test_distribution_display_tanzu_tkg() {
    assert_eq!(format!("{}", KubernetesDistribution::TanzuTKG), "VMware Tanzu (TKG)");
}

#[test]
fn test_distribution_display_rancher_desktop() {
    assert_eq!(format!("{}", KubernetesDistribution::RancherDesktop), "Rancher Desktop");
}

#[test]
fn test_distribution_display_lke() {
    assert_eq!(format!("{}", KubernetesDistribution::LKE), "Linode LKE");
}

#[test]
fn test_distribution_display_civo_k8s() {
    assert_eq!(format!("{}", KubernetesDistribution::CivoK8s), "Civo Kubernetes");
}

#[test]
fn test_distribution_display_hetzner_k8s() {
    assert_eq!(format!("{}", KubernetesDistribution::HetznerK8s), "Hetzner Kubernetes");
}

// ============================================================================
// New managed distribution tests
// ============================================================================

#[test]
fn test_cluster_info_is_managed_lke() {
    let info = create_cluster_info(KubernetesDistribution::LKE);
    assert!(info.is_managed());
}

#[test]
fn test_cluster_info_is_managed_civo_k8s() {
    let info = create_cluster_info(KubernetesDistribution::CivoK8s);
    assert!(info.is_managed());
}

#[test]
fn test_cluster_info_is_managed_hetzner_k8s() {
    let info = create_cluster_info(KubernetesDistribution::HetznerK8s);
    assert!(info.is_managed());
}

#[test]
fn test_cluster_info_is_not_managed_k0s() {
    let info = create_cluster_info(KubernetesDistribution::K0s);
    assert!(!info.is_managed());
}

#[test]
fn test_cluster_info_is_not_managed_talos() {
    let info = create_cluster_info(KubernetesDistribution::Talos);
    assert!(!info.is_managed());
}

#[test]
fn test_cluster_info_is_not_managed_tanzu_tkg() {
    let info = create_cluster_info(KubernetesDistribution::TanzuTKG);
    assert!(!info.is_managed());
}

#[test]
fn test_cluster_info_is_not_managed_rancher_desktop() {
    let info = create_cluster_info(KubernetesDistribution::RancherDesktop);
    assert!(!info.is_managed());
}

// ============================================================================
// Container OS detection tests
// ============================================================================

use kubecontrol::debug::cloud::detect_container_os;

#[test]
fn test_detect_container_os_talos() {
    let nodes = vec![create_full_node("node-1", BTreeMap::new(), true, "amd64", "Talos (v1.6.4)")];
    let os = detect_container_os(&nodes);
    assert_eq!(os, Some("Talos Linux".to_string()));
}

#[test]
fn test_detect_container_os_flatcar() {
    let nodes = vec![create_full_node("node-1", BTreeMap::new(), true, "amd64", "Flatcar Container Linux 3510.2.1")];
    let os = detect_container_os(&nodes);
    assert_eq!(os, Some("Flatcar Container Linux".to_string()));
}

#[test]
fn test_detect_container_os_bottlerocket() {
    let nodes = vec![create_full_node("node-1", BTreeMap::new(), true, "amd64", "Bottlerocket OS 1.15.1")];
    let os = detect_container_os(&nodes);
    assert_eq!(os, Some("Bottlerocket".to_string()));
}

#[test]
fn test_detect_container_os_cos() {
    let nodes = vec![create_full_node("node-1", BTreeMap::new(), true, "amd64", "Container-Optimized OS from Google")];
    let os = detect_container_os(&nodes);
    assert_eq!(os, Some("Container-Optimized OS (Google)".to_string()));
}

#[test]
fn test_detect_container_os_rhcos() {
    let nodes = vec![create_full_node("node-1", BTreeMap::new(), true, "amd64", "Red Hat Enterprise Linux CoreOS 413.92")];
    let os = detect_container_os(&nodes);
    assert_eq!(os, Some("Red Hat CoreOS".to_string()));
}

#[test]
fn test_detect_container_os_none_for_ubuntu() {
    let nodes = vec![create_full_node("node-1", BTreeMap::new(), true, "amd64", "Ubuntu 22.04.3 LTS")];
    let os = detect_container_os(&nodes);
    assert_eq!(os, None);
}

#[test]
fn test_detect_container_os_empty_nodes() {
    let nodes: Vec<Node> = vec![];
    let os = detect_container_os(&nodes);
    assert_eq!(os, None);
}

// ============================================================================
// Cloud provider serialization tests for new providers
// ============================================================================

#[test]
fn test_cloud_provider_json_serialization_hetzner() {
    let provider = CloudProvider::Hetzner;
    let json = serde_json::to_string(&provider).unwrap();
    assert_eq!(json, "\"hetzner\"");
}

#[test]
fn test_cloud_provider_json_serialization_linode() {
    let provider = CloudProvider::Linode;
    let json = serde_json::to_string(&provider).unwrap();
    assert_eq!(json, "\"linode\"");
}

#[test]
fn test_cloud_provider_json_serialization_civo() {
    let provider = CloudProvider::Civo;
    let json = serde_json::to_string(&provider).unwrap();
    assert_eq!(json, "\"civo\"");
}

#[test]
fn test_distribution_json_serialization_k0s() {
    let dist = KubernetesDistribution::K0s;
    let json = serde_json::to_string(&dist).unwrap();
    assert_eq!(json, "\"k0s\"");
}

#[test]
fn test_distribution_json_serialization_talos() {
    let dist = KubernetesDistribution::Talos;
    let json = serde_json::to_string(&dist).unwrap();
    assert_eq!(json, "\"talos\"");
}

#[test]
fn test_distribution_json_serialization_lke() {
    let dist = KubernetesDistribution::LKE;
    let json = serde_json::to_string(&dist).unwrap();
    assert_eq!(json, "\"lke\"");
}

// ============================================================================
// EKS detection tests
// ============================================================================

use kubecontrol::debug::eks::is_eks;

#[test]
fn test_is_eks_with_nodegroup_label() {
    let mut labels = BTreeMap::new();
    labels.insert("eks.amazonaws.com/nodegroup".to_string(), "my-nodegroup".to_string());

    let nodes = vec![create_node_with_labels("node-1", labels)];
    assert!(is_eks(&nodes));
}

#[test]
fn test_is_eks_with_eksctl_label() {
    let mut labels = BTreeMap::new();
    labels.insert("alpha.eksctl.io/nodegroup-name".to_string(), "ng-1".to_string());

    let nodes = vec![create_node_with_labels("node-1", labels)];
    assert!(is_eks(&nodes));
}

#[test]
fn test_is_eks_with_aws_provider_id() {
    let nodes = vec![create_node_with_provider_id("node-1", "aws:///us-west-2a/i-1234567890abcdef0")];
    assert!(is_eks(&nodes));
}

#[test]
fn test_is_eks_with_nodegroup_image_label() {
    let mut labels = BTreeMap::new();
    labels.insert("eks.amazonaws.com/nodegroup-image".to_string(), "ami-12345".to_string());

    let nodes = vec![create_node_with_labels("node-1", labels)];
    assert!(is_eks(&nodes));
}

#[test]
fn test_is_eks_false_for_gke() {
    let mut labels = BTreeMap::new();
    labels.insert("cloud.google.com/gke-nodepool".to_string(), "default-pool".to_string());

    let nodes = vec![create_node_with_labels("node-1", labels)];
    assert!(!is_eks(&nodes));
}

#[test]
fn test_is_eks_false_for_aks() {
    let mut labels = BTreeMap::new();
    labels.insert("kubernetes.azure.com/agentpool".to_string(), "nodepool1".to_string());

    let nodes = vec![create_node_with_labels("node-1", labels)];
    assert!(!is_eks(&nodes));
}

#[test]
fn test_is_eks_false_for_vanilla_cluster() {
    let nodes = vec![create_node_with_labels("node-1", BTreeMap::new())];
    assert!(!is_eks(&nodes));
}

#[test]
fn test_is_eks_false_for_empty_nodes() {
    let nodes: Vec<Node> = vec![];
    assert!(!is_eks(&nodes));
}

#[test]
fn test_is_eks_with_multiple_nodes_one_eks() {
    let mut eks_labels = BTreeMap::new();
    eks_labels.insert("eks.amazonaws.com/nodegroup".to_string(), "ng".to_string());

    let nodes = vec![
        create_node_with_labels("node-1", BTreeMap::new()),
        create_node_with_labels("node-2", eks_labels),
    ];
    assert!(is_eks(&nodes));
}
