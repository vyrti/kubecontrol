//! Tests for resource trait implementations

use kubecontrol::resources::{KubeResource, Tabular, Execable};
use k8s_openapi::api::core::v1::{Pod, Service, ConfigMap, Secret, Namespace, Node};
use k8s_openapi::api::apps::v1::{Deployment, StatefulSet, DaemonSet, ReplicaSet};

mod common {
    include!("../common/mod.rs");
}

// ============================================================================
// Pod KubeResource trait tests
// ============================================================================

#[test]
fn test_pod_kind() {
    assert_eq!(Pod::KIND, "Pod");
}

#[test]
fn test_pod_group() {
    assert_eq!(Pod::GROUP, "");
}

#[test]
fn test_pod_version() {
    assert_eq!(Pod::VERSION, "v1");
}

#[test]
fn test_pod_plural() {
    assert_eq!(Pod::PLURAL, "pods");
}

#[test]
fn test_pod_aliases() {
    assert!(Pod::ALIASES.contains(&"po"));
    assert!(Pod::ALIASES.contains(&"pod"));
}

#[test]
fn test_pod_namespaced() {
    assert!(Pod::NAMESPACED);
}

#[test]
fn test_pod_name() {
    let pod = common::create_mock_pod("test-pod", "default", "Running");
    assert_eq!(pod.name(), "test-pod");
}

#[test]
fn test_pod_namespace() {
    let pod = common::create_mock_pod("test-pod", "default", "Running");
    assert_eq!(pod.namespace(), Some("default"));
}

#[test]
fn test_pod_age() {
    let pod = common::create_mock_pod("test-pod", "default", "Running");
    let age = pod.age();
    // Age should be "1h" since we created it 1 hour ago
    assert_eq!(age, "1h");
}

// ============================================================================
// Pod Tabular trait tests
// ============================================================================

#[test]
fn test_pod_headers() {
    let headers = Pod::headers();
    assert_eq!(headers.len(), 5);
    assert!(headers.contains(&"NAME"));
    assert!(headers.contains(&"READY"));
    assert!(headers.contains(&"STATUS"));
    assert!(headers.contains(&"RESTARTS"));
    assert!(headers.contains(&"AGE"));
}

#[test]
fn test_pod_headers_wide() {
    let headers = Pod::headers_wide();
    assert_eq!(headers.len(), 7);
    assert!(headers.contains(&"NAME"));
    assert!(headers.contains(&"IP"));
    assert!(headers.contains(&"NODE"));
}

#[test]
fn test_pod_row() {
    let pod = common::create_mock_pod("test-pod", "default", "Running");
    let row = pod.row();
    assert_eq!(row.len(), 5);
    assert_eq!(row[0], "test-pod");
    // Row should contain ready count, status, restarts, age
}

#[test]
fn test_pod_row_wide() {
    let pod = common::create_mock_pod("test-pod", "default", "Running");
    let row = pod.row_wide();
    assert_eq!(row.len(), 7);
    assert_eq!(row[0], "test-pod");
}

// ============================================================================
// Pod Execable trait tests
// ============================================================================

#[test]
fn test_pod_containers() {
    let pod = common::create_mock_pod("test-pod", "default", "Running");
    let containers = pod.containers();
    assert_eq!(containers.len(), 1);
    assert_eq!(containers[0], "main");
}

#[test]
fn test_pod_default_container() {
    let pod = common::create_mock_pod("test-pod", "default", "Running");
    let default = pod.default_container();
    assert_eq!(default, Some("main".to_string()));
}

// ============================================================================
// Service KubeResource trait tests
// ============================================================================

#[test]
fn test_service_kind() {
    assert_eq!(Service::KIND, "Service");
}

#[test]
fn test_service_group() {
    assert_eq!(Service::GROUP, "");
}

#[test]
fn test_service_version() {
    assert_eq!(Service::VERSION, "v1");
}

#[test]
fn test_service_plural() {
    assert_eq!(Service::PLURAL, "services");
}

#[test]
fn test_service_aliases() {
    assert!(Service::ALIASES.contains(&"svc"));
}

#[test]
fn test_service_namespaced() {
    assert!(Service::NAMESPACED);
}

#[test]
fn test_service_name() {
    let svc = common::create_mock_service("my-service", "default", "ClusterIP");
    assert_eq!(svc.name(), "my-service");
}

// ============================================================================
// Service Tabular trait tests
// ============================================================================

#[test]
fn test_service_headers() {
    let headers = Service::headers();
    assert!(headers.contains(&"NAME"));
    assert!(headers.contains(&"TYPE"));
}

#[test]
fn test_service_row() {
    let svc = common::create_mock_service("my-service", "default", "ClusterIP");
    let row = svc.row();
    assert!(!row.is_empty());
    assert_eq!(row[0], "my-service");
}

// ============================================================================
// ConfigMap KubeResource trait tests
// ============================================================================

#[test]
fn test_configmap_kind() {
    assert_eq!(ConfigMap::KIND, "ConfigMap");
}

#[test]
fn test_configmap_group() {
    assert_eq!(ConfigMap::GROUP, "");
}

#[test]
fn test_configmap_version() {
    assert_eq!(ConfigMap::VERSION, "v1");
}

#[test]
fn test_configmap_plural() {
    assert_eq!(ConfigMap::PLURAL, "configmaps");
}

#[test]
fn test_configmap_aliases() {
    assert!(ConfigMap::ALIASES.contains(&"cm"));
}

#[test]
fn test_configmap_namespaced() {
    assert!(ConfigMap::NAMESPACED);
}

// ============================================================================
// Secret KubeResource trait tests
// ============================================================================

#[test]
fn test_secret_kind() {
    assert_eq!(Secret::KIND, "Secret");
}

#[test]
fn test_secret_group() {
    assert_eq!(Secret::GROUP, "");
}

#[test]
fn test_secret_version() {
    assert_eq!(Secret::VERSION, "v1");
}

#[test]
fn test_secret_plural() {
    assert_eq!(Secret::PLURAL, "secrets");
}

#[test]
fn test_secret_namespaced() {
    assert!(Secret::NAMESPACED);
}

// ============================================================================
// Namespace KubeResource trait tests
// ============================================================================

#[test]
fn test_namespace_kind() {
    assert_eq!(Namespace::KIND, "Namespace");
}

#[test]
fn test_namespace_group() {
    assert_eq!(Namespace::GROUP, "");
}

#[test]
fn test_namespace_version() {
    assert_eq!(Namespace::VERSION, "v1");
}

#[test]
fn test_namespace_plural() {
    assert_eq!(Namespace::PLURAL, "namespaces");
}

#[test]
fn test_namespace_aliases() {
    assert!(Namespace::ALIASES.contains(&"ns"));
}

#[test]
fn test_namespace_not_namespaced() {
    assert!(!Namespace::NAMESPACED); // Namespace is cluster-scoped
}

// ============================================================================
// Node KubeResource trait tests
// ============================================================================

#[test]
fn test_node_kind() {
    assert_eq!(Node::KIND, "Node");
}

#[test]
fn test_node_group() {
    assert_eq!(Node::GROUP, "");
}

#[test]
fn test_node_version() {
    assert_eq!(Node::VERSION, "v1");
}

#[test]
fn test_node_plural() {
    assert_eq!(Node::PLURAL, "nodes");
}

#[test]
fn test_node_aliases() {
    assert!(Node::ALIASES.contains(&"no"));
}

#[test]
fn test_node_not_namespaced() {
    assert!(!Node::NAMESPACED); // Node is cluster-scoped
}

#[test]
fn test_node_name() {
    let node = common::create_mock_node("node-1", true);
    assert_eq!(node.name(), "node-1");
}

#[test]
fn test_node_namespace_is_none() {
    let node = common::create_mock_node("node-1", true);
    assert!(node.namespace().is_none());
}

// ============================================================================
// Deployment KubeResource trait tests
// ============================================================================

#[test]
fn test_deployment_kind() {
    assert_eq!(Deployment::KIND, "Deployment");
}

#[test]
fn test_deployment_group() {
    assert_eq!(Deployment::GROUP, "apps");
}

#[test]
fn test_deployment_version() {
    assert_eq!(Deployment::VERSION, "v1");
}

#[test]
fn test_deployment_plural() {
    assert_eq!(Deployment::PLURAL, "deployments");
}

#[test]
fn test_deployment_aliases() {
    assert!(Deployment::ALIASES.contains(&"deploy"));
}

#[test]
fn test_deployment_namespaced() {
    assert!(Deployment::NAMESPACED);
}

#[test]
fn test_deployment_name() {
    let deploy = common::create_mock_deployment("my-deployment", "default", 3);
    assert_eq!(deploy.name(), "my-deployment");
}

// ============================================================================
// StatefulSet KubeResource trait tests
// ============================================================================

#[test]
fn test_statefulset_kind() {
    assert_eq!(StatefulSet::KIND, "StatefulSet");
}

#[test]
fn test_statefulset_group() {
    assert_eq!(StatefulSet::GROUP, "apps");
}

#[test]
fn test_statefulset_version() {
    assert_eq!(StatefulSet::VERSION, "v1");
}

#[test]
fn test_statefulset_plural() {
    assert_eq!(StatefulSet::PLURAL, "statefulsets");
}

#[test]
fn test_statefulset_aliases() {
    assert!(StatefulSet::ALIASES.contains(&"sts"));
}

#[test]
fn test_statefulset_namespaced() {
    assert!(StatefulSet::NAMESPACED);
}

// ============================================================================
// DaemonSet KubeResource trait tests
// ============================================================================

#[test]
fn test_daemonset_kind() {
    assert_eq!(DaemonSet::KIND, "DaemonSet");
}

#[test]
fn test_daemonset_group() {
    assert_eq!(DaemonSet::GROUP, "apps");
}

#[test]
fn test_daemonset_version() {
    assert_eq!(DaemonSet::VERSION, "v1");
}

#[test]
fn test_daemonset_plural() {
    assert_eq!(DaemonSet::PLURAL, "daemonsets");
}

#[test]
fn test_daemonset_aliases() {
    assert!(DaemonSet::ALIASES.contains(&"ds"));
}

#[test]
fn test_daemonset_namespaced() {
    assert!(DaemonSet::NAMESPACED);
}

// ============================================================================
// ReplicaSet KubeResource trait tests
// ============================================================================

#[test]
fn test_replicaset_kind() {
    assert_eq!(ReplicaSet::KIND, "ReplicaSet");
}

#[test]
fn test_replicaset_group() {
    assert_eq!(ReplicaSet::GROUP, "apps");
}

#[test]
fn test_replicaset_version() {
    assert_eq!(ReplicaSet::VERSION, "v1");
}

#[test]
fn test_replicaset_plural() {
    assert_eq!(ReplicaSet::PLURAL, "replicasets");
}

#[test]
fn test_replicaset_aliases() {
    assert!(ReplicaSet::ALIASES.contains(&"rs"));
}

#[test]
fn test_replicaset_namespaced() {
    assert!(ReplicaSet::NAMESPACED);
}
