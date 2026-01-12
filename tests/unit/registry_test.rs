//! Tests for src/resources/registry.rs - ResourceRegistry

use kubecontrol::resources::RESOURCE_REGISTRY;

// ============================================================================
// lookup by kind tests
// ============================================================================

#[test]
fn test_lookup_pod_by_kind() {
    let info = RESOURCE_REGISTRY.lookup("Pod").unwrap();
    assert_eq!(info.kind, "Pod");
    assert_eq!(info.plural, "pods");
    assert!(info.namespaced);
}

#[test]
fn test_lookup_deployment_by_kind() {
    let info = RESOURCE_REGISTRY.lookup("Deployment").unwrap();
    assert_eq!(info.kind, "Deployment");
    assert_eq!(info.group, "apps");
    assert_eq!(info.plural, "deployments");
}

#[test]
fn test_lookup_service_by_kind() {
    let info = RESOURCE_REGISTRY.lookup("Service").unwrap();
    assert_eq!(info.kind, "Service");
    assert_eq!(info.plural, "services");
}

#[test]
fn test_lookup_configmap_by_kind() {
    let info = RESOURCE_REGISTRY.lookup("ConfigMap").unwrap();
    assert_eq!(info.kind, "ConfigMap");
    assert_eq!(info.plural, "configmaps");
}

#[test]
fn test_lookup_secret_by_kind() {
    let info = RESOURCE_REGISTRY.lookup("Secret").unwrap();
    assert_eq!(info.kind, "Secret");
    assert_eq!(info.plural, "secrets");
}

#[test]
fn test_lookup_namespace_by_kind() {
    let info = RESOURCE_REGISTRY.lookup("Namespace").unwrap();
    assert_eq!(info.kind, "Namespace");
    assert!(!info.namespaced); // Namespace is cluster-scoped
}

#[test]
fn test_lookup_node_by_kind() {
    let info = RESOURCE_REGISTRY.lookup("Node").unwrap();
    assert_eq!(info.kind, "Node");
    assert!(!info.namespaced); // Node is cluster-scoped
}

// ============================================================================
// lookup by plural tests
// ============================================================================

#[test]
fn test_lookup_pods_by_plural() {
    let info = RESOURCE_REGISTRY.lookup("pods").unwrap();
    assert_eq!(info.kind, "Pod");
}

#[test]
fn test_lookup_deployments_by_plural() {
    let info = RESOURCE_REGISTRY.lookup("deployments").unwrap();
    assert_eq!(info.kind, "Deployment");
}

#[test]
fn test_lookup_services_by_plural() {
    let info = RESOURCE_REGISTRY.lookup("services").unwrap();
    assert_eq!(info.kind, "Service");
}

#[test]
fn test_lookup_configmaps_by_plural() {
    let info = RESOURCE_REGISTRY.lookup("configmaps").unwrap();
    assert_eq!(info.kind, "ConfigMap");
}

#[test]
fn test_lookup_secrets_by_plural() {
    let info = RESOURCE_REGISTRY.lookup("secrets").unwrap();
    assert_eq!(info.kind, "Secret");
}

#[test]
fn test_lookup_namespaces_by_plural() {
    let info = RESOURCE_REGISTRY.lookup("namespaces").unwrap();
    assert_eq!(info.kind, "Namespace");
}

#[test]
fn test_lookup_nodes_by_plural() {
    let info = RESOURCE_REGISTRY.lookup("nodes").unwrap();
    assert_eq!(info.kind, "Node");
}

// ============================================================================
// lookup by alias tests
// ============================================================================

#[test]
fn test_lookup_pod_by_alias_po() {
    let info = RESOURCE_REGISTRY.lookup("po").unwrap();
    assert_eq!(info.kind, "Pod");
}

#[test]
fn test_lookup_deployment_by_alias_deploy() {
    let info = RESOURCE_REGISTRY.lookup("deploy").unwrap();
    assert_eq!(info.kind, "Deployment");
}

#[test]
fn test_lookup_service_by_alias_svc() {
    let info = RESOURCE_REGISTRY.lookup("svc").unwrap();
    assert_eq!(info.kind, "Service");
}

#[test]
fn test_lookup_configmap_by_alias_cm() {
    let info = RESOURCE_REGISTRY.lookup("cm").unwrap();
    assert_eq!(info.kind, "ConfigMap");
}

#[test]
fn test_lookup_namespace_by_alias_ns() {
    let info = RESOURCE_REGISTRY.lookup("ns").unwrap();
    assert_eq!(info.kind, "Namespace");
}

#[test]
fn test_lookup_node_by_alias_no() {
    let info = RESOURCE_REGISTRY.lookup("no").unwrap();
    assert_eq!(info.kind, "Node");
}

#[test]
fn test_lookup_statefulset_by_alias_sts() {
    let info = RESOURCE_REGISTRY.lookup("sts").unwrap();
    assert_eq!(info.kind, "StatefulSet");
}

#[test]
fn test_lookup_daemonset_by_alias_ds() {
    let info = RESOURCE_REGISTRY.lookup("ds").unwrap();
    assert_eq!(info.kind, "DaemonSet");
}

#[test]
fn test_lookup_replicaset_by_alias_rs() {
    let info = RESOURCE_REGISTRY.lookup("rs").unwrap();
    assert_eq!(info.kind, "ReplicaSet");
}

// ============================================================================
// case insensitivity tests
// ============================================================================

#[test]
fn test_lookup_case_insensitive_uppercase() {
    let info = RESOURCE_REGISTRY.lookup("PODS").unwrap();
    assert_eq!(info.kind, "Pod");
}

#[test]
fn test_lookup_case_insensitive_mixed_case() {
    let info = RESOURCE_REGISTRY.lookup("PoDs").unwrap();
    assert_eq!(info.kind, "Pod");
}

#[test]
fn test_lookup_case_insensitive_kind() {
    let info = RESOURCE_REGISTRY.lookup("pod").unwrap();
    assert_eq!(info.kind, "Pod");
}

#[test]
fn test_lookup_case_insensitive_alias() {
    let info = RESOURCE_REGISTRY.lookup("PO").unwrap();
    assert_eq!(info.kind, "Pod");
}

// ============================================================================
// invalid lookup tests
// ============================================================================

#[test]
fn test_lookup_nonexistent_resource() {
    let result = RESOURCE_REGISTRY.lookup("nonexistent");
    assert!(result.is_none());
}

#[test]
fn test_lookup_empty_string() {
    let result = RESOURCE_REGISTRY.lookup("");
    assert!(result.is_none());
}

#[test]
fn test_lookup_partial_name() {
    let result = RESOURCE_REGISTRY.lookup("pod"); // "pod" should work (alias)
    assert!(result.is_some());
}

// ============================================================================
// all() tests
// ============================================================================

#[test]
fn test_all_returns_all_resources() {
    let all: Vec<_> = RESOURCE_REGISTRY.all().collect();

    // Should have at least core resources
    assert!(all.len() >= 10);

    // Should include common resources
    let kinds: Vec<_> = all.iter().map(|r| r.kind).collect();
    assert!(kinds.contains(&"Pod"));
    assert!(kinds.contains(&"Deployment"));
    assert!(kinds.contains(&"Service"));
    assert!(kinds.contains(&"ConfigMap"));
    assert!(kinds.contains(&"Namespace"));
    assert!(kinds.contains(&"Node"));
}

#[test]
fn test_all_has_unique_kinds() {
    let all: Vec<_> = RESOURCE_REGISTRY.all().collect();
    let kinds: Vec<_> = all.iter().map(|r| r.kind).collect();

    // Check for unique kinds
    let mut sorted_kinds = kinds.clone();
    sorted_kinds.sort();
    sorted_kinds.dedup();
    assert_eq!(kinds.len(), sorted_kinds.len());
}

// ============================================================================
// all_names() tests
// ============================================================================

#[test]
fn test_all_names_returns_plurals_and_aliases() {
    let names = RESOURCE_REGISTRY.all_names();

    // Should include plural names
    assert!(names.contains(&"pods"));
    assert!(names.contains(&"deployments"));
    assert!(names.contains(&"services"));

    // Should include aliases
    assert!(names.contains(&"po"));
    assert!(names.contains(&"deploy"));
    assert!(names.contains(&"svc"));
    assert!(names.contains(&"cm"));
    assert!(names.contains(&"ns"));
}

#[test]
fn test_all_names_sorted() {
    let names = RESOURCE_REGISTRY.all_names();

    // Names should be sorted
    let mut sorted = names.clone();
    sorted.sort();
    assert_eq!(names, sorted);
}

#[test]
fn test_all_names_no_duplicates() {
    let names = RESOURCE_REGISTRY.all_names();

    // Should have no duplicates
    let mut unique = names.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(names.len(), unique.len());
}

// ============================================================================
// ResourceInfo tests
// ============================================================================

#[test]
fn test_resource_info_pod() {
    let info = RESOURCE_REGISTRY.lookup("pods").unwrap();
    assert_eq!(info.kind, "Pod");
    assert_eq!(info.group, "");
    assert_eq!(info.version, "v1");
    assert_eq!(info.plural, "pods");
    assert!(info.aliases.contains(&"po"));
    assert!(info.namespaced);
}

#[test]
fn test_resource_info_deployment() {
    let info = RESOURCE_REGISTRY.lookup("deployments").unwrap();
    assert_eq!(info.kind, "Deployment");
    assert_eq!(info.group, "apps");
    assert_eq!(info.version, "v1");
    assert_eq!(info.plural, "deployments");
    assert!(info.aliases.contains(&"deploy"));
    assert!(info.namespaced);
}

#[test]
fn test_resource_info_statefulset() {
    let info = RESOURCE_REGISTRY.lookup("statefulsets").unwrap();
    assert_eq!(info.kind, "StatefulSet");
    assert_eq!(info.group, "apps");
    assert!(info.aliases.contains(&"sts"));
    assert!(info.namespaced);
}

#[test]
fn test_resource_info_daemonset() {
    let info = RESOURCE_REGISTRY.lookup("daemonsets").unwrap();
    assert_eq!(info.kind, "DaemonSet");
    assert_eq!(info.group, "apps");
    assert!(info.aliases.contains(&"ds"));
    assert!(info.namespaced);
}

#[test]
fn test_resource_info_replicaset() {
    let info = RESOURCE_REGISTRY.lookup("replicasets").unwrap();
    assert_eq!(info.kind, "ReplicaSet");
    assert_eq!(info.group, "apps");
    assert!(info.aliases.contains(&"rs"));
    assert!(info.namespaced);
}

#[test]
fn test_resource_info_clone() {
    let info = RESOURCE_REGISTRY.lookup("pods").unwrap();
    let cloned = info.clone();
    assert_eq!(info.kind, cloned.kind);
    assert_eq!(info.group, cloned.group);
    assert_eq!(info.plural, cloned.plural);
}
