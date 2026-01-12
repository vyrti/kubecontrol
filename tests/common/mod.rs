// Common test utilities and helpers

use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use chrono::{Utc, Duration as ChronoDuration};

/// Create a mock Pod for testing
pub fn create_mock_pod(name: &str, namespace: &str, status: &str) -> Pod {
    Pod {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            creation_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                Utc::now() - ChronoDuration::hours(1),
            )),
            ..Default::default()
        },
        status: Some(k8s_openapi::api::core::v1::PodStatus {
            phase: Some(status.to_string()),
            ..Default::default()
        }),
        spec: Some(k8s_openapi::api::core::v1::PodSpec {
            containers: vec![k8s_openapi::api::core::v1::Container {
                name: "main".to_string(),
                image: Some("nginx:latest".to_string()),
                ..Default::default()
            }],
            ..Default::default()
        }),
    }
}

/// Create a mock Pod with specific age
pub fn create_mock_pod_with_age(name: &str, namespace: &str, status: &str, hours_ago: i64) -> Pod {
    let mut pod = create_mock_pod(name, namespace, status);
    pod.metadata.creation_timestamp = Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
        Utc::now() - ChronoDuration::hours(hours_ago),
    ));
    pod
}

/// Create a mock Deployment for testing
pub fn create_mock_deployment(name: &str, namespace: &str, replicas: i32) -> k8s_openapi::api::apps::v1::Deployment {
    use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec, DeploymentStatus};

    Deployment {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            creation_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                Utc::now() - ChronoDuration::days(1),
            )),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(replicas),
            selector: k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector {
                match_labels: Some([("app".to_string(), name.to_string())].into()),
                ..Default::default()
            },
            template: k8s_openapi::api::core::v1::PodTemplateSpec::default(),
            ..Default::default()
        }),
        status: Some(DeploymentStatus {
            replicas: Some(replicas),
            ready_replicas: Some(replicas),
            available_replicas: Some(replicas),
            ..Default::default()
        }),
    }
}

/// Create a mock Service for testing
pub fn create_mock_service(name: &str, namespace: &str, service_type: &str) -> k8s_openapi::api::core::v1::Service {
    use k8s_openapi::api::core::v1::{Service, ServiceSpec, ServicePort};

    Service {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            creation_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                Utc::now() - ChronoDuration::hours(12),
            )),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            type_: Some(service_type.to_string()),
            ports: Some(vec![ServicePort {
                port: 80,
                target_port: Some(k8s_openapi::apimachinery::pkg::util::intstr::IntOrString::Int(8080)),
                protocol: Some("TCP".to_string()),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        status: None,
    }
}

/// Create a mock ConfigMap for testing
pub fn create_mock_configmap(name: &str, namespace: &str, data: Vec<(&str, &str)>) -> k8s_openapi::api::core::v1::ConfigMap {
    use k8s_openapi::api::core::v1::ConfigMap;

    ConfigMap {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            creation_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                Utc::now() - ChronoDuration::hours(6),
            )),
            ..Default::default()
        },
        data: Some(data.into_iter().map(|(k, v)| (k.to_string(), v.to_string())).collect()),
        ..Default::default()
    }
}

/// Create a mock Namespace for testing
pub fn create_mock_namespace(name: &str, status: &str) -> k8s_openapi::api::core::v1::Namespace {
    use k8s_openapi::api::core::v1::{Namespace, NamespaceStatus};

    Namespace {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            creation_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                Utc::now() - ChronoDuration::days(30),
            )),
            ..Default::default()
        },
        spec: None,
        status: Some(NamespaceStatus {
            phase: Some(status.to_string()),
            ..Default::default()
        }),
    }
}

/// Create a mock Node for testing
pub fn create_mock_node(name: &str, ready: bool) -> k8s_openapi::api::core::v1::Node {
    use k8s_openapi::api::core::v1::{Node, NodeStatus, NodeCondition, NodeAddress};

    Node {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            creation_timestamp: Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                Utc::now() - ChronoDuration::days(7),
            )),
            ..Default::default()
        },
        spec: None,
        status: Some(NodeStatus {
            conditions: Some(vec![NodeCondition {
                type_: "Ready".to_string(),
                status: if ready { "True" } else { "False" }.to_string(),
                ..Default::default()
            }]),
            addresses: Some(vec![NodeAddress {
                type_: "InternalIP".to_string(),
                address: "10.0.0.1".to_string(),
            }]),
            ..Default::default()
        }),
    }
}

/// Check if running in a Kubernetes environment (has kubeconfig)
pub fn has_kubeconfig() -> bool {
    std::env::var("KUBECONFIG").is_ok()
        || std::path::Path::new(&format!(
            "{}/.kube/config",
            std::env::var("HOME").unwrap_or_default()
        ))
        .exists()
}
