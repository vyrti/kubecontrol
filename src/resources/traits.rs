//! Core traits for Kubernetes resources

use crate::error::Result;
use async_trait::async_trait;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::{Api, Client, Resource};
use serde::{de::DeserializeOwned, Serialize};
use std::fmt::Debug;

/// Core trait that all Kubernetes resources implement
pub trait KubeResource:
    Clone + Debug + DeserializeOwned + Serialize + Send + Sync + Resource + 'static
{
    /// The Kubernetes API kind (e.g., "Pod", "Deployment")
    const KIND: &'static str;

    /// The API group (e.g., "", "apps", "batch")
    const GROUP: &'static str;

    /// The API version (e.g., "v1", "v1beta1")
    const VERSION: &'static str;

    /// Plural name for API path (e.g., "pods", "deployments")
    const PLURAL: &'static str;

    /// Short aliases (e.g., ["po"] for pods, ["deploy"] for deployments)
    const ALIASES: &'static [&'static str] = &[];

    /// Whether this resource is namespaced
    const NAMESPACED: bool;

    /// Get object metadata
    fn metadata(&self) -> &ObjectMeta;

    /// Get the resource name
    fn name(&self) -> &str {
        self.metadata()
            .name
            .as_deref()
            .unwrap_or("<unknown>")
    }

    /// Get the resource namespace (if namespaced)
    fn namespace(&self) -> Option<&str> {
        self.metadata().namespace.as_deref()
    }

    /// Get the creation timestamp as a human-readable age string
    fn age(&self) -> String {
        self.metadata()
            .creation_timestamp
            .as_ref()
            .map(|ts| humanize_duration(ts.0))
            .unwrap_or_else(|| "<unknown>".to_string())
    }
}

/// Trait for resources that can be listed
#[async_trait]
pub trait Listable: KubeResource {
    /// Create a kube Api handle for this resource
    fn api(client: Client, namespace: Option<&str>) -> Api<Self>
    where
        Self: Sized;

    /// Create an Api for all namespaces
    fn api_all(client: Client) -> Api<Self>
    where
        Self: Sized;

    /// List resources with optional label selector
    async fn list_resources(
        api: &Api<Self>,
        label_selector: Option<&str>,
        field_selector: Option<&str>,
    ) -> Result<Vec<Self>>
    where
        Self: Sized;
}

/// Trait for resources that have a meaningful table display
pub trait Tabular: KubeResource {
    /// Column headers for table output
    fn headers() -> Vec<&'static str>;

    /// Wide column headers (additional columns for -o wide)
    fn headers_wide() -> Vec<&'static str> {
        Self::headers()
    }

    /// Row values for table output
    fn row(&self) -> Vec<String>;

    /// Wide row values
    fn row_wide(&self) -> Vec<String> {
        self.row()
    }

    /// Get the status for coloring (e.g., "Running", "Pending", "Failed")
    fn status_for_color(&self) -> Option<&str> {
        None
    }
}

/// Trait for resources that can be described in detail
#[async_trait]
pub trait Describable: KubeResource {
    /// Generate a detailed description of the resource
    async fn describe(&self, client: &Client) -> Result<String>;
}

/// Trait for resources that have logs (primarily Pods)
#[async_trait]
pub trait Loggable: KubeResource {
    /// Get logs as a string
    async fn logs(
        &self,
        client: &Client,
        container: Option<&str>,
        tail_lines: Option<i64>,
        since_seconds: Option<i64>,
    ) -> Result<String>;
}

/// Trait for resources that can be scaled
#[async_trait]
pub trait Scalable: KubeResource {
    /// Get current replica count
    fn replicas(&self) -> Option<i32>;

    /// Get desired replica count
    fn desired_replicas(&self) -> Option<i32>;

    /// Scale to specified replica count
    async fn scale(api: &Api<Self>, name: &str, replicas: i32) -> Result<()>
    where
        Self: Sized;
}

/// Trait for resources that support rollout operations
#[async_trait]
pub trait Rollable: KubeResource {
    /// Restart the resource (triggers a rollout)
    async fn restart(api: &Api<Self>, name: &str) -> Result<()>
    where
        Self: Sized;

    /// Get rollout status description
    fn rollout_status(&self) -> String;
}

/// Trait for resources that support exec
pub trait Execable: KubeResource {
    /// Get containers in this resource
    fn containers(&self) -> Vec<String>;

    /// Get the default container name
    fn default_container(&self) -> Option<String>;
}

/// Convert a chrono DateTime to a human-readable duration string
pub fn humanize_duration(time: chrono::DateTime<chrono::Utc>) -> String {
    let now = chrono::Utc::now();
    let duration = now.signed_duration_since(time);

    if duration.num_days() > 0 {
        format!("{}d", duration.num_days())
    } else if duration.num_hours() > 0 {
        format!("{}h", duration.num_hours())
    } else if duration.num_minutes() > 0 {
        format!("{}m", duration.num_minutes())
    } else {
        format!("{}s", duration.num_seconds().max(0))
    }
}

/// Status values that indicate a healthy state
pub const HEALTHY_STATUSES: &[&str] = &["Running", "Succeeded", "Active", "Bound", "Ready", "True"];

/// Status values that indicate a warning state
pub const WARNING_STATUSES: &[&str] = &[
    "Pending",
    "ContainerCreating",
    "PodInitializing",
    "Terminating",
    "Unknown",
];

/// Status values that indicate an error state
pub const ERROR_STATUSES: &[&str] = &[
    "Failed",
    "Error",
    "CrashLoopBackOff",
    "ImagePullBackOff",
    "ErrImagePull",
    "CreateContainerConfigError",
    "InvalidImageName",
    "OOMKilled",
];

/// Determine status category for coloring
pub fn status_category(status: &str) -> StatusCategory {
    if HEALTHY_STATUSES.contains(&status) {
        StatusCategory::Healthy
    } else if ERROR_STATUSES.contains(&status) {
        StatusCategory::Error
    } else if WARNING_STATUSES.contains(&status) {
        StatusCategory::Warning
    } else {
        StatusCategory::Unknown
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StatusCategory {
    Healthy,
    Warning,
    Error,
    Unknown,
}
