//! Pod resource implementation

use crate::error::Result;
use crate::resources::{Describable, Execable, KubeResource, Listable, Loggable, Tabular};
use async_trait::async_trait;
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{ListParams, LogParams};
use kube::{Api, Client};

impl KubeResource for Pod {
    const KIND: &'static str = "Pod";
    const GROUP: &'static str = "";
    const VERSION: &'static str = "v1";
    const PLURAL: &'static str = "pods";
    const ALIASES: &'static [&'static str] = &["po", "pod"];
    const NAMESPACED: bool = true;

    fn metadata(&self) -> &ObjectMeta {
        &self.metadata
    }
}

#[async_trait]
impl Listable for Pod {
    fn api(client: Client, namespace: Option<&str>) -> Api<Self> {
        match namespace {
            Some(ns) => Api::namespaced(client, ns),
            None => Api::default_namespaced(client),
        }
    }

    fn api_all(client: Client) -> Api<Self> {
        Api::all(client)
    }

    async fn list_resources(
        api: &Api<Self>,
        label_selector: Option<&str>,
        field_selector: Option<&str>,
    ) -> Result<Vec<Self>> {
        let mut lp = ListParams::default();
        if let Some(ls) = label_selector {
            lp = lp.labels(ls);
        }
        if let Some(fs) = field_selector {
            lp = lp.fields(fs);
        }

        let list = api.list(&lp).await?;
        Ok(list.items)
    }
}

impl Tabular for Pod {
    fn headers() -> Vec<&'static str> {
        vec!["NAME", "READY", "STATUS", "RESTARTS", "AGE"]
    }

    fn headers_wide() -> Vec<&'static str> {
        vec!["NAME", "READY", "STATUS", "RESTARTS", "AGE", "IP", "NODE"]
    }

    fn row(&self) -> Vec<String> {
        let (ready, total) = ready_containers(self);
        let status = phase(self);
        let restarts = restart_count(self);
        let age = self.age();

        vec![
            self.name().to_string(),
            format!("{}/{}", ready, total),
            status,
            restarts.to_string(),
            age,
        ]
    }

    fn row_wide(&self) -> Vec<String> {
        let mut row = self.row();
        row.push(pod_ip(self).unwrap_or_else(|| "<none>".to_string()));
        row.push(node_name(self).unwrap_or_else(|| "<none>".to_string()));
        row
    }
}

#[async_trait]
impl Describable for Pod {
    async fn describe(&self, _client: &Client) -> Result<String> {
        let mut output = String::new();

        output.push_str(&format!("Name:         {}\n", self.name()));
        output.push_str(&format!(
            "Namespace:    {}\n",
            self.namespace().unwrap_or("<none>")
        ));
        output.push_str(&format!("Node:         {}\n", node_name(self).unwrap_or_else(|| "<none>".to_string())));
        output.push_str(&format!("Status:       {}\n", phase(self)));

        if let Some(ip) = pod_ip(self) {
            output.push_str(&format!("IP:           {}\n", ip));
        }

        // Containers
        if let Some(spec) = &self.spec {
            output.push_str("\nContainers:\n");
            for container in &spec.containers {
                output.push_str(&format!("  {}:\n", container.name));
                output.push_str(&format!(
                    "    Image:    {}\n",
                    container.image.as_deref().unwrap_or("<none>")
                ));
            }
        }

        Ok(output)
    }
}

#[async_trait]
impl Loggable for Pod {
    async fn logs(
        &self,
        client: &Client,
        container: Option<&str>,
        tail_lines: Option<i64>,
        since_seconds: Option<i64>,
    ) -> Result<String> {
        let api: Api<Pod> = match self.namespace() {
            Some(ns) => Api::namespaced(client.clone(), ns),
            None => Api::default_namespaced(client.clone()),
        };

        let mut lp = LogParams::default();

        if let Some(c) = container {
            lp.container = Some(c.to_string());
        }
        if let Some(tail) = tail_lines {
            lp.tail_lines = Some(tail);
        }
        if let Some(since) = since_seconds {
            lp.since_seconds = Some(since);
        }

        let logs = api.logs(self.name(), &lp).await?;
        Ok(logs)
    }
}

impl Execable for Pod {
    fn containers(&self) -> Vec<String> {
        self.spec
            .as_ref()
            .map(|s| s.containers.iter().map(|c| c.name.clone()).collect())
            .unwrap_or_default()
    }

    fn default_container(&self) -> Option<String> {
        // Check for annotation first
        if let Some(annotations) = &self.metadata.annotations {
            if let Some(default) = annotations.get("kubectl.kubernetes.io/default-container") {
                return Some(default.clone());
            }
        }

        // Otherwise return first container
        self.spec
            .as_ref()
            .and_then(|s| s.containers.first())
            .map(|c| c.name.clone())
    }
}

// Pod-specific helper functions

/// Get ready container count and total container count
fn ready_containers(pod: &Pod) -> (i32, i32) {
    let total = pod
        .spec
        .as_ref()
        .map(|s| s.containers.len() as i32)
        .unwrap_or(0);

    let ready = pod
        .status
        .as_ref()
        .and_then(|s| s.container_statuses.as_ref())
        .map(|cs| cs.iter().filter(|c| c.ready).count() as i32)
        .unwrap_or(0);

    (ready, total)
}

/// Get total restart count across all containers
fn restart_count(pod: &Pod) -> i32 {
    pod.status
        .as_ref()
        .and_then(|s| s.container_statuses.as_ref())
        .map(|cs| cs.iter().map(|c| c.restart_count).sum())
        .unwrap_or(0)
}

/// Get pod phase/status
fn phase(pod: &Pod) -> String {
    // Check for terminating first
    if pod.metadata.deletion_timestamp.is_some() {
        return "Terminating".to_string();
    }

    // Check container statuses for more specific status
    if let Some(status) = &pod.status {
        if let Some(container_statuses) = &status.container_statuses {
            for cs in container_statuses {
                if let Some(state) = &cs.state {
                    if let Some(waiting) = &state.waiting {
                        if let Some(reason) = &waiting.reason {
                            return reason.clone();
                        }
                    }
                    if let Some(terminated) = &state.terminated {
                        if let Some(reason) = &terminated.reason {
                            return reason.clone();
                        }
                    }
                }
            }
        }

        // Fall back to phase
        if let Some(p) = &status.phase {
            return p.clone();
        }
    }

    "Unknown".to_string()
}

/// Get pod IP
fn pod_ip(pod: &Pod) -> Option<String> {
    pod.status.as_ref().and_then(|s| s.pod_ip.clone())
}

/// Get node name
fn node_name(pod: &Pod) -> Option<String> {
    pod.spec.as_ref().and_then(|s| s.node_name.clone())
}
