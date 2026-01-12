//! Node resource implementation

use crate::error::Result;
use crate::resources::{Describable, KubeResource, Listable, Tabular};
use async_trait::async_trait;
use k8s_openapi::api::core::v1::Node;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::ListParams;
use kube::{Api, Client};

impl KubeResource for Node {
    const KIND: &'static str = "Node";
    const GROUP: &'static str = "";
    const VERSION: &'static str = "v1";
    const PLURAL: &'static str = "nodes";
    const ALIASES: &'static [&'static str] = &["no"];
    const NAMESPACED: bool = false;

    fn metadata(&self) -> &ObjectMeta {
        &self.metadata
    }
}

#[async_trait]
impl Listable for Node {
    fn api(client: Client, _namespace: Option<&str>) -> Api<Self> {
        Api::all(client)
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

impl Tabular for Node {
    fn headers() -> Vec<&'static str> {
        vec!["NAME", "STATUS", "ROLES", "AGE", "VERSION"]
    }

    fn headers_wide() -> Vec<&'static str> {
        vec!["NAME", "STATUS", "ROLES", "AGE", "VERSION", "INTERNAL-IP", "OS-IMAGE"]
    }

    fn row(&self) -> Vec<String> {
        vec![
            self.name().to_string(),
            status_string(self),
            roles(self),
            self.age(),
            kubelet_version(self),
        ]
    }

    fn row_wide(&self) -> Vec<String> {
        let mut row = self.row();
        row.push(internal_ip(self).unwrap_or_else(|| "<none>".to_string()));
        row.push(os_image(self).unwrap_or_else(|| "<unknown>".to_string()));
        row
    }

    fn status_for_color(&self) -> Option<&str> {
        if is_ready(self) {
            Some("Ready")
        } else {
            Some("NotReady")
        }
    }
}

fn status_string(node: &Node) -> String {
    let mut statuses = Vec::new();

    if is_ready(node) {
        statuses.push("Ready");
    } else {
        statuses.push("NotReady");
    }

    // Check for scheduling disabled
    if let Some(spec) = &node.spec {
        if spec.unschedulable == Some(true) {
            statuses.push("SchedulingDisabled");
        }
    }

    statuses.join(",")
}

fn is_ready(node: &Node) -> bool {
    node.status
        .as_ref()
        .and_then(|s| s.conditions.as_ref())
        .map(|conditions| {
            conditions
                .iter()
                .any(|c| c.type_ == "Ready" && c.status == "True")
        })
        .unwrap_or(false)
}

fn roles(node: &Node) -> String {
    let labels = match &node.metadata.labels {
        Some(l) => l,
        None => return "<none>".to_string(),
    };

    let roles: Vec<&str> = labels
        .keys()
        .filter_map(|k| {
            if k.starts_with("node-role.kubernetes.io/") {
                Some(k.strip_prefix("node-role.kubernetes.io/").unwrap())
            } else {
                None
            }
        })
        .collect();

    if roles.is_empty() {
        "<none>".to_string()
    } else {
        roles.join(",")
    }
}

fn kubelet_version(node: &Node) -> String {
    node.status
        .as_ref()
        .and_then(|s| s.node_info.as_ref())
        .map(|i| i.kubelet_version.clone())
        .unwrap_or_else(|| "<unknown>".to_string())
}

fn internal_ip(node: &Node) -> Option<String> {
    node.status
        .as_ref()
        .and_then(|s| s.addresses.as_ref())
        .and_then(|addrs| {
            addrs
                .iter()
                .find(|a| a.type_ == "InternalIP")
                .map(|a| a.address.clone())
        })
}

fn os_image(node: &Node) -> Option<String> {
    node.status
        .as_ref()
        .and_then(|s| s.node_info.as_ref())
        .map(|i| i.os_image.clone())
}

#[async_trait]
impl Describable for Node {
    async fn describe(&self, _client: &Client) -> Result<String> {
        let mut output = String::new();

        output.push_str(&format!("Name:               {}\n", self.name()));
        output.push_str(&format!("Roles:              {}\n", roles(self)));
        output.push_str(&format!("Status:             {}\n", status_string(self)));

        if let Some(status) = &self.status {
            if let Some(info) = &status.node_info {
                output.push_str(&format!("Kubelet Version:    {}\n", info.kubelet_version));
                output.push_str(&format!("OS Image:           {}\n", info.os_image));
                output.push_str(&format!("Operating System:   {}\n", info.operating_system));
                output.push_str(&format!("Architecture:       {}\n", info.architecture));
                output.push_str(&format!("Container Runtime:  {}\n", info.container_runtime_version));
            }

            if let Some(addresses) = &status.addresses {
                output.push_str("\nAddresses:\n");
                for addr in addresses {
                    output.push_str(&format!("  {}: {}\n", addr.type_, addr.address));
                }
            }

            if let Some(capacity) = &status.capacity {
                output.push_str("\nCapacity:\n");
                for (key, value) in capacity {
                    output.push_str(&format!("  {}: {}\n", key, value.0));
                }
            }
        }

        Ok(output)
    }
}
