//! Deployment resource implementation

use crate::error::Result;
use crate::resources::{Describable, KubeResource, Listable, Rollable, Scalable, Tabular};
use async_trait::async_trait;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{ListParams, Patch, PatchParams};
use kube::{Api, Client};
use serde_json::json;

impl KubeResource for Deployment {
    const KIND: &'static str = "Deployment";
    const GROUP: &'static str = "apps";
    const VERSION: &'static str = "v1";
    const PLURAL: &'static str = "deployments";
    const ALIASES: &'static [&'static str] = &["deploy"];
    const NAMESPACED: bool = true;

    fn metadata(&self) -> &ObjectMeta {
        &self.metadata
    }
}

#[async_trait]
impl Listable for Deployment {
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

impl Tabular for Deployment {
    fn headers() -> Vec<&'static str> {
        vec!["NAME", "READY", "UP-TO-DATE", "AVAILABLE", "AGE"]
    }

    fn headers_wide() -> Vec<&'static str> {
        vec!["NAME", "READY", "UP-TO-DATE", "AVAILABLE", "AGE", "CONTAINERS", "IMAGES"]
    }

    fn row(&self) -> Vec<String> {
        let status = self.status.as_ref();

        let desired = self.spec.as_ref().and_then(|s| s.replicas).unwrap_or(0);
        let ready = status.and_then(|s| s.ready_replicas).unwrap_or(0);
        let updated = status.and_then(|s| s.updated_replicas).unwrap_or(0);
        let available = status.and_then(|s| s.available_replicas).unwrap_or(0);

        vec![
            self.name().to_string(),
            format!("{}/{}", ready, desired),
            updated.to_string(),
            available.to_string(),
            self.age(),
        ]
    }

    fn row_wide(&self) -> Vec<String> {
        let mut row = self.row();

        let (containers, images) = container_info(self);
        row.push(containers);
        row.push(images);

        row
    }
}

#[async_trait]
impl Scalable for Deployment {
    fn replicas(&self) -> Option<i32> {
        self.status.as_ref().and_then(|s| s.ready_replicas)
    }

    fn desired_replicas(&self) -> Option<i32> {
        self.spec.as_ref().and_then(|s| s.replicas)
    }

    async fn scale(api: &Api<Self>, name: &str, replicas: i32) -> Result<()> {
        let patch = json!({
            "spec": {
                "replicas": replicas
            }
        });

        api.patch(name, &PatchParams::default(), &Patch::Merge(&patch))
            .await?;
        Ok(())
    }
}

#[async_trait]
impl Rollable for Deployment {
    async fn restart(api: &Api<Self>, name: &str) -> Result<()> {
        let now = chrono::Utc::now().to_rfc3339();
        let patch = json!({
            "spec": {
                "template": {
                    "metadata": {
                        "annotations": {
                            "kubectl.kubernetes.io/restartedAt": now
                        }
                    }
                }
            }
        });

        api.patch(name, &PatchParams::default(), &Patch::Merge(&patch))
            .await?;
        Ok(())
    }

    fn rollout_status(&self) -> String {
        let status = match &self.status {
            Some(s) => s,
            None => return "Unknown".to_string(),
        };

        let desired = self.spec.as_ref().and_then(|s| s.replicas).unwrap_or(0);
        let updated = status.updated_replicas.unwrap_or(0);
        let ready = status.ready_replicas.unwrap_or(0);
        let available = status.available_replicas.unwrap_or(0);

        if updated < desired {
            format!(
                "Waiting for rollout to finish: {} out of {} new replicas have been updated",
                updated, desired
            )
        } else if ready < updated {
            format!(
                "Waiting for rollout to finish: {} of {} updated replicas are available",
                available, updated
            )
        } else if available < desired {
            format!(
                "Waiting for rollout to finish: {} of {} replicas are available",
                available, desired
            )
        } else {
            format!("deployment \"{}\" successfully rolled out", self.name())
        }
    }
}

#[async_trait]
impl Describable for Deployment {
    async fn describe(&self, _client: &Client) -> Result<String> {
        let mut output = String::new();

        output.push_str(&format!("Name:                   {}\n", self.name()));
        output.push_str(&format!(
            "Namespace:              {}\n",
            self.namespace().unwrap_or("<none>")
        ));

        if let Some(spec) = &self.spec {
            output.push_str(&format!(
                "Replicas:               {} desired\n",
                spec.replicas.unwrap_or(1)
            ));
            output.push_str(&format!(
                "Selector:               {}\n",
                spec.selector
                    .match_labels
                    .as_ref()
                    .map(|l| l.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<_>>().join(","))
                    .unwrap_or_else(|| "<none>".to_string())
            ));
            output.push_str(&format!(
                "Strategy:               {}\n",
                spec.strategy
                    .as_ref()
                    .and_then(|s| s.type_.as_deref())
                    .unwrap_or("RollingUpdate")
            ));
        }

        if let Some(status) = &self.status {
            output.push_str(&format!(
                "Ready Replicas:         {}\n",
                status.ready_replicas.unwrap_or(0)
            ));
            output.push_str(&format!(
                "Updated Replicas:       {}\n",
                status.updated_replicas.unwrap_or(0)
            ));
            output.push_str(&format!(
                "Available Replicas:     {}\n",
                status.available_replicas.unwrap_or(0)
            ));
        }

        // Containers
        if let Some(spec) = &self.spec {
            if let Some(pod_spec) = &spec.template.spec {
                output.push_str("\nContainers:\n");
                for container in &pod_spec.containers {
                    output.push_str(&format!("  {}:\n", container.name));
                    output.push_str(&format!(
                        "    Image:      {}\n",
                        container.image.as_deref().unwrap_or("<none>")
                    ));
                }
            }
        }

        Ok(output)
    }
}

fn container_info(deploy: &Deployment) -> (String, String) {
    let spec = match &deploy.spec {
        Some(s) => s,
        None => return ("<none>".to_string(), "<none>".to_string()),
    };

    let pod_spec = match &spec.template.spec {
        Some(s) => s,
        None => return ("<none>".to_string(), "<none>".to_string()),
    };

    let containers: Vec<&str> = pod_spec
        .containers
        .iter()
        .map(|c| c.name.as_str())
        .collect();

    let images: Vec<&str> = pod_spec
        .containers
        .iter()
        .filter_map(|c| c.image.as_deref())
        .collect();

    (containers.join(","), images.join(","))
}
