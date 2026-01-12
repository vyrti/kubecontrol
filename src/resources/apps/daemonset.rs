//! DaemonSet resource implementation

use crate::error::Result;
use crate::resources::{Describable, KubeResource, Listable, Rollable, Tabular};
use async_trait::async_trait;
use k8s_openapi::api::apps::v1::DaemonSet;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{ListParams, Patch, PatchParams};
use kube::{Api, Client};
use serde_json::json;

impl KubeResource for DaemonSet {
    const KIND: &'static str = "DaemonSet";
    const GROUP: &'static str = "apps";
    const VERSION: &'static str = "v1";
    const PLURAL: &'static str = "daemonsets";
    const ALIASES: &'static [&'static str] = &["ds"];
    const NAMESPACED: bool = true;

    fn metadata(&self) -> &ObjectMeta {
        &self.metadata
    }
}

#[async_trait]
impl Listable for DaemonSet {
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

impl Tabular for DaemonSet {
    fn headers() -> Vec<&'static str> {
        vec!["NAME", "DESIRED", "CURRENT", "READY", "UP-TO-DATE", "AVAILABLE", "AGE"]
    }

    fn row(&self) -> Vec<String> {
        let status = self.status.as_ref();

        let desired = status.map(|s| s.desired_number_scheduled).unwrap_or(0);
        let current = status.map(|s| s.current_number_scheduled).unwrap_or(0);
        let ready = status.map(|s| s.number_ready).unwrap_or(0);
        let updated = status.and_then(|s| s.updated_number_scheduled).unwrap_or(0);
        let available = status.and_then(|s| s.number_available).unwrap_or(0);

        vec![
            self.name().to_string(),
            desired.to_string(),
            current.to_string(),
            ready.to_string(),
            updated.to_string(),
            available.to_string(),
            self.age(),
        ]
    }
}

#[async_trait]
impl Rollable for DaemonSet {
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

        let desired = status.desired_number_scheduled;
        let updated = status.updated_number_scheduled.unwrap_or(0);
        let available = status.number_available.unwrap_or(0);

        if updated < desired {
            format!(
                "Waiting for daemon set rollout to finish: {} out of {} new pods have been updated",
                updated, desired
            )
        } else if available < desired {
            format!(
                "Waiting for daemon set rollout to finish: {} of {} updated pods are available",
                available, desired
            )
        } else {
            format!("daemon set \"{}\" successfully rolled out", self.name())
        }
    }
}

#[async_trait]
impl Describable for DaemonSet {
    async fn describe(&self, _client: &Client) -> Result<String> {
        let mut output = String::new();

        output.push_str(&format!("Name:               {}\n", self.name()));
        output.push_str(&format!(
            "Namespace:          {}\n",
            self.namespace().unwrap_or("<none>")
        ));

        if let Some(status) = &self.status {
            output.push_str(&format!("Desired:            {}\n", status.desired_number_scheduled));
            output.push_str(&format!("Current:            {}\n", status.current_number_scheduled));
            output.push_str(&format!("Ready:              {}\n", status.number_ready));
            output.push_str(&format!(
                "Up-to-date:         {}\n",
                status.updated_number_scheduled.unwrap_or(0)
            ));
            output.push_str(&format!(
                "Available:          {}\n",
                status.number_available.unwrap_or(0)
            ));
        }

        Ok(output)
    }
}
