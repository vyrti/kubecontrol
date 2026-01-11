//! ReplicaSet resource implementation

use crate::error::Result;
use crate::resources::{KubeResource, Listable, Scalable, Tabular};
use async_trait::async_trait;
use k8s_openapi::api::apps::v1::ReplicaSet;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::{ListParams, Patch, PatchParams};
use kube::{Api, Client};
use serde_json::json;

impl KubeResource for ReplicaSet {
    const KIND: &'static str = "ReplicaSet";
    const GROUP: &'static str = "apps";
    const VERSION: &'static str = "v1";
    const PLURAL: &'static str = "replicasets";
    const ALIASES: &'static [&'static str] = &["rs"];
    const NAMESPACED: bool = true;

    fn metadata(&self) -> &ObjectMeta {
        &self.metadata
    }
}

#[async_trait]
impl Listable for ReplicaSet {
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

impl Tabular for ReplicaSet {
    fn headers() -> Vec<&'static str> {
        vec!["NAME", "DESIRED", "CURRENT", "READY", "AGE"]
    }

    fn row(&self) -> Vec<String> {
        let desired = self.desired_replicas().unwrap_or(0);
        let current = self
            .status
            .as_ref()
            .map(|s| s.replicas)
            .unwrap_or(0);
        let ready = self.replicas().unwrap_or(0);

        vec![
            self.name().to_string(),
            desired.to_string(),
            current.to_string(),
            ready.to_string(),
            self.age(),
        ]
    }
}

#[async_trait]
impl Scalable for ReplicaSet {
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
