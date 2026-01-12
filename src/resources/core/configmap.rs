//! ConfigMap resource implementation

use crate::error::Result;
use crate::resources::{Describable, KubeResource, Listable, Tabular};
use async_trait::async_trait;
use k8s_openapi::api::core::v1::ConfigMap;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::ListParams;
use kube::{Api, Client};

impl KubeResource for ConfigMap {
    const KIND: &'static str = "ConfigMap";
    const GROUP: &'static str = "";
    const VERSION: &'static str = "v1";
    const PLURAL: &'static str = "configmaps";
    const ALIASES: &'static [&'static str] = &["cm"];
    const NAMESPACED: bool = true;

    fn metadata(&self) -> &ObjectMeta {
        &self.metadata
    }
}

#[async_trait]
impl Listable for ConfigMap {
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

impl Tabular for ConfigMap {
    fn headers() -> Vec<&'static str> {
        vec!["NAME", "DATA", "AGE"]
    }

    fn row(&self) -> Vec<String> {
        let data_count = self.data.as_ref().map(|d| d.len()).unwrap_or(0)
            + self.binary_data.as_ref().map(|d| d.len()).unwrap_or(0);

        vec![
            self.name().to_string(),
            data_count.to_string(),
            self.age(),
        ]
    }
}

#[async_trait]
impl Describable for ConfigMap {
    async fn describe(&self, _client: &Client) -> Result<String> {
        let mut output = String::new();

        output.push_str(&format!("Name:         {}\n", self.name()));
        output.push_str(&format!(
            "Namespace:    {}\n",
            self.namespace().unwrap_or("<none>")
        ));

        if let Some(data) = &self.data {
            output.push_str(&format!("\nData:\n"));
            output.push_str(&format!("====\n"));
            for (key, value) in data {
                output.push_str(&format!("{}:\n----\n{}\n\n", key, value));
            }
        }

        if let Some(binary_data) = &self.binary_data {
            output.push_str(&format!("\nBinaryData:\n"));
            output.push_str(&format!("====\n"));
            for (key, _) in binary_data {
                output.push_str(&format!("{}: {} bytes\n", key, binary_data.get(key).map(|d| d.0.len()).unwrap_or(0)));
            }
        }

        Ok(output)
    }
}
