//! Secret resource implementation

use crate::error::Result;
use crate::resources::{Describable, KubeResource, Listable, Tabular};
use async_trait::async_trait;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::ListParams;
use kube::{Api, Client};

impl KubeResource for Secret {
    const KIND: &'static str = "Secret";
    const GROUP: &'static str = "";
    const VERSION: &'static str = "v1";
    const PLURAL: &'static str = "secrets";
    const ALIASES: &'static [&'static str] = &[];
    const NAMESPACED: bool = true;

    fn metadata(&self) -> &ObjectMeta {
        &self.metadata
    }
}

#[async_trait]
impl Listable for Secret {
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

impl Tabular for Secret {
    fn headers() -> Vec<&'static str> {
        vec!["NAME", "TYPE", "DATA", "AGE"]
    }

    fn row(&self) -> Vec<String> {
        let secret_type = self
            .type_
            .clone()
            .unwrap_or_else(|| "Opaque".to_string());

        let data_count = self.data.as_ref().map(|d| d.len()).unwrap_or(0);

        vec![
            self.name().to_string(),
            secret_type,
            data_count.to_string(),
            self.age(),
        ]
    }
}

#[async_trait]
impl Describable for Secret {
    async fn describe(&self, _client: &Client) -> Result<String> {
        let mut output = String::new();

        output.push_str(&format!("Name:         {}\n", self.name()));
        output.push_str(&format!(
            "Namespace:    {}\n",
            self.namespace().unwrap_or("<none>")
        ));
        output.push_str(&format!(
            "Type:         {}\n",
            self.type_.as_deref().unwrap_or("Opaque")
        ));

        if let Some(data) = &self.data {
            output.push_str(&format!("\nData:\n"));
            output.push_str(&format!("====\n"));
            for (key, value) in data {
                output.push_str(&format!("{}:  {} bytes\n", key, value.0.len()));
            }
        }

        Ok(output)
    }
}
