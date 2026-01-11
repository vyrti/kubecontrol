//! Namespace resource implementation

use crate::error::Result;
use crate::resources::{KubeResource, Listable, Tabular};
use async_trait::async_trait;
use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::ListParams;
use kube::{Api, Client};

impl KubeResource for Namespace {
    const KIND: &'static str = "Namespace";
    const GROUP: &'static str = "";
    const VERSION: &'static str = "v1";
    const PLURAL: &'static str = "namespaces";
    const ALIASES: &'static [&'static str] = &["ns"];
    const NAMESPACED: bool = false;

    fn metadata(&self) -> &ObjectMeta {
        &self.metadata
    }
}

#[async_trait]
impl Listable for Namespace {
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

impl Tabular for Namespace {
    fn headers() -> Vec<&'static str> {
        vec!["NAME", "STATUS", "AGE"]
    }

    fn row(&self) -> Vec<String> {
        let status = self
            .status
            .as_ref()
            .and_then(|s| s.phase.clone())
            .unwrap_or_else(|| "Unknown".to_string());

        vec![self.name().to_string(), status, self.age()]
    }

    fn status_for_color(&self) -> Option<&str> {
        self.status
            .as_ref()
            .and_then(|s| s.phase.as_deref())
    }
}
