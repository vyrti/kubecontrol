//! Service resource implementation

use crate::error::Result;
use crate::resources::{Describable, KubeResource, Listable, Tabular};
use async_trait::async_trait;
use k8s_openapi::api::core::v1::Service;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::api::ListParams;
use kube::{Api, Client};

impl KubeResource for Service {
    const KIND: &'static str = "Service";
    const GROUP: &'static str = "";
    const VERSION: &'static str = "v1";
    const PLURAL: &'static str = "services";
    const ALIASES: &'static [&'static str] = &["svc"];
    const NAMESPACED: bool = true;

    fn metadata(&self) -> &ObjectMeta {
        &self.metadata
    }
}

#[async_trait]
impl Listable for Service {
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

impl Tabular for Service {
    fn headers() -> Vec<&'static str> {
        vec!["NAME", "TYPE", "CLUSTER-IP", "EXTERNAL-IP", "PORT(S)", "AGE"]
    }

    fn row(&self) -> Vec<String> {
        let spec = self.spec.as_ref();

        let svc_type = spec
            .and_then(|s| s.type_.clone())
            .unwrap_or_else(|| "ClusterIP".to_string());

        let cluster_ip = spec
            .and_then(|s| s.cluster_ip.clone())
            .unwrap_or_else(|| "<none>".to_string());

        let external_ip = external_ips(self);
        let ports = format_ports(self);

        vec![
            self.name().to_string(),
            svc_type,
            cluster_ip,
            external_ip,
            ports,
            self.age(),
        ]
    }
}

fn external_ips(svc: &Service) -> String {
    let spec = match &svc.spec {
        Some(s) => s,
        None => return "<none>".to_string(),
    };

    // Check LoadBalancer ingress
    if let Some(status) = &svc.status {
        if let Some(lb) = &status.load_balancer {
            if let Some(ingress) = &lb.ingress {
                let ips: Vec<String> = ingress
                    .iter()
                    .filter_map(|i| i.ip.clone().or_else(|| i.hostname.clone()))
                    .collect();
                if !ips.is_empty() {
                    return ips.join(",");
                }
            }
        }
    }

    // Check external IPs
    if let Some(external_ips) = &spec.external_ips {
        if !external_ips.is_empty() {
            return external_ips.join(",");
        }
    }

    "<none>".to_string()
}

fn format_ports(svc: &Service) -> String {
    let spec = match &svc.spec {
        Some(s) => s,
        None => return "<none>".to_string(),
    };

    let ports = match &spec.ports {
        Some(p) => p,
        None => return "<none>".to_string(),
    };

    ports
        .iter()
        .map(|p| {
            let port = p.port;
            let protocol = p.protocol.as_deref().unwrap_or("TCP");
            if let Some(node_port) = p.node_port {
                format!("{}:{}/{}", port, node_port, protocol)
            } else {
                format!("{}/{}", port, protocol)
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

#[async_trait]
impl Describable for Service {
    async fn describe(&self, _client: &Client) -> Result<String> {
        let mut output = String::new();

        output.push_str(&format!("Name:              {}\n", self.name()));
        output.push_str(&format!(
            "Namespace:         {}\n",
            self.namespace().unwrap_or("<none>")
        ));

        if let Some(spec) = &self.spec {
            output.push_str(&format!(
                "Type:              {}\n",
                spec.type_.as_deref().unwrap_or("ClusterIP")
            ));
            output.push_str(&format!(
                "Cluster-IP:        {}\n",
                spec.cluster_ip.as_deref().unwrap_or("<none>")
            ));
            output.push_str(&format!("External-IP:       {}\n", external_ips(self)));
            output.push_str(&format!("Port(s):           {}\n", format_ports(self)));

            if let Some(selector) = &spec.selector {
                let sel_str = selector
                    .iter()
                    .map(|(k, v)| format!("{}={}", k, v))
                    .collect::<Vec<_>>()
                    .join(",");
                output.push_str(&format!("Selector:          {}\n", sel_str));
            }
        }

        Ok(output)
    }
}
