//! Resource type registry for dynamic resource lookup

use std::collections::HashMap;
use std::sync::LazyLock;

/// Information about a resource type
#[derive(Debug, Clone)]
pub struct ResourceInfo {
    pub kind: &'static str,
    pub group: &'static str,
    pub version: &'static str,
    pub plural: &'static str,
    pub aliases: &'static [&'static str],
    pub namespaced: bool,
}

/// Global resource registry
pub static RESOURCE_REGISTRY: LazyLock<ResourceRegistry> = LazyLock::new(ResourceRegistry::new);

/// Registry for looking up resource types by name or alias
pub struct ResourceRegistry {
    by_plural: HashMap<String, ResourceInfo>,
    by_kind: HashMap<String, ResourceInfo>,
    by_alias: HashMap<String, ResourceInfo>,
}

impl ResourceRegistry {
    fn new() -> Self {
        let mut registry = Self {
            by_plural: HashMap::new(),
            by_kind: HashMap::new(),
            by_alias: HashMap::new(),
        };

        // Core resources
        registry.register(ResourceInfo {
            kind: "Pod",
            group: "",
            version: "v1",
            plural: "pods",
            aliases: &["po", "pod"],
            namespaced: true,
        });

        registry.register(ResourceInfo {
            kind: "Service",
            group: "",
            version: "v1",
            plural: "services",
            aliases: &["svc"],
            namespaced: true,
        });

        registry.register(ResourceInfo {
            kind: "ConfigMap",
            group: "",
            version: "v1",
            plural: "configmaps",
            aliases: &["cm"],
            namespaced: true,
        });

        registry.register(ResourceInfo {
            kind: "Secret",
            group: "",
            version: "v1",
            plural: "secrets",
            aliases: &[],
            namespaced: true,
        });

        registry.register(ResourceInfo {
            kind: "Namespace",
            group: "",
            version: "v1",
            plural: "namespaces",
            aliases: &["ns"],
            namespaced: false,
        });

        registry.register(ResourceInfo {
            kind: "Node",
            group: "",
            version: "v1",
            plural: "nodes",
            aliases: &["no"],
            namespaced: false,
        });

        // Apps resources
        registry.register(ResourceInfo {
            kind: "Deployment",
            group: "apps",
            version: "v1",
            plural: "deployments",
            aliases: &["deploy"],
            namespaced: true,
        });

        registry.register(ResourceInfo {
            kind: "StatefulSet",
            group: "apps",
            version: "v1",
            plural: "statefulsets",
            aliases: &["sts"],
            namespaced: true,
        });

        registry.register(ResourceInfo {
            kind: "DaemonSet",
            group: "apps",
            version: "v1",
            plural: "daemonsets",
            aliases: &["ds"],
            namespaced: true,
        });

        registry.register(ResourceInfo {
            kind: "ReplicaSet",
            group: "apps",
            version: "v1",
            plural: "replicasets",
            aliases: &["rs"],
            namespaced: true,
        });

        registry
    }

    fn register(&mut self, info: ResourceInfo) {
        let plural_lower = info.plural.to_lowercase();
        let kind_lower = info.kind.to_lowercase();

        self.by_plural.insert(plural_lower, info.clone());
        self.by_kind.insert(kind_lower, info.clone());

        for alias in info.aliases {
            self.by_alias.insert(alias.to_lowercase(), info.clone());
        }
    }

    /// Look up resource info by name, plural, or alias
    pub fn lookup(&self, name: &str) -> Option<&ResourceInfo> {
        let name_lower = name.to_lowercase();

        self.by_plural
            .get(&name_lower)
            .or_else(|| self.by_kind.get(&name_lower))
            .or_else(|| self.by_alias.get(&name_lower))
    }

    /// Get all registered resource types
    pub fn all(&self) -> impl Iterator<Item = &ResourceInfo> {
        self.by_plural.values()
    }

    /// Get all resource names and aliases for shell completion
    pub fn all_names(&self) -> Vec<&str> {
        let mut names: Vec<&str> = self.by_plural.keys().map(|s| s.as_str()).collect();
        names.extend(self.by_alias.keys().map(|s| s.as_str()));
        names.sort();
        names.dedup();
        names
    }
}
