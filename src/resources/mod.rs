//! Kubernetes resource types and traits

pub mod traits;
pub mod core;
pub mod apps;
pub mod registry;

pub use traits::*;
pub use registry::{RESOURCE_REGISTRY, ResourceRegistry, ResourceInfo};
