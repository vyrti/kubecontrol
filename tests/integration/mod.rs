//! Integration tests module
//!
//! These tests require a real Kubernetes cluster and are marked with #[ignore].
//! Run them with: cargo test -- --ignored

mod client_test;
mod pods_test;
mod deployments_test;
mod services_test;
mod configmaps_test;
mod nodes_test;
mod web_api_test;
