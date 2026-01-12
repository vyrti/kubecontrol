//! EKS storage checks
//!
//! Note: EBS CSI driver checks are included in cluster.rs (check_eks_addons).
//! This module is a placeholder for future EFS and storage-specific checks.

use crate::debug::types::DebugIssue;
use crate::error::KcError;
use kube::Client;

/// Placeholder for additional EKS storage checks
/// Main storage addon checks are in cluster::check_eks_addons
pub async fn check_storage_issues(_client: &Client) -> Result<Vec<DebugIssue>, KcError> {
    // EBS CSI driver checks are in check_eks_addons
    // Future: Add EFS CSI driver checks, FSx checks, etc.
    Ok(Vec::new())
}
