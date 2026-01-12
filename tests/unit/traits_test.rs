//! Tests for src/resources/traits.rs - humanize_duration, status_category

use kubecontrol::resources::{humanize_duration, status_category, StatusCategory};
use chrono::{Utc, Duration as ChronoDuration};

// ============================================================================
// humanize_duration tests
// ============================================================================

#[test]
fn test_humanize_duration_seconds() {
    let time = Utc::now() - ChronoDuration::seconds(30);
    let result = humanize_duration(time);
    assert_eq!(result, "30s");
}

#[test]
fn test_humanize_duration_zero_seconds() {
    let time = Utc::now();
    let result = humanize_duration(time);
    assert_eq!(result, "0s");
}

#[test]
fn test_humanize_duration_minutes() {
    let time = Utc::now() - ChronoDuration::minutes(5);
    let result = humanize_duration(time);
    assert_eq!(result, "5m");
}

#[test]
fn test_humanize_duration_hours() {
    let time = Utc::now() - ChronoDuration::hours(3);
    let result = humanize_duration(time);
    assert_eq!(result, "3h");
}

#[test]
fn test_humanize_duration_days() {
    let time = Utc::now() - ChronoDuration::days(7);
    let result = humanize_duration(time);
    assert_eq!(result, "7d");
}

#[test]
fn test_humanize_duration_mixed_time_shows_largest_unit() {
    // 2 days and 5 hours should show as 2d
    let time = Utc::now() - ChronoDuration::days(2) - ChronoDuration::hours(5);
    let result = humanize_duration(time);
    assert_eq!(result, "2d");
}

#[test]
fn test_humanize_duration_59_minutes() {
    let time = Utc::now() - ChronoDuration::minutes(59);
    let result = humanize_duration(time);
    assert_eq!(result, "59m");
}

#[test]
fn test_humanize_duration_60_minutes_shows_hours() {
    let time = Utc::now() - ChronoDuration::minutes(60);
    let result = humanize_duration(time);
    assert_eq!(result, "1h");
}

#[test]
fn test_humanize_duration_23_hours() {
    let time = Utc::now() - ChronoDuration::hours(23);
    let result = humanize_duration(time);
    assert_eq!(result, "23h");
}

#[test]
fn test_humanize_duration_24_hours_shows_days() {
    let time = Utc::now() - ChronoDuration::hours(24);
    let result = humanize_duration(time);
    assert_eq!(result, "1d");
}

#[test]
fn test_humanize_duration_future_time_returns_zero() {
    // Future time should return 0s (clamped to 0)
    let time = Utc::now() + ChronoDuration::hours(1);
    let result = humanize_duration(time);
    assert_eq!(result, "0s");
}

// ============================================================================
// status_category tests
// ============================================================================

#[test]
fn test_status_category_running() {
    assert_eq!(status_category("Running"), StatusCategory::Healthy);
}

#[test]
fn test_status_category_succeeded() {
    assert_eq!(status_category("Succeeded"), StatusCategory::Healthy);
}

#[test]
fn test_status_category_active() {
    assert_eq!(status_category("Active"), StatusCategory::Healthy);
}

#[test]
fn test_status_category_bound() {
    assert_eq!(status_category("Bound"), StatusCategory::Healthy);
}

#[test]
fn test_status_category_ready() {
    assert_eq!(status_category("Ready"), StatusCategory::Healthy);
}

#[test]
fn test_status_category_true() {
    assert_eq!(status_category("True"), StatusCategory::Healthy);
}

#[test]
fn test_status_category_pending() {
    assert_eq!(status_category("Pending"), StatusCategory::Warning);
}

#[test]
fn test_status_category_container_creating() {
    assert_eq!(status_category("ContainerCreating"), StatusCategory::Warning);
}

#[test]
fn test_status_category_pod_initializing() {
    assert_eq!(status_category("PodInitializing"), StatusCategory::Warning);
}

#[test]
fn test_status_category_terminating() {
    assert_eq!(status_category("Terminating"), StatusCategory::Warning);
}

#[test]
fn test_status_category_unknown_status() {
    assert_eq!(status_category("Unknown"), StatusCategory::Warning);
}

#[test]
fn test_status_category_failed() {
    assert_eq!(status_category("Failed"), StatusCategory::Error);
}

#[test]
fn test_status_category_error() {
    assert_eq!(status_category("Error"), StatusCategory::Error);
}

#[test]
fn test_status_category_crash_loop_back_off() {
    assert_eq!(status_category("CrashLoopBackOff"), StatusCategory::Error);
}

#[test]
fn test_status_category_image_pull_back_off() {
    assert_eq!(status_category("ImagePullBackOff"), StatusCategory::Error);
}

#[test]
fn test_status_category_err_image_pull() {
    assert_eq!(status_category("ErrImagePull"), StatusCategory::Error);
}

#[test]
fn test_status_category_create_container_config_error() {
    assert_eq!(status_category("CreateContainerConfigError"), StatusCategory::Error);
}

#[test]
fn test_status_category_invalid_image_name() {
    assert_eq!(status_category("InvalidImageName"), StatusCategory::Error);
}

#[test]
fn test_status_category_oom_killed() {
    assert_eq!(status_category("OOMKilled"), StatusCategory::Error);
}

#[test]
fn test_status_category_unknown_value() {
    assert_eq!(status_category("SomeRandomStatus"), StatusCategory::Unknown);
}

#[test]
fn test_status_category_empty_string() {
    assert_eq!(status_category(""), StatusCategory::Unknown);
}

#[test]
fn test_status_category_case_sensitive() {
    // Status matching is case-sensitive
    assert_eq!(status_category("running"), StatusCategory::Unknown);
    assert_eq!(status_category("RUNNING"), StatusCategory::Unknown);
}

// ============================================================================
// StatusCategory tests
// ============================================================================

#[test]
fn test_status_category_debug() {
    assert_eq!(format!("{:?}", StatusCategory::Healthy), "Healthy");
    assert_eq!(format!("{:?}", StatusCategory::Warning), "Warning");
    assert_eq!(format!("{:?}", StatusCategory::Error), "Error");
    assert_eq!(format!("{:?}", StatusCategory::Unknown), "Unknown");
}

#[test]
fn test_status_category_clone() {
    let status = StatusCategory::Healthy;
    let cloned = status.clone();
    assert_eq!(status, cloned);
}

#[test]
fn test_status_category_copy() {
    let status = StatusCategory::Error;
    let copied = status;
    assert_eq!(status, copied);
}

#[test]
fn test_status_category_eq() {
    assert_eq!(StatusCategory::Healthy, StatusCategory::Healthy);
    assert_ne!(StatusCategory::Healthy, StatusCategory::Error);
}
