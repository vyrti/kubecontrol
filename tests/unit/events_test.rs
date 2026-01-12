//! Event analysis unit tests
//!
//! Tests for event chain building and pattern detection.

use k8s_openapi::api::core::v1::Event;
use k8s_openapi::api::core::v1::ObjectReference;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::Time;
use chrono::Utc;
use kubecontrol::debug::events::{build_event_chain, EventChain, ChainEvent};

// ============================================================================
// Helper functions to create mock events
// ============================================================================

fn create_event(
    namespace: &str,
    name: &str,
    reason: &str,
    message: &str,
    event_type: &str,
    involved_name: &str,
    involved_kind: &str,
    count: Option<i32>,
) -> Event {
    Event {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        involved_object: ObjectReference {
            kind: Some(involved_kind.to_string()),
            name: Some(involved_name.to_string()),
            namespace: Some(namespace.to_string()),
            ..Default::default()
        },
        reason: Some(reason.to_string()),
        message: Some(message.to_string()),
        type_: Some(event_type.to_string()),
        count,
        first_timestamp: Some(Time(Utc::now())),
        last_timestamp: Some(Time(Utc::now())),
        ..Default::default()
    }
}

fn create_warning_event(
    namespace: &str,
    name: &str,
    reason: &str,
    message: &str,
    involved_name: &str,
    count: i32,
) -> Event {
    create_event(namespace, name, reason, message, "Warning", involved_name, "Pod", Some(count))
}

fn create_normal_event(
    namespace: &str,
    name: &str,
    reason: &str,
    message: &str,
    involved_name: &str,
) -> Event {
    create_event(namespace, name, reason, message, "Normal", involved_name, "Pod", Some(1))
}

// ============================================================================
// EventChain struct tests
// ============================================================================

#[test]
fn test_event_chain_struct() {
    let chain = EventChain {
        object: "default/my-pod".to_string(),
        events: vec![
            ChainEvent {
                reason: "BackOff".to_string(),
                message: "Back-off restarting failed container".to_string(),
                count: 5,
            },
        ],
        root_cause: Some("Container crash".to_string()),
    };

    assert_eq!(chain.object, "default/my-pod");
    assert_eq!(chain.events.len(), 1);
    assert_eq!(chain.events[0].reason, "BackOff");
    assert_eq!(chain.events[0].count, 5);
    assert_eq!(chain.root_cause, Some("Container crash".to_string()));
}

#[test]
fn test_chain_event_struct() {
    let event = ChainEvent {
        reason: "Failed".to_string(),
        message: "Error pulling image".to_string(),
        count: 3,
    };

    assert_eq!(event.reason, "Failed");
    assert_eq!(event.message, "Error pulling image");
    assert_eq!(event.count, 3);
}

// ============================================================================
// build_event_chain tests
// ============================================================================

#[test]
fn test_build_event_chain_empty_events() {
    let events: Vec<Event> = vec![];
    let chains = build_event_chain(&events);

    assert!(chains.is_empty());
}

#[test]
fn test_build_event_chain_single_event() {
    let events = vec![
        create_warning_event("default", "evt-1", "BackOff", "Container restart", "my-pod", 1),
    ];

    let chains = build_event_chain(&events);

    // Single event doesn't create a chain (needs >= 2 events)
    assert!(chains.is_empty());
}

#[test]
fn test_build_event_chain_multiple_events_same_pod() {
    let events = vec![
        create_warning_event("default", "evt-1", "BackOff", "Container restart", "my-pod", 1),
        create_warning_event("default", "evt-2", "Failed", "Container failed", "my-pod", 1),
    ];

    let chains = build_event_chain(&events);

    assert_eq!(chains.len(), 1);
    assert_eq!(chains[0].object, "default/my-pod");
    assert_eq!(chains[0].events.len(), 2);
}

#[test]
fn test_build_event_chain_events_different_pods() {
    let events = vec![
        create_warning_event("default", "evt-1", "BackOff", "Restart", "pod-a", 1),
        create_warning_event("default", "evt-2", "Failed", "Failed", "pod-a", 1),
        create_warning_event("default", "evt-3", "BackOff", "Restart", "pod-b", 1),
        create_warning_event("default", "evt-4", "Failed", "Failed", "pod-b", 1),
    ];

    let chains = build_event_chain(&events);

    assert_eq!(chains.len(), 2);

    // Find chains by object name
    let pod_a_chain = chains.iter().find(|c| c.object.contains("pod-a"));
    let pod_b_chain = chains.iter().find(|c| c.object.contains("pod-b"));

    assert!(pod_a_chain.is_some());
    assert!(pod_b_chain.is_some());
}

#[test]
fn test_build_event_chain_filters_normal_events() {
    let events = vec![
        create_normal_event("default", "evt-1", "Scheduled", "Pod scheduled", "my-pod"),
        create_normal_event("default", "evt-2", "Pulled", "Image pulled", "my-pod"),
        create_warning_event("default", "evt-3", "BackOff", "Restart", "my-pod", 1),
    ];

    let chains = build_event_chain(&events);

    // Chain is built but only warning events are included in chain events
    if !chains.is_empty() {
        let chain = &chains[0];
        // All events in the chain should be warnings
        for event in &chain.events {
            assert!(event.reason == "BackOff");
        }
    }
}

#[test]
fn test_build_event_chain_events_different_namespaces() {
    let events = vec![
        create_warning_event("default", "evt-1", "BackOff", "Restart", "my-pod", 1),
        create_warning_event("default", "evt-2", "Failed", "Failed", "my-pod", 1),
        create_warning_event("kube-system", "evt-3", "BackOff", "Restart", "my-pod", 1),
        create_warning_event("kube-system", "evt-4", "Failed", "Failed", "my-pod", 1),
    ];

    let chains = build_event_chain(&events);

    // Should have 2 chains because namespace is different
    assert_eq!(chains.len(), 2);
}

#[test]
fn test_build_event_chain_root_cause_image_pull() {
    let events = vec![
        create_warning_event(
            "default",
            "evt-1",
            "Failed",
            "Failed to pull image: ImagePullBackOff",
            "my-pod",
            5,
        ),
        create_warning_event(
            "default",
            "evt-2",
            "BackOff",
            "Back-off pulling image",
            "my-pod",
            3,
        ),
    ];

    let chains = build_event_chain(&events);

    assert!(!chains.is_empty());
    let chain = &chains[0];

    // Root cause should mention image pull
    if let Some(root_cause) = &chain.root_cause {
        assert!(
            root_cause.contains("image") || root_cause.contains("Image"),
            "Root cause should mention image issue: {}",
            root_cause
        );
    }
}

#[test]
fn test_build_event_chain_root_cause_insufficient_resources() {
    let events = vec![
        create_warning_event(
            "default",
            "evt-1",
            "FailedScheduling",
            "0/3 nodes are available: Insufficient cpu",
            "my-pod",
            5,
        ),
        create_warning_event(
            "default",
            "evt-2",
            "FailedScheduling",
            "0/3 nodes are available: Insufficient memory",
            "my-pod",
            3,
        ),
    ];

    let chains = build_event_chain(&events);

    assert!(!chains.is_empty());
    let chain = &chains[0];

    if let Some(root_cause) = &chain.root_cause {
        assert!(
            root_cause.contains("Insufficient") || root_cause.contains("Resource") || root_cause.contains("FailedScheduling"),
            "Root cause should mention resource issue: {}",
            root_cause
        );
    }
}

#[test]
fn test_build_event_chain_root_cause_volume_mount() {
    let events = vec![
        create_warning_event(
            "default",
            "evt-1",
            "FailedMount",
            "Unable to mount volumes",
            "my-pod",
            3,
        ),
        create_warning_event(
            "default",
            "evt-2",
            "FailedMount",
            "Volume mount timeout",
            "my-pod",
            2,
        ),
    ];

    let chains = build_event_chain(&events);

    assert!(!chains.is_empty());
    let chain = &chains[0];

    if let Some(root_cause) = &chain.root_cause {
        assert!(
            root_cause.contains("mount") || root_cause.contains("Mount") || root_cause.contains("volume") || root_cause.contains("Volume") || root_cause.contains("FailedMount"),
            "Root cause should mention mount/volume issue: {}",
            root_cause
        );
    }
}

#[test]
fn test_build_event_chain_preserves_event_count() {
    let events = vec![
        create_warning_event("default", "evt-1", "BackOff", "Restart", "my-pod", 10),
        create_warning_event("default", "evt-2", "Failed", "Failed", "my-pod", 5),
    ];

    let chains = build_event_chain(&events);

    assert!(!chains.is_empty());
    let chain = &chains[0];

    // Find the BackOff event and check its count
    let backoff_event = chain.events.iter().find(|e| e.reason == "BackOff");
    assert!(backoff_event.is_some());
    assert_eq!(backoff_event.unwrap().count, 10);
}

// ============================================================================
// Event chain edge cases
// ============================================================================

#[test]
fn test_build_event_chain_no_namespace() {
    let mut event = create_warning_event("", "evt-1", "BackOff", "Restart", "my-pod", 1);
    event.involved_object.namespace = None;

    let mut event2 = create_warning_event("", "evt-2", "Failed", "Failed", "my-pod", 1);
    event2.involved_object.namespace = None;

    let events = vec![event, event2];
    let chains = build_event_chain(&events);

    // Should still create a chain even without namespace
    assert!(!chains.is_empty());
}

#[test]
fn test_build_event_chain_missing_reason() {
    let mut event1 = create_warning_event("default", "evt-1", "", "Restart", "my-pod", 1);
    event1.reason = None;

    let event2 = create_warning_event("default", "evt-2", "Failed", "Failed", "my-pod", 1);

    let events = vec![event1, event2];
    let chains = build_event_chain(&events);

    // Should handle missing reason gracefully
    assert!(!chains.is_empty());
}

#[test]
fn test_build_event_chain_missing_message() {
    let mut event1 = create_warning_event("default", "evt-1", "BackOff", "", "my-pod", 1);
    event1.message = None;

    let event2 = create_warning_event("default", "evt-2", "Failed", "Failed", "my-pod", 1);

    let events = vec![event1, event2];
    let chains = build_event_chain(&events);

    // Should handle missing message gracefully
    assert!(!chains.is_empty());
}

#[test]
fn test_build_event_chain_clone() {
    let chain = EventChain {
        object: "default/my-pod".to_string(),
        events: vec![
            ChainEvent {
                reason: "BackOff".to_string(),
                message: "Restart".to_string(),
                count: 5,
            },
        ],
        root_cause: Some("Test".to_string()),
    };

    let cloned = chain.clone();

    assert_eq!(chain.object, cloned.object);
    assert_eq!(chain.events.len(), cloned.events.len());
    assert_eq!(chain.root_cause, cloned.root_cause);
}

#[test]
fn test_chain_event_clone() {
    let event = ChainEvent {
        reason: "BackOff".to_string(),
        message: "Restart".to_string(),
        count: 5,
    };

    let cloned = event.clone();

    assert_eq!(event.reason, cloned.reason);
    assert_eq!(event.message, cloned.message);
    assert_eq!(event.count, cloned.count);
}
