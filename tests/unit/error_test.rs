//! Tests for src/error/mod.rs - KcError

use kubecontrol::error::KcError;
use std::error::Error;

// ============================================================================
// KcError Display tests
// ============================================================================

#[test]
fn test_not_found_error_display() {
    let err = KcError::NotFound {
        kind: "Pod".to_string(),
        name: "my-pod".to_string(),
    };
    let display = format!("{}", err);
    assert!(display.contains("Resource not found"));
    assert!(display.contains("Pod"));
    assert!(display.contains("my-pod"));
}

#[test]
fn test_ambiguous_match_error_display() {
    let err = KcError::AmbiguousMatch {
        pattern: "test".to_string(),
        matches: vec!["test-1".to_string(), "test-2".to_string(), "test-3".to_string()],
    };
    let display = format!("{}", err);
    assert!(display.contains("Multiple matches"));
    assert!(display.contains("test"));
    assert!(display.contains("test-1"));
    assert!(display.contains("test-2"));
    assert!(display.contains("test-3"));
}

#[test]
fn test_no_context_error_display() {
    let err = KcError::NoContext;
    let display = format!("{}", err);
    assert!(display.contains("No context specified"));
}

#[test]
fn test_context_not_found_error_display() {
    let err = KcError::ContextNotFound("my-context".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Context not found"));
    assert!(display.contains("my-context"));
}

#[test]
fn test_namespace_not_found_error_display() {
    let err = KcError::NamespaceNotFound("my-namespace".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Namespace not found"));
    assert!(display.contains("my-namespace"));
}

#[test]
fn test_invalid_resource_type_error_display() {
    let err = KcError::InvalidResourceType("bogus".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Invalid resource type"));
    assert!(display.contains("bogus"));
}

#[test]
fn test_config_error_display() {
    let err = KcError::Config("Failed to load kubeconfig".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Configuration error"));
    assert!(display.contains("Failed to load kubeconfig"));
}

#[test]
fn test_cache_error_display() {
    let err = KcError::Cache("Cache miss".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Cache error"));
    assert!(display.contains("Cache miss"));
}

#[test]
fn test_serialization_error_display() {
    let err = KcError::Serialization("Invalid JSON".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Serialization error"));
    assert!(display.contains("Invalid JSON"));
}

#[test]
fn test_invalid_argument_error_display() {
    let err = KcError::InvalidArgument("--replicas must be positive".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Invalid argument"));
    assert!(display.contains("--replicas must be positive"));
}

#[test]
fn test_cancelled_error_display() {
    let err = KcError::Cancelled;
    let display = format!("{}", err);
    assert!(display.contains("Operation cancelled"));
}

#[test]
fn test_timeout_error_display() {
    let err = KcError::Timeout("pod to be ready".to_string());
    let display = format!("{}", err);
    assert!(display.contains("Timeout"));
    assert!(display.contains("pod to be ready"));
}

// ============================================================================
// KcError From conversions tests
// ============================================================================

#[test]
fn test_from_io_error() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
    let kc_err: KcError = io_err.into();

    if let KcError::Io(e) = kc_err {
        assert_eq!(e.kind(), std::io::ErrorKind::NotFound);
    } else {
        panic!("Expected KcError::Io");
    }
}

#[test]
fn test_from_serde_json_error() {
    let json_err = serde_json::from_str::<serde_json::Value>("invalid json").unwrap_err();
    let kc_err: KcError = json_err.into();

    if let KcError::Serialization(msg) = kc_err {
        assert!(!msg.is_empty());
    } else {
        panic!("Expected KcError::Serialization");
    }
}

#[test]
fn test_from_serde_yaml_error() {
    let yaml_err = serde_yaml::from_str::<serde_yaml::Value>(":\ninvalid").unwrap_err();
    let kc_err: KcError = yaml_err.into();

    if let KcError::Serialization(msg) = kc_err {
        assert!(!msg.is_empty());
    } else {
        panic!("Expected KcError::Serialization");
    }
}

// ============================================================================
// KcError Debug tests
// ============================================================================

#[test]
fn test_error_debug() {
    let err = KcError::NotFound {
        kind: "Pod".to_string(),
        name: "test".to_string(),
    };
    let debug = format!("{:?}", err);
    assert!(debug.contains("NotFound"));
    assert!(debug.contains("Pod"));
    assert!(debug.contains("test"));
}

// ============================================================================
// KcError Error trait tests
// ============================================================================

#[test]
fn test_error_source_io() {
    let io_err = std::io::Error::new(std::io::ErrorKind::NotFound, "file not found");
    let kc_err: KcError = io_err.into();

    // KcError::Io should have a source
    assert!(kc_err.source().is_some());
}

#[test]
fn test_error_source_not_found() {
    let err = KcError::NotFound {
        kind: "Pod".to_string(),
        name: "test".to_string(),
    };

    // NotFound doesn't have a source error
    assert!(err.source().is_none());
}

// ============================================================================
// KcError Pattern matching tests
// ============================================================================

#[test]
fn test_error_pattern_matching() {
    let err = KcError::ContextNotFound("test-ctx".to_string());

    match &err {
        KcError::ContextNotFound(name) => assert_eq!(name, "test-ctx"),
        _ => panic!("Wrong error variant"),
    }
}

#[test]
fn test_ambiguous_match_has_matches() {
    let err = KcError::AmbiguousMatch {
        pattern: "test".to_string(),
        matches: vec!["a".to_string(), "b".to_string()],
    };

    if let KcError::AmbiguousMatch { pattern, matches } = err {
        assert_eq!(pattern, "test");
        assert_eq!(matches.len(), 2);
    } else {
        panic!("Wrong error variant");
    }
}
