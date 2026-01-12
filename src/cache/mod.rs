//! Caching layer for Kubernetes resource data

use dashmap::DashMap;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

/// Entry in the in-memory cache
struct CacheEntry {
    data: Vec<u8>,
    created_at: Instant,
}

/// Resource cache with in-memory storage
pub struct Cache {
    /// In-memory cache using DashMap for concurrent access
    memory: DashMap<String, CacheEntry>,
    /// Time-to-live for cache entries
    ttl: Duration,
}

impl Cache {
    /// Create a new cache with the specified TTL in seconds
    pub fn new(ttl_seconds: u64) -> Self {
        Self {
            memory: DashMap::new(),
            ttl: Duration::from_secs(ttl_seconds),
        }
    }

    /// Get a value from the cache
    pub fn get<T: DeserializeOwned>(&self, key: &str) -> Option<T> {
        if let Some(entry) = self.memory.get(key) {
            if entry.created_at.elapsed() < self.ttl {
                return serde_json::from_slice(&entry.data).ok();
            } else {
                // Entry expired, remove it
                drop(entry);
                self.memory.remove(key);
            }
        }
        None
    }

    /// Set a value in the cache
    pub fn set<T: Serialize>(&self, key: &str, value: &T) {
        let data = match serde_json::to_vec(value) {
            Ok(d) => d,
            Err(_) => return,
        };

        self.memory.insert(
            key.to_string(),
            CacheEntry {
                data,
                created_at: Instant::now(),
            },
        );
    }

    /// Remove a value from the cache
    pub fn remove(&self, key: &str) {
        self.memory.remove(key);
    }

    /// Clear all entries from the cache
    pub fn clear(&self) {
        self.memory.clear();
    }

    /// Get the number of entries in the cache
    pub fn len(&self) -> usize {
        self.memory.len()
    }

    /// Check if the cache is empty
    pub fn is_empty(&self) -> bool {
        self.memory.is_empty()
    }

    /// Generate a cache key for a resource list query
    pub fn list_key(context: Option<&str>, namespace: Option<&str>, resource_type: &str) -> String {
        format!(
            "list:{}:{}:{}",
            context.unwrap_or("default"),
            namespace.unwrap_or("all"),
            resource_type
        )
    }

    /// Generate a cache key for a single resource
    pub fn resource_key(
        context: Option<&str>,
        namespace: Option<&str>,
        resource_type: &str,
        name: &str,
    ) -> String {
        format!(
            "get:{}:{}:{}:{}",
            context.unwrap_or("default"),
            namespace.unwrap_or("all"),
            resource_type,
            name
        )
    }
}

/// Global cache instance
static GLOBAL_CACHE: OnceLock<Cache> = OnceLock::new();

/// Get the global cache instance
pub fn global_cache() -> &'static Cache {
    GLOBAL_CACHE.get_or_init(|| Cache::new(30)) // 30 second TTL
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_set_get() {
        let cache = Cache::new(60);

        cache.set("test_key", &vec!["value1", "value2"]);

        let result: Option<Vec<String>> = cache.get("test_key");
        assert!(result.is_some());
        assert_eq!(result.unwrap(), vec!["value1", "value2"]);
    }

    #[test]
    fn test_cache_miss() {
        let cache = Cache::new(60);

        let result: Option<String> = cache.get("nonexistent");
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_remove() {
        let cache = Cache::new(60);

        cache.set("key", &"value".to_string());
        assert!(cache.get::<String>("key").is_some());

        cache.remove("key");
        assert!(cache.get::<String>("key").is_none());
    }

    #[test]
    fn test_cache_clear() {
        let cache = Cache::new(60);

        cache.set("key1", &"value1".to_string());
        cache.set("key2", &"value2".to_string());
        assert_eq!(cache.len(), 2);

        cache.clear();
        assert!(cache.is_empty());
    }

    #[test]
    fn test_cache_key_generation() {
        let key = Cache::list_key(Some("prod"), Some("default"), "pods");
        assert_eq!(key, "list:prod:default:pods");

        let key = Cache::resource_key(Some("prod"), Some("default"), "pod", "nginx");
        assert_eq!(key, "get:prod:default:pod:nginx");
    }
}
