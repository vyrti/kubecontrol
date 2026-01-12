//! Fuzzy matching for resource names

use crate::error::{KcError, Result};
use nucleo::{Config, Matcher, Utf32Str};

/// Fuzzy matcher for resource names
pub struct FuzzyMatcher {
    matcher: Matcher,
}

impl Default for FuzzyMatcher {
    fn default() -> Self {
        Self::new()
    }
}

impl FuzzyMatcher {
    /// Create a new fuzzy matcher
    pub fn new() -> Self {
        Self {
            matcher: Matcher::new(Config::DEFAULT),
        }
    }

    /// Match a pattern against a list of candidates
    /// Returns sorted matches with scores (highest first)
    pub fn match_candidates<'a>(&mut self, pattern: &str, candidates: &'a [String]) -> Vec<(&'a str, u16)> {
        if pattern.is_empty() {
            return Vec::new();
        }

        let mut pattern_buf = Vec::new();
        let pattern_utf32 = Utf32Str::new(pattern, &mut pattern_buf);

        let mut matches: Vec<(&str, u16)> = candidates
            .iter()
            .filter_map(|candidate| {
                let mut candidate_buf = Vec::new();
                let candidate_utf32 = Utf32Str::new(candidate, &mut candidate_buf);
                self.matcher
                    .fuzzy_match(candidate_utf32, pattern_utf32)
                    .map(|score| (candidate.as_str(), score))
            })
            .collect();

        // Sort by score descending
        matches.sort_by(|a, b| b.1.cmp(&a.1));
        matches
    }
}

/// Resolve a potentially partial resource name to an exact name
/// If exact match exists, returns it. Otherwise attempts fuzzy match.
pub fn resolve_name(pattern: &str, candidates: &[String]) -> Result<String> {
    // First try exact match
    if candidates.iter().any(|c| c == pattern) {
        return Ok(pattern.to_string());
    }

    // Try fuzzy matching
    let mut matcher = FuzzyMatcher::new();
    let matches = matcher.match_candidates(pattern, candidates);

    match matches.len() {
        0 => Err(KcError::NotFound {
            kind: "resource".to_string(),
            name: pattern.to_string(),
        }),
        1 => Ok(matches[0].0.to_string()),
        _ => {
            // Check if there's a clear winner (score > 2x the second)
            if matches[0].1 > matches[1].1 * 2 {
                Ok(matches[0].0.to_string())
            } else {
                // Ambiguous - return top matches
                Err(KcError::AmbiguousMatch {
                    pattern: pattern.to_string(),
                    matches: matches.iter().take(5).map(|(n, _)| n.to_string()).collect(),
                })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let candidates = vec![
            "nginx-deployment".to_string(),
            "redis-master".to_string(),
            "postgres-db".to_string(),
        ];

        let result = resolve_name("nginx-deployment", &candidates);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "nginx-deployment");
    }

    #[test]
    fn test_fuzzy_match_single() {
        let candidates = vec![
            "nginx-deployment".to_string(),
            "redis-master".to_string(),
            "postgres-db".to_string(),
        ];

        let result = resolve_name("nginx", &candidates);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "nginx-deployment");
    }

    #[test]
    fn test_fuzzy_match_abbreviation() {
        let candidates = vec![
            "nginx-deployment".to_string(),
            "redis-master".to_string(),
            "postgres-db".to_string(),
        ];

        let result = resolve_name("ngx", &candidates);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "nginx-deployment");
    }

    #[test]
    fn test_no_match() {
        let candidates = vec![
            "nginx-deployment".to_string(),
            "redis-master".to_string(),
        ];

        let result = resolve_name("xyz123", &candidates);
        assert!(result.is_err());
    }
}
