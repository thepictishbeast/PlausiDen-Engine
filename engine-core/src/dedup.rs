//! Artifact deduplication — suppress duplicate synthetic artifacts to avoid
//! statistically suspicious repetition patterns.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::hash::Hasher;

/// A deduplication key for an artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedupKey {
    pub category: String,
    pub content_hash: String,
}

/// Record of a seen artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SeenArtifact {
    pub key: DedupKey,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub count: u32,
}

/// Dedup window policies.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DedupPolicy {
    /// Suppress exact matches within this many seconds.
    pub exact_window_secs: i64,
    /// Maximum allowed repeats of the same artifact in the entire window.
    pub max_repeats: u32,
    /// Lifetime of the dedup cache.
    pub cache_lifetime_secs: i64,
}

impl Default for DedupPolicy {
    fn default() -> Self {
        Self {
            exact_window_secs: 3600,
            max_repeats: 3,
            cache_lifetime_secs: 86_400,
        }
    }
}

/// Artifact deduplicator.
pub struct ArtifactDeduplicator {
    seen: HashMap<String, SeenArtifact>, // hash-hex → record
    policy: DedupPolicy,
    suppressed: u64,
    allowed: u64,
}

impl ArtifactDeduplicator {
    pub fn new(policy: DedupPolicy) -> Self {
        Self {
            seen: HashMap::new(),
            policy,
            suppressed: 0,
            allowed: 0,
        }
    }

    /// Compute a 128-bit fingerprint (two 64-bit SipHash values with different
    /// seeds) of the artifact content. This is not cryptographic but has
    /// negligible collision probability for dedup of synthetic artifacts.
    pub fn hash_content(content: &[u8]) -> String {
        let mut h1 = std::collections::hash_map::DefaultHasher::new();
        h1.write(content);
        let mut h2 = std::collections::hash_map::DefaultHasher::new();
        h2.write(&[0xaa]);
        h2.write(content);
        h2.write(&[0x55]);
        format!("{:016x}{:016x}", h1.finish(), h2.finish())
    }

    /// Check whether an artifact should be allowed through.
    pub fn check(&mut self, category: &str, content: &[u8]) -> DedupResult {
        self.prune_expired();

        let hash_hex = Self::hash_content(content);
        let now = Utc::now();

        let entry = self.seen.entry(hash_hex.clone());
        match entry {
            std::collections::hash_map::Entry::Occupied(mut o) => {
                let rec = o.get_mut();
                let age = (now - rec.last_seen).num_seconds();
                if age < self.policy.exact_window_secs {
                    // Within the window — check repeat cap.
                    if rec.count >= self.policy.max_repeats {
                        self.suppressed += 1;
                        return DedupResult::Suppressed {
                            reason: SuppressReason::MaxRepeats,
                        };
                    }
                    rec.count += 1;
                    rec.last_seen = now;
                    self.suppressed += 1;
                    return DedupResult::Suppressed {
                        reason: SuppressReason::ExactMatch,
                    };
                } else {
                    // Outside window — reset.
                    rec.count = 1;
                    rec.last_seen = now;
                    self.allowed += 1;
                    return DedupResult::Allowed;
                }
            }
            std::collections::hash_map::Entry::Vacant(v) => {
                v.insert(SeenArtifact {
                    key: DedupKey {
                        category: category.into(),
                        content_hash: hash_hex,
                    },
                    first_seen: now,
                    last_seen: now,
                    count: 1,
                });
                self.allowed += 1;
                DedupResult::Allowed
            }
        }
    }

    fn prune_expired(&mut self) {
        let cutoff = Utc::now() - chrono::Duration::seconds(self.policy.cache_lifetime_secs);
        self.seen.retain(|_, rec| rec.last_seen >= cutoff);
    }

    /// Total unique artifacts seen.
    pub fn unique_count(&self) -> usize {
        self.seen.len()
    }

    /// Count of allowed artifacts.
    pub fn allowed_count(&self) -> u64 {
        self.allowed
    }

    /// Count of suppressed artifacts.
    pub fn suppressed_count(&self) -> u64 {
        self.suppressed
    }

    /// Per-category distribution of unique artifacts.
    pub fn by_category(&self) -> HashMap<String, usize> {
        let mut map = HashMap::new();
        for rec in self.seen.values() {
            *map.entry(rec.key.category.clone()).or_insert(0) += 1;
        }
        map
    }

    /// Clear cache.
    pub fn clear(&mut self) {
        self.seen.clear();
        self.allowed = 0;
        self.suppressed = 0;
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DedupResult {
    Allowed,
    Suppressed { reason: SuppressReason },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SuppressReason {
    ExactMatch,
    MaxRepeats,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_allowed() {
        let mut d = ArtifactDeduplicator::new(DedupPolicy::default());
        assert_eq!(d.check("browser", b"content"), DedupResult::Allowed);
    }

    #[test]
    fn test_duplicate_suppressed() {
        let mut d = ArtifactDeduplicator::new(DedupPolicy::default());
        d.check("browser", b"same");
        let result = d.check("browser", b"same");
        assert_eq!(
            result,
            DedupResult::Suppressed {
                reason: SuppressReason::ExactMatch
            }
        );
    }

    #[test]
    fn test_different_content_allowed() {
        let mut d = ArtifactDeduplicator::new(DedupPolicy::default());
        d.check("browser", b"content_a");
        assert_eq!(d.check("browser", b"content_b"), DedupResult::Allowed);
    }

    #[test]
    fn test_max_repeats_cap() {
        let policy = DedupPolicy {
            exact_window_secs: 3600,
            max_repeats: 2,
            cache_lifetime_secs: 86_400,
        };
        let mut d = ArtifactDeduplicator::new(policy);
        d.check("x", b"a");
        d.check("x", b"a"); // count=2
        let result = d.check("x", b"a"); // suppressed — at cap
        assert_eq!(
            result,
            DedupResult::Suppressed {
                reason: SuppressReason::MaxRepeats
            }
        );
    }

    #[test]
    fn test_unique_count() {
        let mut d = ArtifactDeduplicator::new(DedupPolicy::default());
        d.check("a", b"one");
        d.check("a", b"two");
        d.check("a", b"three");
        d.check("a", b"one"); // dup
        assert_eq!(d.unique_count(), 3);
    }

    #[test]
    fn test_counters() {
        let mut d = ArtifactDeduplicator::new(DedupPolicy::default());
        d.check("a", b"one"); // allowed
        d.check("a", b"two"); // allowed
        d.check("a", b"one"); // suppressed
        assert_eq!(d.allowed_count(), 2);
        assert_eq!(d.suppressed_count(), 1);
    }

    #[test]
    fn test_by_category() {
        let mut d = ArtifactDeduplicator::new(DedupPolicy::default());
        d.check("browser", b"a");
        d.check("browser", b"b");
        d.check("filesystem", b"c");
        let by = d.by_category();
        assert_eq!(*by.get("browser").unwrap(), 2);
        assert_eq!(*by.get("filesystem").unwrap(), 1);
    }

    #[test]
    fn test_clear() {
        let mut d = ArtifactDeduplicator::new(DedupPolicy::default());
        d.check("a", b"one");
        d.clear();
        assert_eq!(d.unique_count(), 0);
        assert_eq!(d.allowed_count(), 0);
    }
}
