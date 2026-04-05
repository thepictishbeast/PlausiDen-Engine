//! Browser history generation with referrer chains and realistic timestamps.
//!
//! Generates browsing history entries that forensic analysts cannot distinguish
//! from organic browsing. Each entry has a URL, timestamp, visit count,
//! transition type, and referrer chain linking it to previous visits.

use crate::url_corpus;
use chrono::{DateTime, Duration, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext, ResourceCost,
};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use serde::Serialize;

/// How the user navigated to this URL.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub enum TransitionType {
    /// User clicked a link on another page.
    Link,
    /// User typed the URL directly.
    Typed,
    /// Page redirected automatically.
    Redirect,
    /// User used a bookmark.
    Bookmark,
    /// Search engine result.
    SearchResult,
    /// User reloaded the page.
    Reload,
}

/// A single browser history entry.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct HistoryEntry {
    /// Artifact metadata.
    pub meta: ArtifactMetadata,
    /// The visited URL.
    pub url: String,
    /// Page title (derived from URL).
    pub title: String,
    /// When this page was visited.
    pub visit_time: DateTime<Utc>,
    /// Number of times this URL has been visited.
    pub visit_count: u32,
    /// How the user got to this page.
    pub transition: TransitionType,
    /// Referrer URL (if navigated from another page).
    pub referrer: Option<String>,
}

impl Artifact for HistoryEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;

        // URL must not be empty
        if self.url.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty URL".to_string(),
            });
        }

        // Visit count must be at least 1
        if self.visit_count == 0 {
            return Err(EngineError::ImplausibleArtifact {
                reason: "visit count is zero".to_string(),
            });
        }

        // If transition is Link or SearchResult, referrer should exist
        if matches!(self.transition, TransitionType::Link | TransitionType::SearchResult)
            && self.referrer.is_none()
        {
            return Err(EngineError::ImplausibleArtifact {
                reason: "link/search transition without referrer".to_string(),
            });
        }

        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

/// Generates browser history entries with referrer chains.
pub struct HistoryGenerator {
    /// Recent URLs generated in this session for building referrer chains.
    pub recent_urls: Vec<String>,
}

impl HistoryGenerator {
    /// Create a new history generator.
    pub fn new() -> Self {
        Self {
            recent_urls: Vec::new(),
        }
    }

    /// Generate a title from a URL.
    fn title_from_url(url: &str) -> String {
        // Extract domain and path for a plausible title
        if let Some(domain) = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
        {
            let parts: Vec<&str> = domain.splitn(2, '/').collect();
            let domain_name = parts[0]
                .strip_prefix("www.")
                .unwrap_or(parts[0]);

            if parts.len() > 1 && !parts[1].is_empty() {
                let path = parts[1]
                    .split('/')
                    .last()
                    .unwrap_or("Home")
                    .replace('-', " ")
                    .replace('_', " ");
                let path = path.split('?').next().unwrap_or(&path);
                if path.is_empty() {
                    domain_name.to_string()
                } else {
                    format!("{path} — {domain_name}")
                }
            } else {
                domain_name.to_string()
            }
        } else {
            "Untitled".to_string()
        }
    }

    /// Choose a transition type with realistic distribution.
    ///
    /// When `has_referrer` is false, only transitions that do not require a
    /// referrer are returned (Typed, Bookmark, Redirect, Reload).
    fn choose_transition(
        has_referrer: bool,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> TransitionType {
        let roll = Uniform::new_inclusive(0u32, 99).sample(rng);
        if has_referrer {
            match roll {
                0..=55 => TransitionType::Link,
                56..=75 => TransitionType::SearchResult,
                76..=85 => TransitionType::Redirect,
                86..=92 => TransitionType::Typed,
                93..=97 => TransitionType::Bookmark,
                _ => TransitionType::Reload,
            }
        } else {
            // Without a referrer, only transitions that do not require one
            match roll {
                0..=50 => TransitionType::Typed,
                51..=80 => TransitionType::Bookmark,
                81..=93 => TransitionType::Redirect,
                _ => TransitionType::Reload,
            }
        }
    }
}

impl Default for HistoryGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for HistoryGenerator {
    fn generate(
        &self,
        profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        // Pick a URL from the user's interest categories
        let category = profile
            .interests
            .choose(rng)
            .unwrap_or(&engine_core::profile::InterestCategory::News);

        let urls = url_corpus::urls_for_category(category);
        let base_url = urls
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("no URLs for category".to_string()))?;

        // Sometimes visit the base URL, sometimes a subpage
        let visit_subpage = Uniform::new_inclusive(0u32, 2).sample(rng);
        let url = if visit_subpage == 0 {
            base_url.to_string()
        } else {
            let subpages = url_corpus::subpages_for_url(base_url);
            subpages
                .choose(rng)
                .cloned()
                .unwrap_or_else(|| base_url.to_string())
        };

        // Build referrer chain — use recent URLs if available
        let has_referrer = !self.recent_urls.is_empty()
            && Uniform::new_inclusive(0u32, 3).sample(rng) > 0;
        let referrer = if has_referrer {
            self.recent_urls.last().cloned()
        } else {
            None
        };

        let transition = Self::choose_transition(referrer.is_some(), rng);

        // Timestamp: slightly before "now" in context, with jitter
        let jitter_secs = Uniform::new_inclusive(0i64, 300)
            
            .sample(rng);
        let visit_time = context.now - Duration::seconds(jitter_secs);

        // Visit count: usually 1-5, occasionally higher for frequently visited sites
        let visit_count = if Uniform::new_inclusive(0u32, 9).sample(rng) > 7 {
            Uniform::new_inclusive(5u32, 50)
                
                .sample(rng)
        } else {
            Uniform::new_inclusive(1u32, 5)
                
                .sample(rng)
        };

        let title = Self::title_from_url(&url);

        let meta = ArtifactMetadata::new(
            DataCategory::BrowserActivity,
            visit_time,
            visit_time,
            url.len() as u64 + title.len() as u64 + 128,
        )?;

        let entry = HistoryEntry {
            meta,
            url,
            title,
            visit_time,
            visit_count,
            transition,
            referrer,
        };

        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory {
        DataCategory::BrowserActivity
    }

    fn forensic_weight(&self) -> u32 {
        100 // Browser history is the most relied-upon forensic artifact
    }

    fn resource_cost(&self) -> ResourceCost {
        ResourceCost {
            cpu_us: 50,
            disk_bytes: 512,
            network_bytes: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    fn test_profile() -> UserProfile {
        UserProfile::default()
    }

    #[test]
    fn test_history_entry_has_realistic_timestamps() {
        let generator = HistoryGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
        let meta = artifact.metadata();

        // Timestamp should be in the past or very near present
        assert!(meta.created_at <= Utc::now() + Duration::seconds(1));
        // Should not be unreasonably old
        assert!(meta.created_at > Utc::now() - Duration::hours(1));
    }

    #[test]
    fn test_history_entries_have_referrer_chains() {
        let mut generator = HistoryGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        // Generate several entries to build up recent_urls
        let mut has_referrer = false;
        for _ in 0..20 {
            let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: HistoryEntry = serde_json::from_slice(&bytes).unwrap();

            if entry.referrer.is_some() {
                has_referrer = true;
            }

            // Add to recent URLs for next iteration
            generator.recent_urls.push(entry.url);
            if generator.recent_urls.len() > 10 {
                generator.recent_urls.remove(0);
            }
        }

        assert!(has_referrer, "at least some entries should have referrers after building history");
    }

    #[test]
    fn test_downloads_have_plausible_filenames() {
        // History URLs should look like real URLs
        let generator = HistoryGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(99);

        let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: HistoryEntry = serde_json::from_slice(&bytes).unwrap();

        assert!(entry.url.starts_with("http"), "URL must start with http(s)");
        assert!(!entry.title.is_empty(), "title must not be empty");
    }

    #[test]
    fn test_artifact_serialization_roundtrip() {
        let generator = HistoryGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();

        // Should deserialize back without error
        let entry: HistoryEntry = serde_json::from_slice(&bytes).unwrap();
        assert!(!entry.url.is_empty());
        assert!(entry.visit_count >= 1);
    }

    #[test]
    fn test_1000_entries_all_valid() {
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);
        let mut generator = HistoryGenerator::new();

        for i in 0..1000u64 {
            let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
            artifact.validate_plausibility().unwrap_or_else(|e| {
                panic!("entry {i} failed plausibility: {e}");
            });
            let bytes = artifact.to_bytes().unwrap();
            let entry: HistoryEntry = serde_json::from_slice(&bytes).unwrap();
            assert!(!entry.url.is_empty(), "entry {i}: empty URL");
            assert!(entry.visit_count >= 1, "entry {i}: zero visit count");
            assert!(!entry.title.is_empty(), "entry {i}: empty title");
            assert!(
                entry.url.starts_with("http"),
                "entry {i}: URL does not start with http: {}",
                entry.url,
            );
            // Build up referrer chain for subsequent entries
            generator.recent_urls.push(entry.url);
            if generator.recent_urls.len() > 20 {
                generator.recent_urls.remove(0);
            }
        }
    }

    #[test]
    fn test_referrer_chain_consistency() {
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);
        let mut generator = HistoryGenerator::new();

        let mut link_without_referrer = 0u32;
        let mut total_entries = 0u32;

        for _ in 0..500u64 {
            let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: HistoryEntry = serde_json::from_slice(&bytes).unwrap();

            total_entries += 1;

            // The validate_plausibility already enforces Link/SearchResult must have referrer.
            match entry.transition {
                TransitionType::Link | TransitionType::SearchResult => {
                    if entry.referrer.is_none() {
                        link_without_referrer += 1;
                    }
                }
                _ => {}
            }

            // Build up referrer chain for subsequent entries
            generator.recent_urls.push(entry.url);
            if generator.recent_urls.len() > 20 {
                generator.recent_urls.remove(0);
            }
        }

        assert!(total_entries >= 500);
        // Validation ensures Link/SearchResult always have referrers when generated
        // through the generator, so this should be 0 (enforced by validate_plausibility)
        assert_eq!(
            link_without_referrer, 0,
            "link/search entries must have referrers"
        );
    }

    #[test]
    fn test_visit_count_distribution() {
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);
        let mut generator = HistoryGenerator::new();

        let mut low_count = 0u32;   // 1-5
        let mut high_count = 0u32;  // 5-50

        for _ in 0..1000u64 {
            let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: HistoryEntry = serde_json::from_slice(&bytes).unwrap();

            if entry.visit_count <= 5 {
                low_count += 1;
            } else {
                high_count += 1;
            }

            // Build up referrer chain for subsequent entries
            generator.recent_urls.push(entry.url);
            if generator.recent_urls.len() > 20 {
                generator.recent_urls.remove(0);
            }
        }

        // ~80% should have visit count 1-5 (probability 8/10 from code)
        // ~20% should have visit count 5-50
        assert!(
            low_count > 600,
            "most entries should have low visit counts (1-5): got {low_count}/1000"
        );
        assert!(
            high_count > 50,
            "some entries should have high visit counts (5-50): got {high_count}/1000"
        );
    }
}
