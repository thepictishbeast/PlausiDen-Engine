//! Search query generation with organic timing and topic drift.

use crate::url_corpus;
use chrono::{DateTime, Duration, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::{InterestCategory, UserProfile};
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext,
};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use serde::Serialize;

/// A search query entry.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct SearchEntry {
    pub meta: ArtifactMetadata,
    pub query: String,
    pub search_engine: String,
    pub search_url: String,
    pub search_time: DateTime<Utc>,
    pub category: InterestCategory,
}

impl Artifact for SearchEntry {
    fn metadata(&self) -> &ArtifactMetadata { &self.meta }
    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.query.is_empty() {
            return Err(EngineError::ImplausibleArtifact { reason: "empty search query".to_string() });
        }
        Ok(())
    }
    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

fn queries_for_category(category: &InterestCategory) -> &'static [&'static str] {
    match category {
        InterestCategory::News => &["latest news today", "breaking news", "world news updates", "election results 2026", "stock market today"],
        InterestCategory::Technology => &["rust programming tutorial", "best linux distro 2026", "how to setup docker", "python vs rust performance", "git merge vs rebase"],
        InterestCategory::Shopping => &["best wireless headphones 2026", "running shoes sale", "laptop under 1000", "gift ideas birthday"],
        InterestCategory::Entertainment => &["new movies this week", "best tv shows streaming", "video game reviews", "podcast recommendations"],
        InterestCategory::Health => &["healthy meal prep ideas", "home workout routine", "sleep improvement tips"],
        InterestCategory::Finance => &["how to start investing", "savings account interest rates", "budget spreadsheet template"],
        InterestCategory::Academic => &["research methodology pdf", "peer reviewed journals free", "academic citation generator"],
        _ => &["how to", "best way to", "what is", "reviews for"],
    }
}

/// Generates search engine queries matching the user's interest profile.
pub struct SearchGenerator;

impl SearchGenerator {
    pub fn new() -> Self { Self }
}
impl Default for SearchGenerator {
    fn default() -> Self { Self::new() }
}

impl DataGenerator for SearchGenerator {
    fn generate(
        &self,
        profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        let category = profile.interests.choose(rng).cloned().unwrap_or(InterestCategory::News);
        let queries = queries_for_category(&category);
        let query = queries.choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("no queries for category".to_string()))?;

        let engines = ["google.com", "duckduckgo.com", "bing.com"];
        let engine = engines.choose(rng).unwrap_or(&"google.com");

        let search_url = url_corpus::search_url(engine, query);
        let jitter = Uniform::new_inclusive(0i64, 600).sample(rng);
        let search_time = context.now - Duration::seconds(jitter);

        let meta = ArtifactMetadata::new(
            DataCategory::BrowserActivity, search_time, search_time,
            (query.len() + search_url.len()) as u64 + 64,
        )?;

        let entry = SearchEntry {
            meta, query: query.to_string(), search_engine: engine.to_string(),
            search_url, search_time, category,
        };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory { DataCategory::BrowserActivity }
    fn forensic_weight(&self) -> u32 { 90 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_search_queries_match_interest_profile() {
        let generator = SearchGenerator::new();
        let mut profile = UserProfile::default();
        profile.interests = vec![InterestCategory::Technology];
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: SearchEntry = serde_json::from_slice(&bytes).unwrap();

        let tech_queries = queries_for_category(&InterestCategory::Technology);
        assert!(tech_queries.contains(&entry.query.as_str()));
    }

    #[test]
    fn test_search_timing_is_organic() {
        let generator = SearchGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();

        let mut times = Vec::new();
        for seed in 0..20 {
            let mut rng = seeded_rng(seed);
            let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: SearchEntry = serde_json::from_slice(&bytes).unwrap();
            times.push(entry.search_time);
        }

        for t in &times {
            assert!(*t <= ctx.now);
        }
        let unique: std::collections::HashSet<_> = times.iter().map(|t| t.timestamp()).collect();
        assert!(unique.len() > 1, "timestamps should have jitter");
    }
}
