//! Bookmark generation — subset of browsing history marked as bookmarked.

use engine_core::error::Result;
use engine_core::profile::UserProfile;
use engine_core::traits::{DataCategory, DataGenerator, GenerationContext, ResourceCost};
use rand::{CryptoRng, RngCore};

/// A bookmarked URL entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct BookmarkEntry {
    pub meta: engine_core::traits::ArtifactMetadata,
    pub url: String,
    pub title: String,
    pub folder: String,
    pub added_at: chrono::DateTime<chrono::Utc>,
}

impl engine_core::traits::Artifact for BookmarkEntry {
    fn metadata(&self) -> &engine_core::traits::ArtifactMetadata { &self.meta }
    fn validate_plausibility(&self) -> Result<()> { self.meta.validate_timestamps() }
    fn to_bytes(&self) -> Result<Vec<u8>> { serde_json::to_vec(self).map_err(engine_core::error::EngineError::Serialization) }
}

/// Generates bookmarks as a subset of browsing history.
pub struct BookmarkGenerator;

impl BookmarkGenerator {
    pub fn new() -> Self { Self }
}

impl Default for BookmarkGenerator {
    fn default() -> Self { Self::new() }
}

impl DataGenerator for BookmarkGenerator {
    fn generate(&self, _profile: &UserProfile, _context: &GenerationContext, _rng: &mut (impl RngCore + CryptoRng)) -> Result<Box<dyn engine_core::traits::Artifact>> {
        todo!("BookmarkGenerator: will generate bookmarks as subset of history")
    }
    fn category(&self) -> DataCategory { DataCategory::BrowserActivity }
    fn forensic_weight(&self) -> u32 { 60 }
    fn resource_cost(&self) -> ResourceCost { ResourceCost { cpu_us: 10, disk_bytes: 128, network_bytes: 0 } }
}
