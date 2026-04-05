//! Download history generation — plausible file downloads matching browsing profile.

use engine_core::error::Result;
use engine_core::profile::UserProfile;
use engine_core::traits::{DataCategory, DataGenerator, GenerationContext, ResourceCost};
use rand::{CryptoRng, RngCore};

/// A download history entry.
#[derive(Debug, Clone, serde::Serialize)]
pub struct DownloadEntry {
    pub meta: engine_core::traits::ArtifactMetadata,
    pub url: String,
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: u64,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub completed_at: chrono::DateTime<chrono::Utc>,
}

impl engine_core::traits::Artifact for DownloadEntry {
    fn metadata(&self) -> &engine_core::traits::ArtifactMetadata { &self.meta }
    fn validate_plausibility(&self) -> Result<()> { self.meta.validate_timestamps() }
    fn to_bytes(&self) -> Result<Vec<u8>> { serde_json::to_vec(self).map_err(engine_core::error::EngineError::Serialization) }
}

pub struct DownloadGenerator;
impl DownloadGenerator { pub fn new() -> Self { Self } }
impl Default for DownloadGenerator { fn default() -> Self { Self::new() } }

impl DataGenerator for DownloadGenerator {
    fn generate(&self, _profile: &UserProfile, _context: &GenerationContext, _rng: &mut (impl RngCore + CryptoRng)) -> Result<Box<dyn engine_core::traits::Artifact>> {
        todo!("DownloadGenerator: will generate plausible download entries")
    }
    fn category(&self) -> DataCategory { DataCategory::BrowserActivity }
    fn forensic_weight(&self) -> u32 { 75 }
    fn resource_cost(&self) -> ResourceCost { ResourceCost { cpu_us: 30, disk_bytes: 256, network_bytes: 0 } }
}
