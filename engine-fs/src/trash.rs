//! Trash/Recycle Bin metadata — records of recently deleted files.

use chrono::{DateTime, Duration, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct TrashEntry {
    pub meta: ArtifactMetadata,
    pub original_path: String,
    pub deleted_at: DateTime<Utc>,
    pub file_size: u64,
}

impl Artifact for TrashEntry {
    fn metadata(&self) -> &ArtifactMetadata { &self.meta }
    fn validate_plausibility(&self) -> Result<()> { self.meta.validate_timestamps() }
    fn to_bytes(&self) -> Result<Vec<u8>> { serde_json::to_vec(self).map_err(EngineError::Serialization) }
}

const DELETED_FILES: &[(&str, u64)] = &[
    ("/home/user/Downloads/old_installer.deb", 80_000_000),
    ("/home/user/Documents/draft_v1.docx", 50_000),
    ("/home/user/Pictures/screenshot_old.png", 2_000_000),
    ("/home/user/tmp/test.txt", 500),
    ("/home/user/Downloads/archive.tar.gz", 150_000_000),
];

pub struct TrashGenerator;
impl TrashGenerator { pub fn new() -> Self { Self } }
impl Default for TrashGenerator { fn default() -> Self { Self::new() } }

impl DataGenerator for TrashGenerator {
    fn generate(&self, _profile: &UserProfile, context: &GenerationContext, rng: &mut (impl RngCore + CryptoRng)) -> Result<Box<dyn Artifact>> {
        let (path, size) = DELETED_FILES.choose(rng).unwrap();
        let days_ago = Uniform::new_inclusive(1i64, 30).sample(rng);
        let deleted_at = context.now - Duration::days(days_ago);
        let meta = ArtifactMetadata::new(DataCategory::FileSystem, deleted_at, deleted_at, *size)?;
        let entry = TrashEntry { meta, original_path: path.to_string(), deleted_at, file_size: *size };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }
    fn category(&self) -> DataCategory { DataCategory::FileSystem }
    fn forensic_weight(&self) -> u32 { 55 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;
    #[test]
    fn test_trash() { let g = TrashGenerator::new(); let p = UserProfile::default(); let c = GenerationContext::new(); let mut r = seeded_rng(42); g.generate(&p, &c, &mut r).unwrap().validate_plausibility().unwrap(); }
}
