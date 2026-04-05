//! Thumbnail cache metadata — records of which files have been previewed.

use chrono::{DateTime, Duration, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ThumbnailEntry {
    pub meta: ArtifactMetadata,
    pub original_path: String,
    pub thumbnail_uri: String,
    pub mime_type: String,
    pub width: u32,
    pub height: u32,
    pub cached_at: DateTime<Utc>,
}

impl Artifact for ThumbnailEntry {
    fn metadata(&self) -> &ArtifactMetadata { &self.meta }
    fn validate_plausibility(&self) -> Result<()> { self.meta.validate_timestamps() }
    fn to_bytes(&self) -> Result<Vec<u8>> { serde_json::to_vec(self).map_err(EngineError::Serialization) }
}

const THUMB_SOURCES: &[(&str, &str)] = &[
    ("/home/user/Pictures/vacation.jpg", "image/jpeg"),
    ("/home/user/Documents/report.pdf", "application/pdf"),
    ("/home/user/Downloads/photo.png", "image/png"),
    ("/home/user/Videos/clip.mp4", "video/mp4"),
    ("/home/user/Documents/spreadsheet.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
];

pub struct ThumbnailGenerator;
impl ThumbnailGenerator { pub fn new() -> Self { Self } }
impl Default for ThumbnailGenerator { fn default() -> Self { Self::new() } }

impl DataGenerator for ThumbnailGenerator {
    fn generate(&self, _profile: &UserProfile, context: &GenerationContext, rng: &mut (impl RngCore + CryptoRng)) -> Result<Box<dyn Artifact>> {
        let (path, mime) = THUMB_SOURCES.choose(rng).unwrap();
        let w = [128, 256, 512].choose(rng).unwrap();
        let h = [128, 256, 512].choose(rng).unwrap();
        let days_ago = Uniform::new_inclusive(1i64, 90).sample(rng);
        let cached_at = context.now - Duration::days(days_ago);
        let hash = Uniform::new_inclusive(100000u32, 999999).sample(rng);
        let meta = ArtifactMetadata::new(DataCategory::FileSystem, cached_at, cached_at, 8192)?;
        let entry = ThumbnailEntry { meta, original_path: path.to_string(), thumbnail_uri: format!("file:///home/user/.cache/thumbnails/normal/{hash}.png"), mime_type: mime.to_string(), width: *w, height: *h, cached_at };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }
    fn category(&self) -> DataCategory { DataCategory::FileSystem }
    fn forensic_weight(&self) -> u32 { 40 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;
    #[test]
    fn test_thumbnail() { let g = ThumbnailGenerator::new(); let p = UserProfile::default(); let c = GenerationContext::new(); let mut r = seeded_rng(42); g.generate(&p, &c, &mut r).unwrap().validate_plausibility().unwrap(); }
    #[test]
    fn test_100_thumbnails() { let g = ThumbnailGenerator::new(); let p = UserProfile::default(); let c = GenerationContext::new(); for s in 0..100 { let mut r = seeded_rng(s); g.generate(&p, &c, &mut r).unwrap().validate_plausibility().unwrap(); } }
}
