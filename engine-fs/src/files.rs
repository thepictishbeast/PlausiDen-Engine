//! Document, image, download, and temp file generation.
//!
//! Generates realistic file metadata — names, paths, sizes, timestamps,
//! MIME types — matching the user's profile.

use chrono::{DateTime, Duration, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::{OccupationCategory, UserProfile};
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext,
};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct FileEntry {
    pub meta: ArtifactMetadata,
    pub filename: String,
    pub path: String,
    pub mime_type: String,
    pub file_size: u64,
    pub created: DateTime<Utc>,
    pub modified: DateTime<Utc>,
    pub accessed: DateTime<Utc>,
}

impl Artifact for FileEntry {
    fn metadata(&self) -> &ArtifactMetadata { &self.meta }
    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.filename.is_empty() {
            return Err(EngineError::ImplausibleArtifact { reason: "empty filename".into() });
        }
        if self.file_size == 0 {
            return Err(EngineError::ImplausibleArtifact { reason: "zero-byte file".into() });
        }
        if self.modified < self.created {
            return Err(EngineError::ImplausibleArtifact { reason: "modified before created".into() });
        }
        Ok(())
    }
    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

struct FileTpl { name: &'static str, ext: &'static str, mime: &'static str, min: u64, max: u64, dir: &'static str }

fn templates(profile: &UserProfile) -> Vec<FileTpl> {
    let mut t = vec![
        FileTpl { name: "IMG_", ext: "jpg", mime: "image/jpeg", min: 500_000, max: 8_000_000, dir: "Pictures" },
        FileTpl { name: "Screenshot_", ext: "png", mime: "image/png", min: 100_000, max: 4_000_000, dir: "Pictures" },
        FileTpl { name: "download_", ext: "pdf", mime: "application/pdf", min: 50_000, max: 5_000_000, dir: "Downloads" },
        FileTpl { name: "notes_", ext: "txt", mime: "text/plain", min: 100, max: 50_000, dir: "Documents" },
    ];
    match profile.demographic.occupation {
        OccupationCategory::Journalist => { t.push(FileTpl { name: "article_", ext: "docx", mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", min: 20_000, max: 500_000, dir: "Documents" }); t.push(FileTpl { name: "interview_", ext: "mp3", mime: "audio/mpeg", min: 5_000_000, max: 50_000_000, dir: "Documents/Interviews" }); }
        OccupationCategory::TechWorker => { t.push(FileTpl { name: "main", ext: "rs", mime: "text/x-rust", min: 500, max: 50_000, dir: "Projects" }); t.push(FileTpl { name: "config", ext: "json", mime: "application/json", min: 100, max: 10_000, dir: "Projects" }); }
        OccupationCategory::Student => { t.push(FileTpl { name: "essay_", ext: "docx", mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", min: 15_000, max: 200_000, dir: "Documents/School" }); }
        _ => { t.push(FileTpl { name: "document_", ext: "docx", mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document", min: 10_000, max: 500_000, dir: "Documents" }); }
    }
    t
}

pub struct FileGenerator;
impl FileGenerator { pub fn new() -> Self { Self } }
impl Default for FileGenerator { fn default() -> Self { Self::new() } }

impl DataGenerator for FileGenerator {
    fn generate(&self, profile: &UserProfile, context: &GenerationContext, rng: &mut (impl RngCore + CryptoRng)) -> Result<Box<dyn Artifact>> {
        let tmpls = templates(profile);
        let tpl = tmpls.choose(rng).ok_or_else(|| EngineError::InvalidContext("no templates".into()))?;
        let suffix = Uniform::new_inclusive(1000u32, 9999).sample(rng);
        let filename = if tpl.ext.is_empty() { tpl.name.to_string() } else { format!("{}{}_{}.{}", tpl.name, context.now.format("%Y%m%d"), suffix, tpl.ext) };
        let path = format!("/home/user/{}/{}", tpl.dir, filename);
        let file_size = Uniform::new_inclusive(tpl.min, tpl.max).sample(rng);
        let days_ago = Uniform::new_inclusive(1i64, 365).sample(rng);
        let created = context.now - Duration::days(days_ago);
        let mod_offset = Uniform::new_inclusive(0i64, days_ago).sample(rng);
        let modified = created + Duration::days(mod_offset);
        let accessed = context.now - Duration::days(Uniform::new_inclusive(0i64, 7).sample(rng));
        let meta = ArtifactMetadata::new(DataCategory::FileSystem, created, modified, file_size)?;
        let entry = FileEntry { meta, filename, path, mime_type: tpl.mime.to_string(), file_size, created, modified, accessed };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }
    fn category(&self) -> DataCategory { DataCategory::FileSystem }
    fn forensic_weight(&self) -> u32 { 95 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_file() {
        let g = FileGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);
        let a = g.generate(&p, &c, &mut r).unwrap();
        a.validate_plausibility().unwrap();
        let b = a.to_bytes().unwrap();
        let e: FileEntry = serde_json::from_slice(&b).unwrap();
        assert!(!e.filename.is_empty());
        assert!(e.file_size > 0);
    }

    #[test]
    fn test_journalist_files() {
        let g = FileGenerator::new();
        let mut p = UserProfile::default();
        p.demographic.occupation = OccupationCategory::Journalist;
        let c = GenerationContext::new();
        let mut found = false;
        for s in 0..200 { let mut r = seeded_rng(s); let a = g.generate(&p, &c, &mut r).unwrap(); let b = a.to_bytes().unwrap(); let e: FileEntry = serde_json::from_slice(&b).unwrap(); if e.mime_type.contains("audio") { found = true; break; } }
        assert!(found, "journalist should get audio files");
    }

    #[test]
    fn test_500_files_valid() {
        let g = FileGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..500 { let mut r = seeded_rng(s); g.generate(&p, &c, &mut r).unwrap().validate_plausibility().unwrap(); }
    }

    #[test]
    fn test_timestamps_consistent() {
        let g = FileGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..100 { let mut r = seeded_rng(s); let a = g.generate(&p, &c, &mut r).unwrap(); let b = a.to_bytes().unwrap(); let e: FileEntry = serde_json::from_slice(&b).unwrap(); assert!(e.modified >= e.created); }
    }
}
