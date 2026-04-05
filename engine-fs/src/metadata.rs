//! Extended file metadata — xattrs, permissions, ownership.

use chrono::{DateTime, Duration, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct MetadataEntry {
    pub meta: ArtifactMetadata,
    pub path: String,
    pub permissions: String,
    pub owner: String,
    pub group: String,
    pub inode: u64,
    pub hard_links: u32,
    pub xattrs: Vec<(String, String)>,
}

impl Artifact for MetadataEntry {
    fn metadata(&self) -> &ArtifactMetadata { &self.meta }
    fn validate_plausibility(&self) -> Result<()> { self.meta.validate_timestamps() }
    fn to_bytes(&self) -> Result<Vec<u8>> { serde_json::to_vec(self).map_err(EngineError::Serialization) }
}

pub struct MetadataGenerator;
impl MetadataGenerator { pub fn new() -> Self { Self } }
impl Default for MetadataGenerator { fn default() -> Self { Self::new() } }

impl DataGenerator for MetadataGenerator {
    fn generate(&self, _profile: &UserProfile, context: &GenerationContext, rng: &mut (impl RngCore + CryptoRng)) -> Result<Box<dyn Artifact>> {
        let paths = ["/home/user/doc.txt", "/home/user/.config/app.conf", "/usr/bin/tool", "/var/log/app.log"];
        let path = paths.choose(rng).unwrap();
        let perms = ["-rw-r--r--", "-rwxr-xr-x", "-rw-------", "-rw-rw-r--"].choose(rng).unwrap();
        let owners = ["user", "root", "www-data"];
        let owner = owners.choose(rng).unwrap();
        let days_ago = Uniform::new_inclusive(1i64, 365).sample(rng);
        let ts = context.now - Duration::days(days_ago);
        let meta = ArtifactMetadata::new(DataCategory::FileSystem, ts, ts, 256)?;
        let entry = MetadataEntry {
            meta, path: path.to_string(), permissions: perms.to_string(),
            owner: owner.to_string(), group: owner.to_string(),
            inode: Uniform::new_inclusive(100000u64, 9999999).sample(rng),
            hard_links: 1, xattrs: vec![],
        };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }
    fn category(&self) -> DataCategory { DataCategory::FileSystem }
    fn forensic_weight(&self) -> u32 { 45 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;
    #[test]
    fn test_metadata() { let g = MetadataGenerator::new(); let p = UserProfile::default(); let c = GenerationContext::new(); let mut r = seeded_rng(42); g.generate(&p, &c, &mut r).unwrap().validate_plausibility().unwrap(); }
}
