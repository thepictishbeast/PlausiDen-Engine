//! Package install history generation — dpkg/apt/pacman logs.

use chrono::{DateTime, Duration, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext,
};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct InstallEntry {
    pub meta: ArtifactMetadata,
    pub package_name: String,
    pub version: String,
    pub action: InstallAction,
    pub source: String,
    pub size_bytes: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub enum InstallAction { Install, Upgrade, Remove, Autoremove }

impl Artifact for InstallEntry {
    fn metadata(&self) -> &ArtifactMetadata { &self.meta }
    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.package_name.is_empty() { return Err(EngineError::ImplausibleArtifact { reason: "empty package name".into() }); }
        Ok(())
    }
    fn to_bytes(&self) -> Result<Vec<u8>> { serde_json::to_vec(self).map_err(EngineError::Serialization) }
}

const COMMON_PACKAGES: &[(&str, &str, u64)] = &[
    ("firefox", "121.0-1", 200_000_000), ("chromium", "120.0.6099.109-1", 300_000_000),
    ("vim", "9.0.2136-1", 15_000_000), ("git", "2.43.0-1", 30_000_000),
    ("curl", "8.5.0-1", 500_000), ("openssh-client", "9.6p1-1", 2_000_000),
    ("python3", "3.12.1-1", 50_000_000), ("nodejs", "20.10.0-1", 30_000_000),
    ("docker-ce", "24.0.7-1", 50_000_000), ("nginx", "1.24.0-2", 1_500_000),
    ("htop", "3.3.0-1", 200_000), ("tmux", "3.3a-4", 500_000),
    ("build-essential", "12.10", 10_000_000), ("libssl-dev", "3.0.13-1", 8_000_000),
    ("zsh", "5.9-6", 5_000_000), ("neovim", "0.9.5-1", 20_000_000),
];

pub struct InstallGenerator;
impl InstallGenerator { pub fn new() -> Self { Self } }
impl Default for InstallGenerator { fn default() -> Self { Self::new() } }

impl DataGenerator for InstallGenerator {
    fn generate(&self, _profile: &UserProfile, context: &GenerationContext, rng: &mut (impl RngCore + CryptoRng)) -> Result<Box<dyn Artifact>> {
        let (name, version, size) = COMMON_PACKAGES.choose(rng).unwrap();
        let action = match Uniform::new_inclusive(0u32, 9).sample(rng) {
            0..=5 => InstallAction::Install,
            6..=8 => InstallAction::Upgrade,
            _ => InstallAction::Remove,
        };
        let days_ago = Uniform::new_inclusive(1i64, 365).sample(rng);
        let timestamp = context.now - Duration::days(days_ago);
        let meta = ArtifactMetadata::new(DataCategory::System, timestamp, timestamp, *size)?;

        let entry = InstallEntry {
            meta, package_name: name.to_string(), version: version.to_string(),
            action, source: "apt".into(), size_bytes: *size, timestamp,
        };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }
    fn category(&self) -> DataCategory { DataCategory::System }
    fn forensic_weight(&self) -> u32 { 50 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_install() {
        let g = InstallGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);
        g.generate(&p, &c, &mut r).unwrap().validate_plausibility().unwrap();
    }

    #[test]
    fn test_200_installs_valid() {
        let g = InstallGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..200 { let mut r = seeded_rng(s); g.generate(&p, &c, &mut r).unwrap().validate_plausibility().unwrap(); }
    }
}
