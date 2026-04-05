//! localStorage/IndexedDB entry generation for visited sites.

use engine_core::error::Result;
use engine_core::profile::UserProfile;
use engine_core::traits::{DataCategory, DataGenerator, GenerationContext};
use rand::{CryptoRng, RngCore};

#[derive(Debug, Clone, serde::Serialize)]
pub struct LocalStorageEntry {
    pub meta: engine_core::traits::ArtifactMetadata,
    pub origin: String,
    pub key: String,
    pub value: String,
}

impl engine_core::traits::Artifact for LocalStorageEntry {
    fn metadata(&self) -> &engine_core::traits::ArtifactMetadata { &self.meta }
    fn validate_plausibility(&self) -> Result<()> { self.meta.validate_timestamps() }
    fn to_bytes(&self) -> Result<Vec<u8>> { serde_json::to_vec(self).map_err(engine_core::error::EngineError::Serialization) }
}

pub struct LocalStorageGenerator;
impl LocalStorageGenerator { pub fn new() -> Self { Self } }
impl Default for LocalStorageGenerator { fn default() -> Self { Self::new() } }

impl DataGenerator for LocalStorageGenerator {
    fn generate(&self, _profile: &UserProfile, _context: &GenerationContext, _rng: &mut (impl RngCore + CryptoRng)) -> Result<Box<dyn engine_core::traits::Artifact>> {
        todo!("LocalStorageGenerator: will generate plausible localStorage entries")
    }
    fn category(&self) -> DataCategory { DataCategory::BrowserActivity }
}
