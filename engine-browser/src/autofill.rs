//! Form autofill data generation — names, addresses, emails.

use engine_core::error::Result;
use engine_core::profile::UserProfile;
use engine_core::traits::{DataCategory, DataGenerator, GenerationContext};
use rand::{CryptoRng, RngCore};

#[derive(Debug, Clone, serde::Serialize)]
pub struct AutofillEntry {
    pub meta: engine_core::traits::ArtifactMetadata,
    pub field_name: String,
    pub field_value: String,
    pub form_url: String,
    pub last_used: chrono::DateTime<chrono::Utc>,
    pub use_count: u32,
}

impl engine_core::traits::Artifact for AutofillEntry {
    fn metadata(&self) -> &engine_core::traits::ArtifactMetadata { &self.meta }
    fn validate_plausibility(&self) -> Result<()> { self.meta.validate_timestamps() }
    fn to_bytes(&self) -> Result<Vec<u8>> { serde_json::to_vec(self).map_err(engine_core::error::EngineError::Serialization) }
}

pub struct AutofillGenerator;
impl AutofillGenerator { pub fn new() -> Self { Self } }
impl Default for AutofillGenerator { fn default() -> Self { Self::new() } }

impl DataGenerator for AutofillGenerator {
    fn generate(&self, _profile: &UserProfile, _context: &GenerationContext, _rng: &mut (impl RngCore + CryptoRng)) -> Result<Box<dyn engine_core::traits::Artifact>> {
        todo!("AutofillGenerator: will generate plausible form autofill entries")
    }
    fn category(&self) -> DataCategory { DataCategory::BrowserActivity }
}
