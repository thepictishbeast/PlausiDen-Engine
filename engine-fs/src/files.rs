//! Document, image, download, and temp file generation.
use engine_core::error::Result;
use engine_core::profile::UserProfile;
use engine_core::traits::{DataCategory, DataGenerator, GenerationContext};
use rand::{CryptoRng, RngCore};

pub struct FileGenerator;
impl FileGenerator { pub fn new() -> Self { Self } }
impl DataGenerator for FileGenerator {
    fn generate(&self, _p: &UserProfile, _c: &GenerationContext, _r: &mut (impl RngCore + CryptoRng)) -> Result<Box<dyn engine_core::traits::Artifact>> { todo!() }
    fn category(&self) -> DataCategory { DataCategory::FileSystem }
}
