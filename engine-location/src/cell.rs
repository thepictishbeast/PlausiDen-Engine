//! Cell tower connection history — MCC/MNC/LAC/CID records.

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
pub struct CellEntry {
    pub meta: ArtifactMetadata,
    pub mcc: u16,       // Mobile Country Code
    pub mnc: u16,       // Mobile Network Code
    pub lac: u32,       // Location Area Code
    pub cell_id: u32,   // Cell ID
    pub signal_dbm: i32, // Signal strength
    pub network_type: String, // LTE, 5G, 3G
    pub connected_at: DateTime<Utc>,
    pub duration_secs: u64,
}

impl Artifact for CellEntry {
    fn metadata(&self) -> &ArtifactMetadata { &self.meta }
    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.signal_dbm > 0 || self.signal_dbm < -140 {
            return Err(EngineError::ImplausibleArtifact { reason: format!("signal {} out of range", self.signal_dbm) });
        }
        Ok(())
    }
    fn to_bytes(&self) -> Result<Vec<u8>> { serde_json::to_vec(self).map_err(EngineError::Serialization) }
}

const US_CARRIERS: &[(u16, u16, &str)] = &[
    (310, 260, "T-Mobile"), (310, 410, "AT&T"), (311, 480, "Verizon"),
    (310, 120, "Sprint"), (310, 150, "Cricket"), (310, 580, "US Cellular"),
];

pub struct CellGenerator;
impl CellGenerator { pub fn new() -> Self { Self } }
impl Default for CellGenerator { fn default() -> Self { Self::new() } }

impl DataGenerator for CellGenerator {
    fn generate(&self, _profile: &UserProfile, context: &GenerationContext, rng: &mut (impl RngCore + CryptoRng)) -> Result<Box<dyn Artifact>> {
        let (mcc, mnc, _carrier) = US_CARRIERS.choose(rng).unwrap();
        let lac = Uniform::new_inclusive(1u32, 65535).sample(rng);
        let cell_id = Uniform::new_inclusive(1u32, 268435455).sample(rng);
        let signal = Uniform::new_inclusive(-110i32, -50).sample(rng);
        let net_type = ["LTE", "5G NR", "3G", "LTE-A"].choose(rng).unwrap();
        let duration = Uniform::new_inclusive(60u64, 7200).sample(rng);
        let jitter = Uniform::new_inclusive(0i64, 86400).sample(rng);
        let connected_at = context.now - Duration::seconds(jitter);

        let meta = ArtifactMetadata::new(DataCategory::Location, connected_at, connected_at, 256)?;

        let entry = CellEntry {
            meta, mcc: *mcc, mnc: *mnc, lac, cell_id, signal_dbm: signal,
            network_type: net_type.to_string(), connected_at, duration_secs: duration,
        };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }
    fn category(&self) -> DataCategory { DataCategory::Location }
    fn forensic_weight(&self) -> u32 { 75 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_cell() {
        let g = CellGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);
        g.generate(&p, &c, &mut r).unwrap().validate_plausibility().unwrap();
    }

    #[test]
    fn test_300_cells_valid() {
        let g = CellGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..300 { let mut r = seeded_rng(s); g.generate(&p, &c, &mut r).unwrap().validate_plausibility().unwrap(); }
    }

    #[test]
    fn test_signal_in_range() {
        let g = CellGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..100 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: CellEntry = serde_json::from_slice(&b).unwrap();
            assert!(e.signal_dbm >= -140 && e.signal_dbm <= 0);
        }
    }
}
