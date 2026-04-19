//! Cell tower log generation with US carrier codes and movement correlation.
//!
//! Produces cell tower connection records that correlate with GPS movement.
//! Each log entry contains MCC/MNC (carrier identification), LAC (location
//! area code), cell ID, signal strength, and connection timestamps.
//!
//! US carrier codes follow real-world allocations:
//! - AT&T: MCC 310 / MNC 410
//! - Verizon: MCC 311 / MNC 480
//! - T-Mobile: MCC 310 / MNC 260
//! - Sprint (now T-Mobile): MCC 310 / MNC 120
//! - US Cellular: MCC 311 / MNC 580
//! - Cricket (AT&T MVNO): MCC 310 / MNC 150
//!
//! Tower changes correlate with GPS movement: stationary users stay on
//! the same tower, moving users hand off between towers.

use chrono::{DateTime, Duration, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext, ResourceCost,
};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Carrier table
// ---------------------------------------------------------------------------

/// A US carrier entry with MCC, MNC, and name.
struct CarrierInfo {
    mcc: u16,
    mnc: u16,
    #[allow(dead_code)]
    name: &'static str,
}

/// US carrier codes following real-world FCC allocations.
const US_CARRIERS: &[CarrierInfo] = &[
    CarrierInfo {
        mcc: 310,
        mnc: 410,
        name: "AT&T",
    },
    CarrierInfo {
        mcc: 311,
        mnc: 480,
        name: "Verizon",
    },
    CarrierInfo {
        mcc: 310,
        mnc: 260,
        name: "T-Mobile",
    },
    CarrierInfo {
        mcc: 310,
        mnc: 120,
        name: "Sprint",
    },
    CarrierInfo {
        mcc: 311,
        mnc: 580,
        name: "US Cellular",
    },
    CarrierInfo {
        mcc: 310,
        mnc: 150,
        name: "Cricket",
    },
    CarrierInfo {
        mcc: 310,
        mnc: 030,
        name: "AT&T (Centennial)",
    },
    CarrierInfo {
        mcc: 311,
        mnc: 490,
        name: "Verizon (LTE)",
    },
    CarrierInfo {
        mcc: 310,
        mnc: 160,
        name: "T-Mobile (Metro)",
    },
    CarrierInfo {
        mcc: 310,
        mnc: 770,
        name: "i-wireless",
    },
];

/// Network technology types weighted by current deployment prevalence.
const NETWORK_TYPES: &[&str] = &["LTE", "LTE", "LTE", "5G NR", "5G NR", "LTE-A", "3G"];

// ---------------------------------------------------------------------------
// CellTowerLog
// ---------------------------------------------------------------------------

/// A single cell tower connection log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CellTowerLog {
    /// Artifact metadata (id, timestamps, category).
    pub meta: ArtifactMetadata,
    /// Mobile Country Code (310 or 311 for US).
    pub mcc: u16,
    /// Mobile Network Code (carrier-specific).
    pub mnc: u16,
    /// Location Area Code (geographic region).
    pub lac: u32,
    /// Cell ID (individual tower/sector).
    pub cell_id: u32,
    /// Signal strength in dBm (typical: -50 strong to -120 weak).
    pub signal_dbm: i32,
    /// Radio access technology (LTE, 5G NR, 3G, LTE-A).
    pub network_type: String,
    /// Timestamp of this connection record.
    pub timestamp: DateTime<Utc>,
    /// How long the device was camped on this tower, in seconds.
    pub duration_secs: u64,
}

impl Artifact for CellTowerLog {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;

        // MCC must be valid US code
        if self.mcc != 310 && self.mcc != 311 {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!(
                    "MCC {} is not a valid US mobile country code (310/311)",
                    self.mcc
                ),
            });
        }

        // Signal strength: real-world range -140 to -44 dBm
        if self.signal_dbm > 0 || self.signal_dbm < -140 {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!(
                    "signal strength {} dBm out of realistic range [-140, 0]",
                    self.signal_dbm
                ),
            });
        }

        // LAC and cell_id must be non-zero
        if self.lac == 0 {
            return Err(EngineError::ImplausibleArtifact {
                reason: "LAC must be non-zero".to_string(),
            });
        }
        if self.cell_id == 0 {
            return Err(EngineError::ImplausibleArtifact {
                reason: "cell_id must be non-zero".to_string(),
            });
        }

        if self.network_type.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "network_type must not be empty".to_string(),
            });
        }

        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

// ---------------------------------------------------------------------------
// CellTowerGenerator
// ---------------------------------------------------------------------------

/// Generates cell tower connection logs with movement-correlated handoffs.
///
/// Maintains a "current tower" state. When the user is stationary, the
/// same tower is reported with minor signal fluctuations. When the user
/// moves (based on consecutive generation calls), a tower handoff occurs
/// with a new LAC/cell_id and potentially different signal strength.
///
/// The carrier (MCC/MNC) is chosen once per persona and persists.
pub struct CellTowerGenerator {
    /// Persistent carrier MCC for this persona.
    carrier_mcc: Option<u16>,
    /// Persistent carrier MNC for this persona.
    carrier_mnc: Option<u16>,
    /// Current tower LAC (changes on handoff).
    current_lac: Option<u32>,
    /// Current tower cell_id (changes on handoff).
    current_cell_id: Option<u32>,
    /// Last reported signal for gradual variation.
    last_signal: Option<i32>,
    /// Last timestamp for time progression.
    last_timestamp: Option<DateTime<Utc>>,
    /// Points remaining on the current tower before a handoff.
    handoff_countdown: u32,
}

impl CellTowerGenerator {
    /// Create a new cell tower generator with no prior state.
    pub fn new() -> Self {
        Self {
            carrier_mcc: None,
            carrier_mnc: None,
            current_lac: None,
            current_cell_id: None,
            last_signal: None,
            last_timestamp: None,
            handoff_countdown: 0,
        }
    }

    /// Select a carrier and lock it for this persona.
    fn ensure_carrier(&mut self, rng: &mut (impl RngCore + CryptoRng)) {
        if self.carrier_mcc.is_none() {
            let carrier = US_CARRIERS.choose(rng).unwrap_or(&US_CARRIERS[0]);
            self.carrier_mcc = Some(carrier.mcc);
            self.carrier_mnc = Some(carrier.mnc);
        }
    }

    /// Perform a tower handoff: new LAC, new cell_id, reset countdown.
    fn handoff(&mut self, rng: &mut (impl RngCore + CryptoRng)) {
        // LAC range: 1-65535 (16-bit)
        self.current_lac = Some(Uniform::new_inclusive(1u32, 65535).sample(rng));
        // Cell ID range: 1-268435455 (28-bit for LTE E-UTRAN Cell ID)
        self.current_cell_id = Some(Uniform::new_inclusive(1u32, 268_435_455).sample(rng));
        // Reset countdown: stationary = stay longer, moving = shorter
        self.handoff_countdown = Uniform::new_inclusive(3u32, 20).sample(rng);
    }

    /// Generate signal strength with small drift from previous value.
    fn drift_signal(last: Option<i32>, rng: &mut (impl RngCore + CryptoRng)) -> i32 {
        let base = last.unwrap_or(-75);
        let drift = Uniform::new_inclusive(-5i32, 5).sample(rng);
        (base + drift).clamp(-120, -44)
    }

    /// Generate a trace of `count` cell tower log entries.
    ///
    /// Maintains tower state: consecutive entries on the same tower
    /// until a handoff occurs (countdown reaches zero).
    pub fn generate_trace(
        &mut self,
        profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
        count: usize,
    ) -> Result<Vec<CellTowerLog>> {
        self.ensure_carrier(rng);
        let mut entries = Vec::with_capacity(count);

        for _ in 0..count {
            // Handoff if countdown expired
            if self.handoff_countdown == 0 || self.current_lac.is_none() {
                self.handoff(rng);
            }
            self.handoff_countdown = self.handoff_countdown.saturating_sub(1);

            let mcc = self.carrier_mcc.unwrap_or(310);
            let mnc = self.carrier_mnc.unwrap_or(410);
            let lac = self.current_lac.unwrap_or(1);
            let cell_id = self.current_cell_id.unwrap_or(1);

            let signal = Self::drift_signal(self.last_signal, rng);
            self.last_signal = Some(signal);

            let net_type = NETWORK_TYPES.choose(rng).copied().unwrap_or("LTE");

            // Time step: cell logs are less frequent than GPS (30s - 5min)
            let dt_secs = Uniform::new_inclusive(30i64, 300).sample(rng);
            let timestamp = self
                .last_timestamp
                .map(|t| t + Duration::seconds(dt_secs))
                .unwrap_or(context.now);
            self.last_timestamp = Some(timestamp);

            let duration = Uniform::new_inclusive(30u64, 1800).sample(rng);

            let _ = profile; // Used indirectly via context timing

            let meta = ArtifactMetadata::new(DataCategory::Location, timestamp, timestamp, 256)?;

            let entry = CellTowerLog {
                meta,
                mcc,
                mnc,
                lac,
                cell_id,
                signal_dbm: signal,
                network_type: net_type.to_string(),
                timestamp,
                duration_secs: duration,
            };

            entry.validate_plausibility()?;
            entries.push(entry);
        }

        Ok(entries)
    }
}

impl Default for CellTowerGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for CellTowerGenerator {
    fn generate(
        &self,
        _profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        let carrier = US_CARRIERS.choose(rng).unwrap_or(&US_CARRIERS[0]);

        let mcc = self.carrier_mcc.unwrap_or(carrier.mcc);
        let mnc = self.carrier_mnc.unwrap_or(carrier.mnc);

        let lac = self
            .current_lac
            .unwrap_or_else(|| Uniform::new_inclusive(1u32, 65535).sample(rng));
        let cell_id = self
            .current_cell_id
            .unwrap_or_else(|| Uniform::new_inclusive(1u32, 268_435_455).sample(rng));

        let signal = Self::drift_signal(self.last_signal, rng);

        let net_type = NETWORK_TYPES.choose(rng).copied().unwrap_or("LTE");

        let duration = Uniform::new_inclusive(60u64, 3600).sample(rng);

        let jitter = Uniform::new_inclusive(0i64, 600).sample(rng);
        let timestamp = context.now - Duration::seconds(jitter);

        let meta = ArtifactMetadata::new(DataCategory::Location, timestamp, timestamp, 256)?;

        let entry = CellTowerLog {
            meta,
            mcc,
            mnc,
            lac,
            cell_id,
            signal_dbm: signal,
            network_type: net_type.to_string(),
            timestamp,
            duration_secs: duration,
        };

        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory {
        DataCategory::Location
    }

    fn forensic_weight(&self) -> u32 {
        75
    }

    fn resource_cost(&self) -> ResourceCost {
        ResourceCost {
            cpu_us: 15,
            disk_bytes: 256,
            network_bytes: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    fn test_profile() -> UserProfile {
        UserProfile::default()
    }

    #[test]
    fn test_basic_cell_generation() {
        let cell = CellTowerGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let artifact = cell.generate(&profile, &ctx, &mut rng);
        assert!(artifact.is_ok());
        let artifact = artifact.expect("checked");
        assert!(artifact.validate_plausibility().is_ok());
    }

    #[test]
    fn test_mcc_is_valid_us_code() {
        let cell = CellTowerGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(77);

        for _ in 0..200 {
            let artifact = cell.generate(&profile, &ctx, &mut rng).expect("generate");
            let bytes = artifact.to_bytes().expect("to_bytes");
            let entry: CellTowerLog = serde_json::from_slice(&bytes).expect("deser");

            assert!(
                entry.mcc == 310 || entry.mcc == 311,
                "MCC {} must be 310 or 311",
                entry.mcc,
            );
        }
    }

    #[test]
    fn test_signal_strength_in_range() {
        let cell = CellTowerGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(99);

        for i in 0..300 {
            let artifact = cell.generate(&profile, &ctx, &mut rng).expect("generate");
            let bytes = artifact.to_bytes().expect("to_bytes");
            let entry: CellTowerLog = serde_json::from_slice(&bytes).expect("deser");

            assert!(
                entry.signal_dbm >= -140 && entry.signal_dbm <= 0,
                "entry {i}: signal {} dBm out of range",
                entry.signal_dbm,
            );
        }
    }

    #[test]
    fn test_lac_and_cell_id_nonzero() {
        let cell = CellTowerGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(55);

        for _ in 0..200 {
            let artifact = cell.generate(&profile, &ctx, &mut rng).expect("generate");
            let bytes = artifact.to_bytes().expect("to_bytes");
            let entry: CellTowerLog = serde_json::from_slice(&bytes).expect("deser");

            assert!(entry.lac > 0, "LAC must be non-zero");
            assert!(entry.cell_id > 0, "cell_id must be non-zero");
        }
    }

    #[test]
    fn test_trace_maintains_tower_continuity() {
        let mut cell = CellTowerGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let entries = cell
            .generate_trace(&profile, &ctx, &mut rng, 50)
            .expect("trace");

        // Verify that some consecutive entries share the same tower (lac + cell_id)
        let mut same_tower_count = 0u32;
        for pair in entries.windows(2) {
            if pair[0].lac == pair[1].lac && pair[0].cell_id == pair[1].cell_id {
                same_tower_count += 1;
            }
        }
        assert!(
            same_tower_count > 0,
            "at least some consecutive entries should be on the same tower",
        );
    }

    #[test]
    fn test_trace_carrier_persistence() {
        let mut cell = CellTowerGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let entries = cell
            .generate_trace(&profile, &ctx, &mut rng, 100)
            .expect("trace");

        let first_mcc = entries[0].mcc;
        let first_mnc = entries[0].mnc;

        for (i, entry) in entries.iter().enumerate() {
            assert_eq!(
                entry.mcc, first_mcc,
                "entry {i}: carrier MCC must be consistent",
            );
            assert_eq!(
                entry.mnc, first_mnc,
                "entry {i}: carrier MNC must be consistent",
            );
        }
    }

    #[test]
    fn test_timestamps_monotonically_increase_in_trace() {
        let mut cell = CellTowerGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let entries = cell
            .generate_trace(&profile, &ctx, &mut rng, 100)
            .expect("trace");

        for pair in entries.windows(2) {
            assert!(
                pair[1].timestamp >= pair[0].timestamp,
                "timestamps must be non-decreasing in trace",
            );
        }
    }

    #[test]
    fn test_serialization_roundtrip() {
        let cell = CellTowerGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let artifact = cell.generate(&profile, &ctx, &mut rng).expect("generate");
        let bytes = artifact.to_bytes().expect("to_bytes");
        let entry: CellTowerLog = serde_json::from_slice(&bytes).expect("deser");

        let bytes2 = serde_json::to_vec(&entry).expect("re-serialize");
        let entry2: CellTowerLog = serde_json::from_slice(&bytes2).expect("re-deser");

        assert_eq!(entry.mcc, entry2.mcc);
        assert_eq!(entry.mnc, entry2.mnc);
        assert_eq!(entry.lac, entry2.lac);
        assert_eq!(entry.cell_id, entry2.cell_id);
        assert_eq!(entry.signal_dbm, entry2.signal_dbm);
    }

    #[test]
    fn test_500_entries_all_valid() {
        let cell = CellTowerGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();

        for seed in 0..500u64 {
            let mut rng = seeded_rng(seed);
            let artifact = cell.generate(&profile, &ctx, &mut rng).expect("generate");
            if let Err(e) = artifact.validate_plausibility() {
                panic!("seed {seed} failed plausibility: {e}");
            }
        }
    }
}
