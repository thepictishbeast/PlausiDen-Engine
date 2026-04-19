//! Call log generation with circadian timing and realistic durations.
//!
//! Produces call history entries that follow human activity patterns: calls
//! cluster during waking hours, missed calls are more common during sleep
//! and work hours, and durations match organic distributions.

use chrono::{DateTime, Duration, Timelike, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext, ResourceCost,
};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Phone number pool for generating realistic call logs.
const PHONE_POOL: &[&str] = &[
    "(202) 555-0147",
    "(312) 555-0198",
    "(415) 555-0123",
    "(718) 555-0176",
    "(213) 555-0134",
    "(305) 555-0189",
    "(404) 555-0156",
    "(617) 555-0112",
    "(503) 555-0167",
    "(512) 555-0143",
    "(206) 555-0178",
    "(303) 555-0121",
    "(614) 555-0195",
    "(704) 555-0132",
    "(919) 555-0187",
    "(602) 555-0154",
    "(480) 555-0116",
    "(816) 555-0169",
    "(314) 555-0141",
    "(612) 555-0193",
    "(913) 555-0128",
    "(408) 555-0185",
    "(510) 555-0152",
    "(916) 555-0117",
    "(720) 555-0163",
    "(469) 555-0139",
    "(972) 555-0191",
    "(678) 555-0126",
    "(770) 555-0183",
    "(407) 555-0148",
    "(813) 555-0114",
    "(757) 555-0165",
];

/// Direction of a phone call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallDirection {
    /// User placed the call.
    Outgoing,
    /// User received the call.
    Incoming,
    /// Call arrived but was not answered.
    Missed,
}

/// A single call log entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallEntry {
    /// Artifact metadata (timestamps, category, size).
    pub meta: ArtifactMetadata,
    /// Phone number of the other party.
    pub phone_number: String,
    /// Direction of the call.
    pub direction: CallDirection,
    /// Duration in seconds (0 for missed calls).
    pub duration_secs: u32,
    /// When the call started.
    pub call_time: DateTime<Utc>,
}

impl Artifact for CallEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;

        if self.phone_number.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "call entry has empty phone number".to_string(),
            });
        }

        // Missed calls must have zero duration
        if self.direction == CallDirection::Missed && self.duration_secs != 0 {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!("missed call has non-zero duration: {}s", self.duration_secs),
            });
        }

        // Connected calls should have some duration
        if self.direction != CallDirection::Missed && self.duration_secs == 0 {
            return Err(EngineError::ImplausibleArtifact {
                reason: "connected call has zero duration".to_string(),
            });
        }

        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

/// Generates call log entries with circadian timing patterns.
pub struct CallGenerator;

impl CallGenerator {
    /// Create a new call generator.
    pub fn new() -> Self {
        Self
    }

    /// Choose call direction, with missed calls more likely during sleep hours.
    fn choose_direction(
        hour: u32,
        profile: &UserProfile,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> CallDirection {
        let is_sleep = if profile.activity_schedule.wake_hour < profile.activity_schedule.sleep_hour
        {
            hour < profile.activity_schedule.wake_hour as u32
                || hour >= profile.activity_schedule.sleep_hour as u32
        } else {
            hour < profile.activity_schedule.wake_hour as u32
                && hour >= profile.activity_schedule.sleep_hour as u32
        };

        let roll = Uniform::new_inclusive(0u32, 99).sample(rng);

        if is_sleep {
            // During sleep: higher missed-call rate
            match roll {
                0..=59 => CallDirection::Missed,
                60..=79 => CallDirection::Incoming,
                _ => CallDirection::Outgoing,
            }
        } else {
            // Waking hours: mostly incoming/outgoing
            match roll {
                0..=39 => CallDirection::Incoming,
                40..=79 => CallDirection::Outgoing,
                _ => CallDirection::Missed,
            }
        }
    }

    /// Generate a call time following circadian patterns.
    ///
    /// Calls cluster during waking hours with peaks mid-morning and early evening.
    fn generate_call_time(
        context: &GenerationContext,
        profile: &UserProfile,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> DateTime<Utc> {
        // Place call within the last 30 days
        let day_offset = Uniform::new_inclusive(0i64, 29).sample(rng);
        let base = context.now - Duration::days(day_offset);

        let wake = profile.activity_schedule.wake_hour as u32;
        let sleep = profile.activity_schedule.sleep_hour as u32;

        // 85% during waking hours, 15% during sleep
        let hour = if Uniform::new_inclusive(0u32, 99).sample(rng) < 85 {
            if wake < sleep {
                Uniform::new_inclusive(wake, sleep.saturating_sub(1).max(wake)).sample(rng)
            } else {
                // Wraps midnight: e.g., wake=22, sleep=6
                let span = (24 - wake) + sleep;
                let offset = Uniform::new_inclusive(0u32, span.saturating_sub(1)).sample(rng);
                (wake + offset) % 24
            }
        } else {
            // Sleep hours
            if wake < sleep {
                let sleep_options: Vec<u32> = (0..wake).chain(sleep..24).collect();
                if sleep_options.is_empty() {
                    12 // fallback
                } else {
                    *sleep_options.choose(rng).unwrap_or(&3)
                }
            } else {
                Uniform::new_inclusive(sleep, wake.saturating_sub(1).max(sleep)).sample(rng)
            }
        };

        let minute = Uniform::new_inclusive(0u32, 59).sample(rng);
        let second = Uniform::new_inclusive(0u32, 59).sample(rng);

        base.date_naive()
            .and_hms_opt(hour, minute, second)
            .map(|ndt| DateTime::<Utc>::from_naive_utc_and_offset(ndt, Utc))
            .unwrap_or(base)
    }

    /// Generate a realistic call duration.
    fn generate_duration(direction: CallDirection, rng: &mut (impl RngCore + CryptoRng)) -> u32 {
        match direction {
            CallDirection::Missed => 0,
            _ => {
                // Most calls are short, some are long
                let roll = Uniform::new_inclusive(0u32, 99).sample(rng);
                match roll {
                    0..=40 => Uniform::new_inclusive(5u32, 120).sample(rng), // Short: 5s-2min
                    41..=75 => Uniform::new_inclusive(121u32, 600).sample(rng), // Medium: 2-10min
                    76..=92 => Uniform::new_inclusive(601u32, 1200).sample(rng), // Long: 10-20min
                    _ => Uniform::new_inclusive(1201u32, 1800).sample(rng),  // Very long: 20-30min
                }
            }
        }
    }
}

impl Default for CallGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for CallGenerator {
    fn generate(
        &self,
        profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        let phone_number = PHONE_POOL
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("empty phone pool".to_string()))?
            .to_string();

        let call_time = Self::generate_call_time(context, profile, rng);
        let hour = call_time.hour();
        let direction = Self::choose_direction(hour, profile, rng);
        let duration_secs = Self::generate_duration(direction, rng);

        let meta = ArtifactMetadata::new(
            DataCategory::Communications,
            call_time,
            call_time + Duration::seconds(duration_secs as i64),
            64,
        )?;

        let entry = CallEntry {
            meta,
            phone_number,
            direction,
            duration_secs,
            call_time,
        };

        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory {
        DataCategory::Communications
    }

    fn forensic_weight(&self) -> u32 {
        85 // Call logs are significant forensic evidence
    }

    fn resource_cost(&self) -> ResourceCost {
        ResourceCost {
            cpu_us: 20,
            disk_bytes: 128,
            network_bytes: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    fn test_profile() -> UserProfile {
        UserProfile::default()
    }

    #[test]
    fn test_basic_call_generation() {
        let call_gen = CallGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let artifact = call_gen.generate(&profile, &ctx, &mut rng).unwrap();
        artifact.validate_plausibility().unwrap();

        let bytes = artifact.to_bytes().unwrap();
        let entry: CallEntry = serde_json::from_slice(&bytes).unwrap();

        assert!(!entry.phone_number.is_empty());
        match entry.direction {
            CallDirection::Missed => assert_eq!(entry.duration_secs, 0),
            _ => assert!(entry.duration_secs >= 5),
        }
    }

    #[test]
    fn test_missed_calls_zero_duration() {
        let call_gen = CallGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let mut found_missed = false;
        for _ in 0..500 {
            let artifact = call_gen.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: CallEntry = serde_json::from_slice(&bytes).unwrap();

            if entry.direction == CallDirection::Missed {
                found_missed = true;
                assert_eq!(
                    entry.duration_secs, 0,
                    "missed call must have 0 duration, got {}",
                    entry.duration_secs
                );
            }
        }
        assert!(
            found_missed,
            "should have at least one missed call in 500 entries"
        );
    }

    #[test]
    fn test_call_duration_bounds() {
        let call_gen = CallGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(99);

        for i in 0..500 {
            let artifact = call_gen.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: CallEntry = serde_json::from_slice(&bytes).unwrap();

            match entry.direction {
                CallDirection::Missed => {
                    assert_eq!(
                        entry.duration_secs, 0,
                        "entry {i}: missed call duration != 0"
                    );
                }
                _ => {
                    assert!(
                        entry.duration_secs >= 5 && entry.duration_secs <= 1800,
                        "entry {i}: connected call duration {} out of [5, 1800]",
                        entry.duration_secs
                    );
                }
            }
        }
    }

    #[test]
    fn test_circadian_pattern() {
        let call_gen = CallGenerator::new();
        let profile = test_profile(); // wake=7, sleep=23
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let mut waking_calls = 0u32;
        let mut sleep_calls = 0u32;

        for _ in 0..1000 {
            let artifact = call_gen.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: CallEntry = serde_json::from_slice(&bytes).unwrap();

            let hour = entry.call_time.hour();
            if hour >= 7 && hour < 23 {
                waking_calls += 1;
            } else {
                sleep_calls += 1;
            }
        }

        // Should have substantially more waking-hour calls
        assert!(
            waking_calls > sleep_calls * 3,
            "waking calls ({waking_calls}) should vastly outnumber sleep calls ({sleep_calls})"
        );
    }

    #[test]
    fn test_all_directions_represented() {
        let call_gen = CallGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let mut incoming = 0u32;
        let mut outgoing = 0u32;
        let mut missed = 0u32;

        for _ in 0..500 {
            let artifact = call_gen.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: CallEntry = serde_json::from_slice(&bytes).unwrap();

            match entry.direction {
                CallDirection::Incoming => incoming += 1,
                CallDirection::Outgoing => outgoing += 1,
                CallDirection::Missed => missed += 1,
            }
        }

        assert!(incoming > 0, "should have incoming calls");
        assert!(outgoing > 0, "should have outgoing calls");
        assert!(missed > 0, "should have missed calls");
    }
}
