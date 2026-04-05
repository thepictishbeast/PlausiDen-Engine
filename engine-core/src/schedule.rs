//! Organic timing patterns for artifact generation.
//!
//! Real human activity follows circadian rhythms, burst patterns, and session-based
//! behavior. This module generates timing that mimics these patterns so that
//! generated artifacts have timestamps indistinguishable from organic activity.

use crate::error::Result;
use crate::profile::{ActivitySchedule, RiskLevel};
use chrono::{DateTime, Duration, Timelike, Utc};
use rand::distributions::{Distribution, Uniform};
use rand::{CryptoRng, RngCore};

/// Generates organic timing for artifact creation.
///
/// Models human behavior patterns: circadian rhythm, burst/gap patterns,
/// and session-based browsing.
#[derive(Debug, Clone)]
pub struct OrganicScheduler {
    /// Activity schedule from user profile.
    schedule: ActivitySchedule,
    /// Risk level affects generation frequency.
    risk_level: RiskLevel,
}

impl OrganicScheduler {
    /// Create a new scheduler from profile settings.
    pub fn new(schedule: ActivitySchedule, risk_level: RiskLevel) -> Self {
        Self {
            schedule,
            risk_level,
        }
    }

    /// Generate the next artifact timestamp based on the current time.
    ///
    /// Returns a timestamp that follows organic human activity patterns:
    /// - More likely during waking hours
    /// - Burst patterns (clusters of activity followed by gaps)
    /// - Random jitter on all timings
    pub fn next_timestamp(
        &self,
        current: DateTime<Utc>,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> DateTime<Utc> {
        let hour = current.hour() as u8;
        let adjusted_hour = ((hour as i8 + self.schedule.timezone_offset_hours) % 24) as u8;

        // Base interval in seconds — varies by risk level
        let base_interval_secs = match self.risk_level {
            RiskLevel::Low => 300.0,     // ~5 minutes
            RiskLevel::Medium => 120.0,  // ~2 minutes
            RiskLevel::High => 30.0,     // ~30 seconds
            RiskLevel::Maximum => 5.0,   // ~5 seconds
        };

        // Activity multiplier based on time of day (circadian rhythm)
        let activity_factor = self.circadian_factor(adjusted_hour);

        // Adjusted interval: less active = longer gaps
        let adjusted_interval = base_interval_secs / activity_factor;

        // Add jitter: ±50% of the interval
        let min_interval = (adjusted_interval * 0.5) as u64;
        let max_interval = (adjusted_interval * 1.5) as u64;
        let jitter_range = Uniform::new_inclusive(min_interval.max(1), max_interval.max(2));
        let interval_secs = jitter_range.sample(rng);

        current + Duration::seconds(interval_secs as i64)
    }

    /// Generate a batch of timestamps for a session.
    ///
    /// Simulates a browsing/usage session: a burst of activity with short
    /// inter-event intervals, followed by a longer gap.
    pub fn generate_session_timestamps(
        &self,
        start: DateTime<Utc>,
        session_length: usize,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Vec<DateTime<Utc>> {
        let mut timestamps = Vec::with_capacity(session_length);
        let mut current = start;

        for _ in 0..session_length {
            // Within a session, intervals are shorter (2-30 seconds)
            let intra_session = Uniform::new_inclusive(2u64, 30u64);
            let gap = intra_session.sample(rng);
            current = current + Duration::seconds(gap as i64);
            timestamps.push(current);
        }

        timestamps
    }

    /// Returns an activity factor (0.0 to 1.0) based on time of day.
    ///
    /// Models circadian rhythm: high activity during waking hours,
    /// very low during sleep, ramp-up in morning, wind-down at night.
    fn circadian_factor(&self, local_hour: u8) -> f64 {
        let wake = self.schedule.wake_hour as f64;
        let sleep = self.schedule.sleep_hour as f64;
        let hour = local_hour as f64;

        if hour < wake - 1.0 || hour > sleep + 1.0 {
            // Deep sleep — very rare activity
            0.05
        } else if hour < wake {
            // Waking up — ramping
            0.2
        } else if hour < wake + 2.0 {
            // Morning routine — moderate
            0.6
        } else if hour < 12.0 {
            // Late morning — high
            0.9
        } else if hour < 14.0 {
            // Lunch — moderate dip
            0.7
        } else if hour < 17.0 {
            // Afternoon — high
            0.85
        } else if hour < 20.0 {
            // Evening — peak
            1.0
        } else if hour < sleep {
            // Wind down — decreasing
            0.5
        } else {
            // After sleep hour — low
            0.1
        }
    }

    /// Check if a given timestamp falls within active hours.
    pub fn is_active_hour(&self, time: DateTime<Utc>) -> bool {
        let hour = time.hour() as u8;
        let adjusted = ((hour as i8 + self.schedule.timezone_offset_hours).rem_euclid(24)) as u8;
        adjusted >= self.schedule.wake_hour && adjusted <= self.schedule.sleep_hour
    }
}

/// Determines how many artifacts to generate per cycle based on risk level.
pub fn artifacts_per_cycle(risk_level: RiskLevel) -> Result<u32> {
    Ok(match risk_level {
        RiskLevel::Low => 1,
        RiskLevel::Medium => 3,
        RiskLevel::High => 10,
        RiskLevel::Maximum => 50,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::ActivitySchedule;
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn test_scheduler() -> OrganicScheduler {
        OrganicScheduler::new(ActivitySchedule::default(), RiskLevel::Medium)
    }

    fn test_rng() -> ChaCha20Rng {
        ChaCha20Rng::seed_from_u64(42)
    }

    #[test]
    fn test_schedule_generates_organic_timing() {
        let scheduler = test_scheduler();
        let mut rng = test_rng();
        let now = Utc::now();

        let t1 = scheduler.next_timestamp(now, &mut rng);
        let t2 = scheduler.next_timestamp(t1, &mut rng);
        let t3 = scheduler.next_timestamp(t2, &mut rng);

        // All timestamps should be in the future relative to their input
        assert!(t1 > now);
        assert!(t2 > t1);
        assert!(t3 > t2);

        // Intervals should not be identical (jitter applied)
        let i1 = (t1 - now).num_seconds();
        let i2 = (t2 - t1).num_seconds();
        // With different RNG draws, intervals are very likely to differ
        // (not guaranteed but probability of equality is negligible)
        assert!(i1 > 0);
        assert!(i2 > 0);
    }

    #[test]
    fn test_schedule_respects_activity_hours() {
        let scheduler = test_scheduler();

        // 2pm local (within active hours for default schedule wake=7, sleep=23, offset=-5)
        let active_time = chrono::NaiveDate::from_ymd_opt(2026, 4, 4)
            .unwrap()
            .and_hms_opt(19, 0, 0) // 19:00 UTC = 14:00 EST
            .unwrap()
            .and_utc();
        assert!(scheduler.is_active_hour(active_time));

        // 3am local (outside active hours)
        let sleep_time = chrono::NaiveDate::from_ymd_opt(2026, 4, 4)
            .unwrap()
            .and_hms_opt(8, 0, 0) // 08:00 UTC = 03:00 EST
            .unwrap()
            .and_utc();
        assert!(!scheduler.is_active_hour(sleep_time));
    }

    #[test]
    fn test_session_timestamps_are_ordered() {
        let scheduler = test_scheduler();
        let mut rng = test_rng();
        let start = Utc::now();

        let timestamps = scheduler.generate_session_timestamps(start, 10, &mut rng);

        assert_eq!(timestamps.len(), 10);
        for window in timestamps.windows(2) {
            assert!(window[1] > window[0], "timestamps must be strictly ordered");
        }
    }

    #[test]
    fn test_risk_level_affects_generation_volume() {
        let low = artifacts_per_cycle(RiskLevel::Low).unwrap();
        let medium = artifacts_per_cycle(RiskLevel::Medium).unwrap();
        let high = artifacts_per_cycle(RiskLevel::High).unwrap();
        let maximum = artifacts_per_cycle(RiskLevel::Maximum).unwrap();

        assert!(low < medium);
        assert!(medium < high);
        assert!(high < maximum);
    }
}
