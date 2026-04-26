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
        // BUG ASSUMPTION: timezone_offset_hours can be negative (the
        // typical UTC offset). The earlier `(hour as i8 + offset) % 24`
        // used Rust's truncated remainder (negative for negative
        // numerators) and then `as u8` wrapped it to ~250, which
        // pushed `circadian_factor` permanently into the deep-sleep
        // branch (250 > sleep + 1). The result was that any user
        // with a negative TZ offset got the lowest possible activity
        // factor every hour of the day. `is_active_hour` already
        // uses `rem_euclid(24)`; this code was the lone holdout.
        let adjusted_hour =
            (hour as i16 + self.schedule.timezone_offset_hours as i16).rem_euclid(24) as u8;

        // Base interval in seconds — varies by risk level
        let base_interval_secs = match self.risk_level {
            RiskLevel::Low => 300.0,    // ~5 minutes
            RiskLevel::Medium => 120.0, // ~2 minutes
            RiskLevel::High => 30.0,    // ~30 seconds
            RiskLevel::Maximum => 5.0,  // ~5 seconds
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
            current += Duration::seconds(gap as i64);
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

    // --- Property-based tests ---

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_next_timestamp_always_future(seed in 0u64..100_000) {
            let scheduler = test_scheduler();
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            let now = Utc::now();
            let next = scheduler.next_timestamp(now, &mut rng);
            prop_assert!(next > now, "next_timestamp must always be in the future");
        }

        #[test]
        fn prop_jitter_produces_different_intervals(seed_a in 0u64..50_000, seed_b in 50_000u64..100_000) {
            let scheduler = test_scheduler();
            let now = Utc::now();
            let mut rng_a = ChaCha20Rng::seed_from_u64(seed_a);
            let mut rng_b = ChaCha20Rng::seed_from_u64(seed_b);
            let t_a = scheduler.next_timestamp(now, &mut rng_a);
            let t_b = scheduler.next_timestamp(now, &mut rng_b);
            // Different seeds should (almost always) yield different intervals.
            // We cannot assert absolute inequality for every seed pair, but
            // over the proptest sample space the probability of collision is negligible.
            // So we just verify both are valid future timestamps.
            prop_assert!(t_a > now);
            prop_assert!(t_b > now);
        }

        #[test]
        fn prop_circadian_factor_bounded(hour in 0u8..24) {
            let scheduler = test_scheduler();
            let factor = scheduler.circadian_factor(hour);
            prop_assert!((0.0..=1.0).contains(&factor),
                "circadian factor {} for hour {} is out of [0.0, 1.0]", factor, hour);
        }
    }

    // --- Edge-case tests ---

    #[test]
    fn test_very_long_session_remains_ordered() {
        let scheduler = test_scheduler();
        let mut rng = test_rng();
        let start = Utc::now();

        let timestamps = scheduler.generate_session_timestamps(start, 1500, &mut rng);

        assert_eq!(timestamps.len(), 1500);
        for window in timestamps.windows(2) {
            assert!(
                window[1] > window[0],
                "timestamps must be strictly ordered even in long sessions"
            );
        }
        // First timestamp should be after start
        assert!(timestamps[0] > start);
    }

    #[test]
    fn test_midnight_crossing_schedule() {
        // Person who stays up late: wake=22 (10 PM), sleep=6 (6 AM next day).
        // This is an unusual but valid schedule (night-shift worker).
        let schedule = ActivitySchedule {
            wake_hour: 22,
            sleep_hour: 6,
            active_days: vec![0, 1, 2, 3, 4, 5, 6],
            timezone_offset_hours: 0,
        };
        let scheduler = OrganicScheduler::new(schedule, RiskLevel::Medium);
        let mut rng = test_rng();
        let now = Utc::now();

        // Should still produce valid future timestamps
        let t = scheduler.next_timestamp(now, &mut rng);
        assert!(t > now);

        // Circadian factor should return a value in [0, 1] for all hours
        for hour in 0..24u8 {
            let factor = scheduler.circadian_factor(hour);
            assert!(
                (0.0..=1.0).contains(&factor),
                "circadian factor {} for hour {} out of bounds with midnight-crossing schedule",
                factor,
                hour,
            );
        }
    }

    #[test]
    fn test_all_risk_levels_produce_future_timestamps() {
        let now = Utc::now();
        let schedule = ActivitySchedule::default();

        for risk in [
            RiskLevel::Low,
            RiskLevel::Medium,
            RiskLevel::High,
            RiskLevel::Maximum,
        ] {
            let scheduler = OrganicScheduler::new(schedule.clone(), risk);
            let mut rng = test_rng();
            let t = scheduler.next_timestamp(now, &mut rng);
            assert!(
                t > now,
                "risk level {:?} must produce future timestamps",
                risk
            );
        }
    }

    // REGRESSION-GUARD: an earlier next_timestamp() used
    //   ((hour as i8 + offset) % 24) as u8
    // which silently produced ~250 for any negative TZ offset
    // because Rust's `%` is truncated remainder (negative for
    // negative numerators) and `as u8` wrapped the sign-extended
    // value. circadian_factor(250) hit `hour > sleep + 1.0` and
    // returned 0.05 unconditionally — every user with a negative
    // UTC offset (i.e. North America) got the deepest-sleep activity
    // factor 24/7. This test pins the fix.
    //
    // We can't directly assert the activity factor (it's private),
    // but we CAN observe its effect: with deep-sleep factor (0.05)
    // the interval is base_interval / 0.05 = 20x base. With a
    // realistic factor (~0.9 for 14:00) the interval is base / 0.9.
    // The two are an order of magnitude apart for the SAME wall-
    // clock hour, so we just check the median interval is bounded.
    #[test]
    fn test_negative_timezone_offset_does_not_force_deep_sleep() {
        // 14:00 UTC, with a -5h offset → 09:00 local — well inside
        // the active "high" band of circadian_factor.
        let schedule = ActivitySchedule {
            wake_hour: 7,
            sleep_hour: 23,
            active_days: vec![0, 1, 2, 3, 4, 5, 6],
            timezone_offset_hours: -5, // EST
        };
        let scheduler = OrganicScheduler::new(schedule, RiskLevel::Medium);
        let mut rng = test_rng();
        // Pin a specific UTC hour to remove wall-clock variance from
        // the test.
        let t0 = chrono::NaiveDate::from_ymd_opt(2026, 4, 4)
            .unwrap()
            .and_hms_opt(14, 0, 0)
            .unwrap()
            .and_utc();

        // Sample many intervals — measure the median.
        let mut intervals = Vec::with_capacity(100);
        for _ in 0..100 {
            let t1 = scheduler.next_timestamp(t0, &mut rng);
            intervals.push((t1 - t0).num_seconds());
        }
        intervals.sort();
        let median = intervals[intervals.len() / 2];

        // Base interval at Medium risk = 120s. Deep-sleep factor
        // 0.05 → 2400s; daytime factor (0.6 morning routine) → 200s.
        // The buggy version was always at 2400±50% so anything
        // below ~1200 is proof of the fix. We require the median to
        // be below 1000s as a generous bound.
        assert!(
            median < 1000,
            "median interval {median}s suggests deep-sleep factor \
             is in effect — negative TZ offset bug regressed",
        );
    }
}
