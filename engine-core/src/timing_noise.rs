//! Timing noise injector — add organic jitter to generation timestamps so
//! synthetic artifact timing patterns are statistically indistinguishable
//! from human activity.

use chrono::{DateTime, Duration, Utc};
use rand::Rng;
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::{Deserialize, Serialize};

/// Timing noise distribution.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NoiseModel {
    /// Uniform random jitter within [min, max] seconds.
    Uniform { min: i64, max: i64 },
    /// Gaussian jitter with given std deviation (seconds).
    Gaussian { std_dev_secs: f64 },
    /// Exponential inter-arrival times (Poisson process) — mean seconds.
    Exponential { mean_secs: f64 },
    /// Piecewise: slow at night, fast during active hours.
    Diurnal { peak_hours: Vec<u8>, off_peak_factor: f64 },
}

/// Timing noise injector.
pub struct TimingNoiser {
    rng: StdRng,
}

impl TimingNoiser {
    pub fn new(seed: u64) -> Self {
        Self { rng: StdRng::seed_from_u64(seed) }
    }

    pub fn from_entropy() -> Self {
        Self { rng: StdRng::from_entropy() }
    }

    /// Generate a noise delta in seconds.
    pub fn sample_delta_secs(&mut self, model: &NoiseModel) -> i64 {
        match model {
            NoiseModel::Uniform { min, max } => {
                if max <= min { return *min; }
                self.rng.r#gen_range(*min..=*max)
            }
            NoiseModel::Gaussian { std_dev_secs } => {
                // Box-Muller transform.
                let u1: f64 = self.rng.r#gen();
                let u2: f64 = self.rng.r#gen();
                let u1 = u1.max(f64::MIN_POSITIVE);
                let z = (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos();
                (z * std_dev_secs).round() as i64
            }
            NoiseModel::Exponential { mean_secs } => {
                let u: f64 = self.rng.r#gen::<f64>().max(f64::MIN_POSITIVE);
                (-mean_secs * u.ln()).round() as i64
            }
            NoiseModel::Diurnal { .. } => 0,
        }
    }

    /// Apply noise to a timestamp.
    pub fn apply(&mut self, ts: DateTime<Utc>, model: &NoiseModel) -> DateTime<Utc> {
        let delta = self.sample_delta_secs(model);
        ts + Duration::seconds(delta)
    }

    /// Is this timestamp inside a diurnal peak?
    pub fn in_peak_hours(&self, ts: &DateTime<Utc>, peak_hours: &[u8]) -> bool {
        use chrono::Timelike;
        let hour = ts.hour() as u8;
        peak_hours.contains(&hour)
    }

    /// Compute an activity weight for a given hour (used by schedulers).
    pub fn diurnal_weight(&self, ts: &DateTime<Utc>, model: &NoiseModel) -> f64 {
        if let NoiseModel::Diurnal { peak_hours, off_peak_factor } = model {
            if self.in_peak_hours(ts, peak_hours) {
                1.0
            } else {
                *off_peak_factor
            }
        } else {
            1.0
        }
    }

    /// Generate a sequence of N jittered timestamps starting from `base`.
    pub fn sequence(&mut self, base: DateTime<Utc>, count: usize, model: &NoiseModel) -> Vec<DateTime<Utc>> {
        let mut out = Vec::with_capacity(count);
        let mut cursor = base;
        for _ in 0..count {
            cursor = self.apply(cursor, model);
            out.push(cursor);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Timelike;

    #[test]
    fn test_uniform_within_range() {
        let mut n = TimingNoiser::new(42);
        let model = NoiseModel::Uniform { min: 5, max: 10 };
        for _ in 0..100 {
            let d = n.sample_delta_secs(&model);
            assert!(d >= 5 && d <= 10);
        }
    }

    #[test]
    fn test_uniform_zero_range() {
        let mut n = TimingNoiser::new(42);
        let model = NoiseModel::Uniform { min: 7, max: 7 };
        assert_eq!(n.sample_delta_secs(&model), 7);
    }

    #[test]
    fn test_gaussian_mean_near_zero() {
        let mut n = TimingNoiser::new(42);
        let model = NoiseModel::Gaussian { std_dev_secs: 10.0 };
        let samples: Vec<i64> = (0..1000).map(|_| n.sample_delta_secs(&model)).collect();
        let mean: f64 = samples.iter().map(|x| *x as f64).sum::<f64>() / samples.len() as f64;
        assert!(mean.abs() < 3.0);
    }

    #[test]
    fn test_exponential_non_negative() {
        let mut n = TimingNoiser::new(42);
        let model = NoiseModel::Exponential { mean_secs: 60.0 };
        for _ in 0..100 {
            let d = n.sample_delta_secs(&model);
            assert!(d >= 0);
        }
    }

    #[test]
    fn test_apply_moves_timestamp() {
        let mut n = TimingNoiser::new(42);
        let ts = Utc::now();
        let new_ts = n.apply(ts, &NoiseModel::Uniform { min: 60, max: 60 });
        assert_eq!((new_ts - ts).num_seconds(), 60);
    }

    #[test]
    fn test_sequence() {
        let mut n = TimingNoiser::new(42);
        let base = Utc::now();
        let seq = n.sequence(base, 10, &NoiseModel::Uniform { min: 1, max: 10 });
        assert_eq!(seq.len(), 10);
    }

    #[test]
    fn test_peak_hours() {
        let n = TimingNoiser::new(42);
        let ts = Utc::now().with_hour(10).unwrap();
        assert!(n.in_peak_hours(&ts, &vec![9, 10, 11]));
        assert!(!n.in_peak_hours(&ts, &vec![2, 3, 4]));
    }

    #[test]
    fn test_diurnal_weight() {
        let n = TimingNoiser::new(42);
        let ts = Utc::now().with_hour(10).unwrap();
        let model = NoiseModel::Diurnal { peak_hours: vec![9, 10, 11], off_peak_factor: 0.1 };
        assert_eq!(n.diurnal_weight(&ts, &model), 1.0);

        let ts_off = Utc::now().with_hour(3).unwrap();
        assert_eq!(n.diurnal_weight(&ts_off, &model), 0.1);
    }

    #[test]
    fn test_deterministic_seed() {
        let mut a = TimingNoiser::new(42);
        let mut b = TimingNoiser::new(42);
        assert_eq!(
            a.sample_delta_secs(&NoiseModel::Uniform { min: 0, max: 1000 }),
            b.sample_delta_secs(&NoiseModel::Uniform { min: 0, max: 1000 }),
        );
    }
}
