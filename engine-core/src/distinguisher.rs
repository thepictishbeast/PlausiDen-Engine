//! Statistical distinguisher framework — measure how well an
//! adversary can tell a synthetic corpus from a real one.
//!
//! # Game
//!
//! Every generator in this workspace is evaluated as the
//! *generator* side of a two-player distinguishing game:
//!
//! 1. The generator produces a corpus of N synthetic samples.
//! 2. A distinguisher is given N real samples and N synthetic
//!    samples, unlabeled.
//! 3. The distinguisher outputs a label per sample.
//! 4. The generator wins if the distinguisher's accuracy is no
//!    better than chance (0.5). The closer the observed accuracy
//!    is to 0.5, the less distinguishable the corpora are.
//!
//! This module provides the math and tooling to play that game
//! *without* committing to a particular distinguisher or a
//! particular input domain. Specific generators plug in their
//! own feature extractors and distinguishers on top.
//!
//! # No real corpus required (yet)
//!
//! Tests in this module use hand-crafted synthetic vectors so
//! the statistical math can be validated independently of any
//! real-world training corpus. When a real corpus becomes
//! available, plug it in via [`Distinguisher::score`] — the
//! framework does not care where the samples come from.

use serde::{Deserialize, Serialize};

/// A single feature vector — an ordered list of real-valued
/// statistics extracted from one sample. Feature extractors live
/// in the domain-specific generator crates.
#[derive(Debug, Clone, PartialEq)]
pub struct FeatureVector {
    pub values: Vec<f64>,
}

impl FeatureVector {
    pub fn new(values: Vec<f64>) -> Self {
        Self { values }
    }

    pub fn len(&self) -> usize {
        self.values.len()
    }

    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }
}

/// Labeled sample for the distinguishing game.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Label {
    Real,
    Synthetic,
}

/// Result of running a distinguishing game against two corpora.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistinguishReport {
    /// Number of samples per class.
    pub n_real: usize,
    pub n_synthetic: usize,
    /// How many samples the distinguisher correctly classified.
    pub correct: usize,
    /// Observed accuracy on the labeled corpus.
    pub accuracy: f64,
    /// One-sided p-value for the null hypothesis "the distinguisher
    /// is at chance". Values close to 1.0 mean the corpora are
    /// effectively indistinguishable (generator winning); values
    /// close to 0.0 mean the distinguisher is beating chance
    /// (generator losing).
    pub p_value_chance: f64,
    /// Effect size (advantage over chance): 2 * (accuracy - 0.5).
    /// Zero means perfect indistinguishability; 1.0 means the
    /// distinguisher is always right.
    pub advantage: f64,
}

impl DistinguishReport {
    /// Does this result count as a pass? A passing run has the
    /// distinguisher within `tolerance` of chance on both accuracy
    /// and advantage — the tighter the tolerance, the stronger the
    /// claim of indistinguishability.
    pub fn passes(&self, tolerance: f64) -> bool {
        (self.accuracy - 0.5).abs() <= tolerance && self.advantage.abs() <= tolerance * 2.0
    }

    pub fn verdict(&self) -> &'static str {
        if self.passes(0.05) {
            "indistinguishable (passes at tolerance 0.05)"
        } else if self.passes(0.10) {
            "borderline (passes at tolerance 0.10)"
        } else {
            "distinguishable (fails)"
        }
    }
}

/// Trait implemented by domain-specific distinguishers.
pub trait Distinguisher {
    /// Classify a single feature vector as Real or Synthetic.
    fn classify(&self, sample: &FeatureVector) -> Label;
}

/// Drive a distinguishing game against two labeled corpora.
///
/// `real` and `synthetic` must contain feature vectors of the same
/// length. The distinguisher runs `classify` against each one and
/// we compute accuracy, p-value, and advantage over the full set.
pub fn score<D: Distinguisher>(
    distinguisher: &D,
    real: &[FeatureVector],
    synthetic: &[FeatureVector],
) -> DistinguishReport {
    let mut correct: usize = 0;
    for v in real {
        if distinguisher.classify(v) == Label::Real {
            correct += 1;
        }
    }
    for v in synthetic {
        if distinguisher.classify(v) == Label::Synthetic {
            correct += 1;
        }
    }

    let total = real.len() + synthetic.len();
    let accuracy = if total == 0 {
        0.0
    } else {
        correct as f64 / total as f64
    };
    let advantage = 2.0 * (accuracy - 0.5);
    let p_value = p_value_against_chance(correct, total);

    DistinguishReport {
        n_real: real.len(),
        n_synthetic: synthetic.len(),
        correct,
        accuracy,
        p_value_chance: p_value,
        advantage,
    }
}

/// Compute a one-sided p-value for the null hypothesis "the
/// distinguisher is at chance accuracy 0.5". Uses a normal
/// approximation to the binomial, which is accurate for any
/// reasonable sample size (n ≥ 30). For small n the approximation
/// is conservative.
///
/// Returns a value in `[0.0, 1.0]`:
/// - Close to 1.0 means "observed accuracy is at or below chance"
///   (generator winning — corpora indistinguishable).
/// - Close to 0.0 means "observed accuracy is far above chance"
///   (generator losing — distinguisher beating chance).
pub fn p_value_against_chance(correct: usize, total: usize) -> f64 {
    if total == 0 {
        return 1.0;
    }
    let n = total as f64;
    let k = correct as f64;
    let p0 = 0.5;
    let mean = n * p0;
    let variance = n * p0 * (1.0 - p0);
    let std_dev = variance.sqrt();
    if std_dev == 0.0 {
        return if k <= mean { 1.0 } else { 0.0 };
    }
    // Standardised score: how many stddevs above the null mean.
    let z = (k - mean) / std_dev;
    // One-sided p-value = P(Z >= z) for a standard normal.
    one_sided_normal_sf(z)
}

/// Survival function of the standard normal: P(Z >= z). Uses a
/// closed-form approximation good to five decimal places, which is
/// more than enough for p-value reporting in the distinguishing
/// game.
pub fn one_sided_normal_sf(z: f64) -> f64 {
    // Abramowitz & Stegun 26.2.17. Good for |z| < 7.
    let z_abs = z.abs();
    let t = 1.0 / (1.0 + 0.2316419 * z_abs);
    let poly = t * (0.319381530
        + t * (-0.356563782
            + t * (1.781477937 + t * (-1.821255978 + t * 1.330274429))));
    let pdf = (-0.5 * z_abs * z_abs).exp() / (2.0 * std::f64::consts::PI).sqrt();
    let tail = pdf * poly;
    if z >= 0.0 {
        tail
    } else {
        1.0 - tail
    }
}

/// Kullback–Leibler divergence between two discrete distributions
/// given as parallel probability vectors of the same length.
/// Returns infinity if `q[i] == 0` for some `i` where `p[i] > 0`.
pub fn kl_divergence(p: &[f64], q: &[f64]) -> f64 {
    assert_eq!(p.len(), q.len(), "KL distributions must be same length");
    let mut sum = 0.0;
    for i in 0..p.len() {
        if p[i] == 0.0 {
            continue;
        }
        if q[i] == 0.0 {
            return f64::INFINITY;
        }
        sum += p[i] * (p[i] / q[i]).ln();
    }
    sum
}

/// Chi-square statistic comparing observed counts to expected
/// counts. Useful for categorical feature distributions.
pub fn chi_square(observed: &[f64], expected: &[f64]) -> f64 {
    assert_eq!(
        observed.len(),
        expected.len(),
        "chi-square arrays must be same length"
    );
    let mut sum = 0.0;
    for i in 0..observed.len() {
        if expected[i] == 0.0 {
            continue;
        }
        let diff = observed[i] - expected[i];
        sum += diff * diff / expected[i];
    }
    sum
}

/// Mean and standard deviation of a slice of f64. Used by feature
/// extractors for z-score normalisation before handing data to a
/// distinguisher.
pub fn mean_stddev(data: &[f64]) -> (f64, f64) {
    if data.is_empty() {
        return (0.0, 0.0);
    }
    let mean: f64 = data.iter().sum::<f64>() / data.len() as f64;
    let var: f64 = data.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / data.len() as f64;
    (mean, var.sqrt())
}

/// Simple L2-nearest-neighbour distinguisher. For every test
/// sample, classify by distance to the closest example in two
/// labeled training corpora. This is a strong baseline: any
/// generator that beats a 1-NN distinguisher is doing well.
pub struct NearestNeighbourDistinguisher {
    real: Vec<FeatureVector>,
    synthetic: Vec<FeatureVector>,
}

impl NearestNeighbourDistinguisher {
    pub fn new(real: Vec<FeatureVector>, synthetic: Vec<FeatureVector>) -> Self {
        Self { real, synthetic }
    }

    fn l2_distance(a: &FeatureVector, b: &FeatureVector) -> f64 {
        if a.values.len() != b.values.len() {
            return f64::INFINITY;
        }
        a.values
            .iter()
            .zip(b.values.iter())
            .map(|(x, y)| (x - y).powi(2))
            .sum::<f64>()
            .sqrt()
    }
}

impl Distinguisher for NearestNeighbourDistinguisher {
    fn classify(&self, sample: &FeatureVector) -> Label {
        let min_real = self
            .real
            .iter()
            .map(|v| Self::l2_distance(v, sample))
            .fold(f64::INFINITY, f64::min);
        let min_synth = self
            .synthetic
            .iter()
            .map(|v| Self::l2_distance(v, sample))
            .fold(f64::INFINITY, f64::min);
        if min_real <= min_synth {
            Label::Real
        } else {
            Label::Synthetic
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(values: &[f64]) -> FeatureVector {
        FeatureVector::new(values.to_vec())
    }

    #[test]
    fn test_p_value_exactly_chance() {
        // 50 / 100 correct at chance. p-value should be ~0.5.
        let p = p_value_against_chance(50, 100);
        assert!((p - 0.5).abs() < 0.01);
    }

    #[test]
    fn test_p_value_strong_signal() {
        // 90 / 100 correct. p-value should be essentially zero.
        let p = p_value_against_chance(90, 100);
        assert!(p < 0.001);
    }

    #[test]
    fn test_p_value_below_chance() {
        // 10 / 100 correct is worse than chance. One-sided p-value
        // should be effectively 1.0.
        let p = p_value_against_chance(10, 100);
        assert!(p > 0.999);
    }

    #[test]
    fn test_one_sided_sf_symmetry() {
        // For the standard normal, P(Z >= 0) = 0.5.
        assert!((one_sided_normal_sf(0.0) - 0.5).abs() < 1e-6);
    }

    #[test]
    fn test_one_sided_sf_two_stddev() {
        // P(Z >= 2) ≈ 0.0228.
        let p = one_sided_normal_sf(2.0);
        assert!((p - 0.0228).abs() < 0.002);
    }

    #[test]
    fn test_kl_divergence_identical_is_zero() {
        let p = [0.25, 0.25, 0.25, 0.25];
        let q = [0.25, 0.25, 0.25, 0.25];
        assert!(kl_divergence(&p, &q).abs() < 1e-12);
    }

    #[test]
    fn test_kl_divergence_nonzero_for_different() {
        let p = [0.5, 0.5];
        let q = [0.9, 0.1];
        assert!(kl_divergence(&p, &q) > 0.0);
    }

    #[test]
    fn test_kl_divergence_infinity_on_zero_q() {
        let p = [0.5, 0.5];
        let q = [1.0, 0.0];
        assert_eq!(kl_divergence(&p, &q), f64::INFINITY);
    }

    #[test]
    fn test_chi_square_identical_is_zero() {
        let o = [10.0, 10.0, 10.0];
        let e = [10.0, 10.0, 10.0];
        assert_eq!(chi_square(&o, &e), 0.0);
    }

    #[test]
    fn test_chi_square_non_zero_for_different() {
        let o = [20.0, 0.0, 10.0];
        let e = [10.0, 10.0, 10.0];
        assert!(chi_square(&o, &e) > 0.0);
    }

    #[test]
    fn test_mean_stddev_empty() {
        let (m, s) = mean_stddev(&[]);
        assert_eq!(m, 0.0);
        assert_eq!(s, 0.0);
    }

    #[test]
    fn test_mean_stddev_known() {
        let (m, s) = mean_stddev(&[1.0, 2.0, 3.0, 4.0, 5.0]);
        assert!((m - 3.0).abs() < 1e-12);
        // Population std dev of 1..5 is sqrt(2).
        assert!((s - 2.0_f64.sqrt()).abs() < 1e-12);
    }

    #[test]
    fn test_nearest_neighbour_distinguishable_corpora() {
        // Real samples cluster around the origin; synthetic
        // cluster around (10, 10). A 1-NN distinguisher should
        // label a query near (10, 10) as Synthetic.
        let real = vec![v(&[0.0, 0.0]), v(&[0.1, -0.1]), v(&[-0.1, 0.1])];
        let synth = vec![v(&[10.0, 10.0]), v(&[9.9, 10.1]), v(&[10.1, 9.9])];
        let d = NearestNeighbourDistinguisher::new(real.clone(), synth.clone());
        assert_eq!(d.classify(&v(&[0.05, 0.0])), Label::Real);
        assert_eq!(d.classify(&v(&[10.05, 10.0])), Label::Synthetic);
    }

    #[test]
    fn test_score_on_identical_corpora_is_at_chance() {
        // If real and synthetic are drawn from the same
        // distribution, a distinguisher trained on one cannot
        // reliably beat chance on the other.
        let corpus_a = vec![v(&[1.0]), v(&[2.0]), v(&[3.0]), v(&[4.0])];
        let corpus_b = vec![v(&[1.0]), v(&[2.0]), v(&[3.0]), v(&[4.0])];
        let d = NearestNeighbourDistinguisher::new(corpus_a.clone(), corpus_b.clone());
        let report = score(&d, &corpus_a, &corpus_b);
        // Identical corpora: the distinguisher labels each sample
        // Real (its "training" corpus_a is the exact point). So
        // the Real samples all score correct, the Synthetic samples
        // all score incorrect, and accuracy is exactly 0.5.
        assert!((report.accuracy - 0.5).abs() < 0.01);
        assert!(report.passes(0.05));
    }

    #[test]
    fn test_score_on_cleanly_separated_corpora_fails() {
        let real = vec![v(&[0.0, 0.0]), v(&[0.1, -0.1]), v(&[-0.1, 0.1])];
        let synth = vec![v(&[10.0, 10.0]), v(&[9.9, 10.1]), v(&[10.1, 9.9])];
        let d = NearestNeighbourDistinguisher::new(real.clone(), synth.clone());
        let report = score(&d, &real, &synth);
        assert!((report.accuracy - 1.0).abs() < 1e-12);
        assert!(!report.passes(0.10));
        assert!(report.verdict().contains("distinguishable"));
    }

    #[test]
    fn test_report_verdict_labels() {
        let indistinguishable = DistinguishReport {
            n_real: 100,
            n_synthetic: 100,
            correct: 100,
            accuracy: 0.5,
            p_value_chance: 0.5,
            advantage: 0.0,
        };
        assert!(indistinguishable.verdict().contains("indistinguishable"));

        let borderline = DistinguishReport {
            n_real: 100,
            n_synthetic: 100,
            correct: 115,
            accuracy: 0.575,
            p_value_chance: 0.05,
            advantage: 0.15,
        };
        assert!(borderline.verdict().contains("borderline"));

        let distinguishable = DistinguishReport {
            n_real: 100,
            n_synthetic: 100,
            correct: 190,
            accuracy: 0.95,
            p_value_chance: 0.0,
            advantage: 0.9,
        };
        assert!(distinguishable.verdict().contains("distinguishable"));
    }

    #[test]
    fn test_score_empty_corpora() {
        let empty: Vec<FeatureVector> = Vec::new();
        let d = NearestNeighbourDistinguisher::new(empty.clone(), empty.clone());
        let report = score(&d, &empty, &empty);
        assert_eq!(report.n_real, 0);
        assert_eq!(report.n_synthetic, 0);
        assert_eq!(report.accuracy, 0.0);
    }

    #[test]
    fn test_feature_vector_mismatched_lengths_l2_infinity() {
        let a = v(&[1.0, 2.0]);
        let b = v(&[1.0, 2.0, 3.0]);
        assert_eq!(NearestNeighbourDistinguisher::l2_distance(&a, &b), f64::INFINITY);
    }
}
