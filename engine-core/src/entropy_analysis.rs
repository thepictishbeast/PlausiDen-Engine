//! Content entropy analysis — measure synthetic artifact entropy to ensure
//! generated content is statistically indistinguishable from real content.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Shannon entropy calculation for byte content.
pub fn shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut h = 0.0;
    for c in counts.iter() {
        if *c == 0 { continue; }
        let p = *c as f64 / len;
        h -= p * p.log2();
    }
    h
}

/// Shannon entropy over strings.
pub fn string_entropy(s: &str) -> f64 {
    shannon_entropy(s.as_bytes())
}

/// Byte-frequency distribution.
pub fn byte_frequency(data: &[u8]) -> HashMap<u8, f64> {
    let mut counts = HashMap::new();
    let len = data.len() as f64;
    for &b in data {
        *counts.entry(b).or_insert(0u64) += 1;
    }
    counts.into_iter()
        .map(|(b, c)| (b, c as f64 / len))
        .collect()
}

/// Entropy assessment for a single artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EntropyReport {
    pub length: usize,
    pub entropy_bits: f64,
    pub entropy_ratio: f64, // ratio to maximum possible
    pub ascii_ratio: f64,
    pub printable_ratio: f64,
    pub whitespace_ratio: f64,
    pub assessment: Assessment,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Assessment {
    /// Entropy too low — likely repetitive or trivial.
    TooLow,
    /// Entropy suspiciously high — likely random bytes or ciphertext.
    TooHigh,
    /// Entropy matches natural text distribution.
    NaturalText,
    /// Entropy matches binary content distribution.
    NaturalBinary,
}

/// Compute an entropy report on arbitrary content.
pub fn analyze(data: &[u8]) -> EntropyReport {
    let length = data.len();
    let entropy_bits = shannon_entropy(data);
    let entropy_ratio = if length == 0 { 0.0 } else { entropy_bits / 8.0 };

    let ascii = data.iter().filter(|b| **b < 128).count();
    let printable = data.iter()
        .filter(|b| (**b >= 0x20 && **b < 0x7f) || **b == b'\n' || **b == b'\r' || **b == b'\t')
        .count();
    let whitespace = data.iter()
        .filter(|b| **b == b' ' || **b == b'\n' || **b == b'\t')
        .count();

    let ascii_ratio = if length == 0 { 0.0 } else { ascii as f64 / length as f64 };
    let printable_ratio = if length == 0 { 0.0 } else { printable as f64 / length as f64 };
    let whitespace_ratio = if length == 0 { 0.0 } else { whitespace as f64 / length as f64 };

    let assessment = if entropy_bits < 2.0 {
        Assessment::TooLow
    } else if printable_ratio > 0.9 && entropy_bits > 3.5 && entropy_bits < 5.5 {
        Assessment::NaturalText
    } else if entropy_bits > 7.8 && printable_ratio < 0.5 {
        Assessment::TooHigh
    } else {
        Assessment::NaturalBinary
    };

    EntropyReport {
        length,
        entropy_bits,
        entropy_ratio,
        ascii_ratio,
        printable_ratio,
        whitespace_ratio,
        assessment,
    }
}

/// Typical entropy ranges for content categories.
pub fn expected_entropy(category: &str) -> Option<(f64, f64)> {
    match category {
        "english_text" => Some((3.8, 5.0)),
        "json" => Some((4.0, 5.5)),
        "html" => Some((4.5, 5.8)),
        "source_code" => Some((4.0, 5.5)),
        "random" => Some((7.9, 8.0)),
        "base64" => Some((5.8, 6.2)),
        "uuid" => Some((4.0, 4.2)),
        "executable" => Some((6.0, 7.5)),
        _ => None,
    }
}

/// Check whether an entropy measurement fits a category.
pub fn fits_category(entropy: f64, category: &str) -> bool {
    if let Some((low, high)) = expected_entropy(category) {
        entropy >= low && entropy <= high
    } else {
        false
    }
}

/// Compute Shannon entropy over sliding blocks of `block_size` bytes.
///
/// Global Shannon entropy averages over the whole buffer, which hides
/// local anomalies: a 10 kB ASCII text with 256 bytes of random noise
/// pasted in the middle still looks like plausible text at the global
/// level, but a 256-byte sliding window would spike at the boundary.
/// Generators can use this to self-validate that their output is
/// internally consistent — a single sharp spike is a smell that a
/// real organic artifact of the same class would not have.
///
/// Returns a vector of (start_offset, entropy_bits) pairs. Empty
/// input or block_size > len returns an empty vector.
pub fn block_entropy(data: &[u8], block_size: usize) -> Vec<(usize, f64)> {
    if block_size == 0 || data.len() < block_size {
        return Vec::new();
    }
    let mut out = Vec::with_capacity(data.len() - block_size + 1);
    // Non-overlapping blocks — overlapping windows would be O(n*w),
    // non-overlapping is O(n) and still catches the spike.
    let mut start = 0;
    while start + block_size <= data.len() {
        let h = shannon_entropy(&data[start..start + block_size]);
        out.push((start, h));
        start += block_size;
    }
    out
}

/// Maximum entropy spread across blocks of size `block_size`.
///
/// A low spread (close to 0) means the content is uniformly mixed;
/// a high spread means there are regions with very different byte
/// distributions (think: binary blob embedded in text). This single
/// number is the cheapest anomaly signal a generator can consult
/// before emitting an artifact.
pub fn block_entropy_spread(data: &[u8], block_size: usize) -> f64 {
    let blocks = block_entropy(data, block_size);
    if blocks.len() < 2 {
        return 0.0;
    }
    let mut min = f64::MAX;
    let mut max = f64::MIN;
    for (_, h) in &blocks {
        if *h < min {
            min = *h;
        }
        if *h > max {
            max = *h;
        }
    }
    max - min
}

/// Longest run of strictly monotonic (all increasing or all
/// decreasing) consecutive bytes.
///
/// Counter-style synthetic data — e.g. `0x00 0x01 0x02 0x03 ...` —
/// has very high Shannon entropy (uniform distribution across the
/// observed bytes) and will easily pass a naive entropy check. But
/// its maximum monotonic run is the full length of the counter,
/// which is a dead giveaway. Real organic content almost never has
/// monotonic runs longer than a handful of bytes.
pub fn max_monotonic_run(data: &[u8]) -> usize {
    if data.len() < 2 {
        return data.len();
    }
    let mut longest = 1usize;
    let mut current_inc = 1usize;
    let mut current_dec = 1usize;
    for pair in data.windows(2) {
        if pair[1] > pair[0] {
            current_inc += 1;
            current_dec = 1;
        } else if pair[1] < pair[0] {
            current_dec += 1;
            current_inc = 1;
        } else {
            current_inc = 1;
            current_dec = 1;
        }
        let local = current_inc.max(current_dec);
        if local > longest {
            longest = local;
        }
    }
    longest
}

/// Chi-square goodness-of-fit statistic against the uniform byte
/// distribution.
///
/// The null hypothesis is "bytes are drawn iid from a uniform
/// distribution over 0..=255". High values are evidence against the
/// null — i.e., the content is NOT uniform random. Useful as the
/// inverse check to `max_monotonic_run`: an artifact that claims to
/// be compressed or encrypted should score close to 255 * chi_crit
/// (bigger buffers converge faster).
///
/// Returns 0.0 for empty input.
pub fn chi_square_uniform(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut counts = [0u64; 256];
    for &b in data {
        counts[b as usize] += 1;
    }
    let expected = data.len() as f64 / 256.0;
    if expected == 0.0 {
        return 0.0;
    }
    let mut sum = 0.0;
    for &c in counts.iter() {
        let diff = c as f64 - expected;
        sum += (diff * diff) / expected;
    }
    sum
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_entropy() {
        assert_eq!(shannon_entropy(&[]), 0.0);
    }

    #[test]
    fn test_uniform_bytes_high_entropy() {
        let data: Vec<u8> = (0..=255).collect();
        let h = shannon_entropy(&data);
        assert!(h > 7.9);
    }

    #[test]
    fn test_single_byte_zero_entropy() {
        let data = vec![0u8; 1000];
        assert_eq!(shannon_entropy(&data), 0.0);
    }

    #[test]
    fn test_english_entropy_range() {
        let text = "The quick brown fox jumps over the lazy dog. \
                    The quick brown fox jumps over the lazy dog.";
        let h = string_entropy(text);
        assert!(h > 3.0 && h < 5.5);
    }

    #[test]
    fn test_byte_frequency_sums_to_one() {
        let data = b"abcdef";
        let freq = byte_frequency(data);
        let sum: f64 = freq.values().sum();
        assert!((sum - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_analyze_text() {
        let report = analyze(b"Hello, world! This is some English text for testing.");
        assert_eq!(report.assessment, Assessment::NaturalText);
    }

    #[test]
    fn test_analyze_too_low() {
        let report = analyze(&vec![0u8; 100]);
        assert_eq!(report.assessment, Assessment::TooLow);
    }

    #[test]
    fn test_analyze_too_high() {
        let data: Vec<u8> = (0..=255).cycle().take(10_000).collect();
        let report = analyze(&data);
        assert_eq!(report.assessment, Assessment::TooHigh);
    }

    #[test]
    fn test_expected_entropy() {
        assert!(expected_entropy("english_text").is_some());
        assert!(expected_entropy("made_up").is_none());
    }

    #[test]
    fn test_fits_category() {
        assert!(fits_category(4.5, "english_text"));
        assert!(!fits_category(7.9, "english_text"));
    }

    #[test]
    fn test_ascii_ratio() {
        let report = analyze(b"pure ASCII text");
        assert!((report.ascii_ratio - 1.0).abs() < 0.01);
    }

    #[test]
    fn test_block_entropy_on_uniform_text() {
        // A reasonably long English text should have low entropy
        // spread across blocks — each block is natural-text-shaped.
        let text = "The quick brown fox jumps over the lazy dog. ".repeat(50);
        let blocks = block_entropy(text.as_bytes(), 128);
        assert!(!blocks.is_empty());
        for (_, h) in &blocks {
            assert!(*h > 2.0 && *h < 6.0);
        }
    }

    #[test]
    fn test_block_entropy_catches_embedded_noise() {
        // Embed a chunk of high-entropy random-ish bytes inside an
        // otherwise-textual stream. Global Shannon will average the
        // two regions and look plausible, but block entropy should
        // show a clear spike at the junction.
        let mut data = b"the quick brown fox jumps over the lazy dog. ".repeat(10);
        // Insert a high-entropy blob — byte cycle is uniform over 256.
        let blob: Vec<u8> = (0u8..=255).collect();
        data.extend_from_slice(&blob);
        data.extend_from_slice(
            b" and more text afterwards so we cross another block boundary ".repeat(10).as_slice(),
        );
        let spread = block_entropy_spread(&data, 128);
        assert!(
            spread > 0.5,
            "block entropy spread should be non-trivial: got {spread}",
        );
    }

    #[test]
    fn test_block_entropy_empty_and_tiny_inputs() {
        assert!(block_entropy(&[], 8).is_empty());
        assert!(block_entropy(b"abc", 8).is_empty());
        assert_eq!(block_entropy_spread(&[], 8), 0.0);
        assert_eq!(block_entropy_spread(b"abc", 8), 0.0);
    }

    #[test]
    fn test_max_monotonic_run_on_counter() {
        // REGRESSION-GUARD: the classic "high Shannon entropy but
        // trivially synthetic" counter pattern. Byte cycle over
        // 0..=255 has entropy 8.0 bits — maximum — but a dumb
        // counter is obviously not organic.
        let counter: Vec<u8> = (0u8..=255).collect();
        let h = shannon_entropy(&counter);
        assert!(h > 7.9, "counter should have max Shannon entropy: {h}");
        let run = max_monotonic_run(&counter);
        assert_eq!(
            run, 256,
            "monotonic run must detect the full counter sequence",
        );
    }

    #[test]
    fn test_max_monotonic_run_on_random_is_short() {
        // A non-monotonic byte stream should have a very short
        // maximum monotonic run. Hand-craft a short alternation.
        let data = b"ABABABABABAB".to_vec();
        let run = max_monotonic_run(&data);
        assert!(run <= 2, "alternating pattern has no long run: {run}");
    }

    #[test]
    fn test_max_monotonic_run_degenerate_sizes() {
        assert_eq!(max_monotonic_run(&[]), 0);
        assert_eq!(max_monotonic_run(&[42]), 1);
    }

    #[test]
    fn test_chi_square_uniform_on_counter_is_small() {
        // A counter over 0..=255 IS the uniform distribution over
        // 256 bins — chi-square should be exactly 0 (each bin has
        // exactly expected count).
        let counter: Vec<u8> = (0u8..=255).collect();
        let chi = chi_square_uniform(&counter);
        assert!(chi.abs() < 1e-9, "chi-square on exact uniform should be 0, got {chi}");
    }

    #[test]
    fn test_chi_square_uniform_on_single_byte_is_large() {
        // All zeros → extreme deviation from uniform.
        let data = vec![0u8; 10_000];
        let chi = chi_square_uniform(&data);
        // Expected count per bin is 10_000 / 256 ≈ 39.06. Bin 0 has
        // 10_000, all others 0. Chi should be astronomically large.
        assert!(chi > 1_000_000.0, "extreme skew should blow up: {chi}");
    }

    #[test]
    fn test_chi_square_uniform_empty() {
        assert_eq!(chi_square_uniform(&[]), 0.0);
    }

    #[test]
    fn test_combined_counter_is_caught_by_monotonic_not_shannon() {
        // The punchline of this suite: the counter pattern passes
        // the Shannon check, passes chi-square (it IS uniform!),
        // but fails the monotonic-run check. A generator that
        // consults only Shannon would pass this obviously-synthetic
        // output; a generator that consults all three primitives
        // will not.
        let counter: Vec<u8> = (0u8..=255).collect();
        assert!(shannon_entropy(&counter) > 7.9); // passes Shannon
        assert!(chi_square_uniform(&counter) < 1e-9); // passes chi-square
        assert_eq!(max_monotonic_run(&counter), 256); // FAILS monotonic
    }
}
