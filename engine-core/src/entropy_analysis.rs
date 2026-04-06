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
}
