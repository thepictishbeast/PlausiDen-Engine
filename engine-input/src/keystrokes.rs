//! Keystroke pattern generation — typing cadence, key sequences, dwell times.
//!
//! Real keystroke dynamics are biometrically unique. Synthetic keystrokes
//! must have realistic inter-key intervals, dwell times, and error rates.

use chrono::{DateTime, Duration, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext,
};
use rand::distributions::{Distribution, Uniform};
use rand::{CryptoRng, RngCore};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct KeystrokeEntry {
    pub meta: ArtifactMetadata,
    /// Sequence of keystrokes.
    pub keystrokes: Vec<Keystroke>,
    /// Average typing speed (chars per minute).
    pub avg_cpm: f64,
    /// Error rate (backspace/delete per 100 chars).
    pub error_rate: f64,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct Keystroke {
    /// Key pressed (character or special key name).
    pub key: String,
    /// Time key was pressed (ms since start of sequence).
    pub press_time_ms: u64,
    /// Time key was released (ms since start of sequence).
    pub release_time_ms: u64,
    /// Dwell time (release - press) in ms.
    pub dwell_ms: u64,
    /// Flight time (time between this press and previous release) in ms.
    pub flight_ms: u64,
}

impl Artifact for KeystrokeEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }
    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.keystrokes.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty keystroke sequence".into(),
            });
        }
        if self.avg_cpm <= 0.0 || self.avg_cpm > 1000.0 {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!("unrealistic CPM: {}", self.avg_cpm),
            });
        }
        Ok(())
    }
    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

/// Common words for typing sequences.
const COMMON_WORDS: &[&str] = &[
    "the", "be", "to", "of", "and", "a", "in", "that", "have", "I", "it", "for", "not", "on",
    "with", "he", "as", "you", "do", "at", "this", "but", "his", "by", "from", "they", "we", "say",
    "her", "she", "search", "help", "click", "open", "close", "save", "delete", "send", "hello",
    "thanks", "please", "yes", "no", "okay", "sure", "great",
];

pub struct KeystrokeGenerator;
impl KeystrokeGenerator {
    pub fn new() -> Self {
        Self
    }
}
impl Default for KeystrokeGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for KeystrokeGenerator {
    fn generate(
        &self,
        _profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        // Generate a sequence of 3-8 words
        let word_count = Uniform::new_inclusive(3u32, 8).sample(rng);
        let mut keystrokes = Vec::new();
        let mut current_ms: u64 = 0;
        let mut total_chars = 0u32;
        let mut errors = 0u32;

        for w in 0..word_count {
            let word_idx = Uniform::new(0usize, COMMON_WORDS.len()).sample(rng);
            let word = COMMON_WORDS[word_idx];

            for ch in word.chars() {
                // Dwell time: 50-150ms (how long key is held)
                let dwell = Uniform::new_inclusive(50u64, 150).sample(rng);
                // Flight time: 80-300ms (time between keys)
                let flight = if keystrokes.is_empty() {
                    0
                } else {
                    Uniform::new_inclusive(80u64, 300).sample(rng)
                };

                let press = current_ms + flight;
                let release = press + dwell;

                keystrokes.push(Keystroke {
                    key: ch.to_string(),
                    press_time_ms: press,
                    release_time_ms: release,
                    dwell_ms: dwell,
                    flight_ms: flight,
                });

                current_ms = release;
                total_chars += 1;
            }

            // Simulate occasional typo + backspace (5% chance per word)
            if Uniform::new_inclusive(0u32, 19).sample(rng) == 0 {
                let dwell = Uniform::new_inclusive(60u64, 120).sample(rng);
                let flight = Uniform::new_inclusive(100u64, 400).sample(rng);
                let press = current_ms + flight;
                keystrokes.push(Keystroke {
                    key: "Backspace".to_string(),
                    press_time_ms: press,
                    release_time_ms: press + dwell,
                    dwell_ms: dwell,
                    flight_ms: flight,
                });
                current_ms = press + dwell;
                errors += 1;
            }

            // Space between words
            if w < word_count - 1 {
                let dwell = Uniform::new_inclusive(40u64, 100).sample(rng);
                let flight = Uniform::new_inclusive(100u64, 250).sample(rng);
                let press = current_ms + flight;
                keystrokes.push(Keystroke {
                    key: " ".to_string(),
                    press_time_ms: press,
                    release_time_ms: press + dwell,
                    dwell_ms: dwell,
                    flight_ms: flight,
                });
                current_ms = press + dwell;
                total_chars += 1;
            }
        }

        let duration_min = current_ms as f64 / 60000.0;
        let avg_cpm = if duration_min > 0.0 {
            total_chars as f64 / duration_min
        } else {
            200.0
        };
        let error_rate = if total_chars > 0 {
            errors as f64 / total_chars as f64 * 100.0
        } else {
            0.0
        };

        let meta = ArtifactMetadata::new(
            DataCategory::Input,
            context.now,
            context.now,
            keystrokes.len() as u64 * 32,
        )?;

        let entry = KeystrokeEntry {
            meta,
            keystrokes,
            avg_cpm,
            error_rate,
        };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory {
        DataCategory::Input
    }
    fn forensic_weight(&self) -> u32 {
        40
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_keystrokes() {
        let g = KeystrokeGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);
        let a = g.generate(&p, &c, &mut r).unwrap();
        a.validate_plausibility().unwrap();
        let b = a.to_bytes().unwrap();
        let e: KeystrokeEntry = serde_json::from_slice(&b).unwrap();
        assert!(!e.keystrokes.is_empty());
        assert!(e.avg_cpm > 0.0);
    }

    #[test]
    fn test_500_keystroke_sequences_valid() {
        let g = KeystrokeGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..500 {
            let mut r = seeded_rng(s);
            g.generate(&p, &c, &mut r)
                .unwrap()
                .validate_plausibility()
                .unwrap();
        }
    }

    #[test]
    fn test_dwell_times_realistic() {
        let g = KeystrokeGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);
        let a = g.generate(&p, &c, &mut r).unwrap();
        let b = a.to_bytes().unwrap();
        let e: KeystrokeEntry = serde_json::from_slice(&b).unwrap();
        for k in &e.keystrokes {
            assert!(
                k.dwell_ms >= 40 && k.dwell_ms <= 200,
                "dwell {} out of range",
                k.dwell_ms
            );
        }
    }

    #[test]
    fn test_timestamps_ordered() {
        let g = KeystrokeGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);
        let a = g.generate(&p, &c, &mut r).unwrap();
        let b = a.to_bytes().unwrap();
        let e: KeystrokeEntry = serde_json::from_slice(&b).unwrap();
        for w in e.keystrokes.windows(2) {
            assert!(
                w[1].press_time_ms >= w[0].press_time_ms,
                "keystrokes not ordered"
            );
        }
    }
}
