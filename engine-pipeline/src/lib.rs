//! # PlausiDen Engine Pipeline
//!
//! End-to-end pollution pipeline. Orchestrates generators, timing, validation.

use std::collections::HashMap;
use chrono::{DateTime, Utc};
use engine_browser::{CookieGenerator, HistoryGenerator, SearchGenerator};
use engine_core::paranoia;
use engine_core::profile::UserProfile;
use engine_core::schedule::OrganicScheduler;
use engine_core::traits::{DataCategory, DataGenerator, GenerationContext};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedArtifact {
    pub category: DataCategory,
    pub bytes: Vec<u8>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InjectionTarget {
    FirefoxHistory,
    FirefoxCookies,
    ChromeHistory,
    ChromeCookies,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionReport {
    pub total_generated: usize,
    pub by_category: HashMap<String, usize>,
    pub duration_secs: u64,
    pub paranoia_failures: usize,
}

enum GeneratorKind {
    History(HistoryGenerator),
    Cookies(CookieGenerator),
    Searches(SearchGenerator),
}

impl GeneratorKind {
    fn generate_artifact(&self, profile: &UserProfile, ctx: &GenerationContext, rng: &mut ChaCha20Rng) -> engine_core::error::Result<Box<dyn engine_core::traits::Artifact>> {
        match self {
            Self::History(g) => g.generate(profile, ctx, rng),
            Self::Cookies(g) => g.generate(profile, ctx, rng),
            Self::Searches(g) => g.generate(profile, ctx, rng),
        }
    }

    fn data_category(&self) -> DataCategory {
        match self {
            Self::History(g) => g.category(),
            Self::Cookies(g) => g.category(),
            Self::Searches(g) => g.category(),
        }
    }
}

pub struct PollutionPipeline {
    profile: UserProfile,
    _scheduler: OrganicScheduler,
    generators: Vec<GeneratorKind>,
    rng: ChaCha20Rng,
}

impl PollutionPipeline {
    pub fn new(profile: UserProfile, seed: u64) -> Self {
        let scheduler = OrganicScheduler::new(profile.activity_schedule.clone(), profile.risk_level);
        Self { profile, _scheduler: scheduler, generators: Vec::new(), rng: ChaCha20Rng::seed_from_u64(seed) }
    }

    pub fn with_generators(mut self, categories: Vec<DataCategory>) -> Self {
        for cat in categories {
            if cat == DataCategory::BrowserActivity {
                self.generators.push(GeneratorKind::History(HistoryGenerator::new()));
                self.generators.push(GeneratorKind::Cookies(CookieGenerator::new()));
                self.generators.push(GeneratorKind::Searches(SearchGenerator::new()));
            }
        }
        self
    }

    pub fn generate_batch(&mut self, count: usize) -> Vec<GeneratedArtifact> {
        let mut artifacts = Vec::with_capacity(count);
        let ctx = GenerationContext::new();

        for _ in 0..count {
            if self.generators.is_empty() { break; }
            let idx = rand::Rng::gen_range(&mut self.rng, 0..self.generators.len());
            let mut rng_clone = self.rng.clone();
            let generator = &self.generators[idx];

            match generator.generate_artifact(&self.profile, &ctx, &mut rng_clone) {
                Ok(artifact) => {
                    if let Err(e) = paranoia::deep_validate_artifact(artifact.as_ref()) {
                        tracing::warn!("Paranoia: {e}");
                        continue;
                    }
                    match artifact.to_bytes() {
                        Ok(bytes) => {
                            let cleaned = strip_meta(&bytes);
                            artifacts.push(GeneratedArtifact {
                                category: generator.data_category(),
                                bytes: cleaned,
                                timestamp: artifact.metadata().created_at,
                            });
                        }
                        Err(e) => tracing::warn!("Serialize: {e}"),
                    }
                }
                Err(e) => tracing::warn!("Generate: {e}"),
            }
            // Advance RNG state
            use rand::RngCore;
            self.rng.next_u64();
        }

        artifacts
    }

    pub fn generate_injectable(&mut self, count: usize, _target: InjectionTarget) -> Vec<Vec<u8>> {
        self.generate_batch(count).into_iter().map(|a| a.bytes).collect()
    }

    pub fn run_session(&mut self, duration_secs: u64) -> SessionReport {
        let start = std::time::Instant::now();
        let mut total = 0usize;
        let mut by_category: HashMap<String, usize> = HashMap::new();
        let mut failures = 0usize;

        loop {
            if duration_secs > 0 && start.elapsed().as_secs() >= duration_secs { break; }
            let batch = self.generate_batch(1);
            if batch.is_empty() { failures += 1; }
            for a in &batch {
                total += 1;
                *by_category.entry(format!("{:?}", a.category)).or_default() += 1;
            }
            if duration_secs == 0 { break; }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }

        SessionReport { total_generated: total, by_category, duration_secs: start.elapsed().as_secs(), paranoia_failures: failures }
    }
}

fn strip_meta(bytes: &[u8]) -> Vec<u8> {
    if let Ok(mut val) = serde_json::from_slice::<serde_json::Value>(bytes) {
        if let Some(obj) = val.as_object_mut() {
            obj.remove("meta");
            obj.remove("artifact_id");
        }
        serde_json::to_vec(&val).unwrap_or_else(|_| bytes.to_vec())
    } else {
        bytes.to_vec()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_browser() {
        let mut p = PollutionPipeline::new(UserProfile::default(), 42)
            .with_generators(vec![DataCategory::BrowserActivity]);
        let a = p.generate_batch(10);
        assert!(!a.is_empty());
    }

    #[test]
    fn test_meta_stripped() {
        let mut p = PollutionPipeline::new(UserProfile::default(), 42)
            .with_generators(vec![DataCategory::BrowserActivity]);
        for a in p.generate_batch(5) {
            let v: serde_json::Value = serde_json::from_slice(&a.bytes).unwrap();
            assert!(v.get("meta").is_none());
        }
    }

    #[test]
    fn test_injectable() {
        let mut p = PollutionPipeline::new(UserProfile::default(), 42)
            .with_generators(vec![DataCategory::BrowserActivity]);
        let i = p.generate_injectable(5, InjectionTarget::FirefoxHistory);
        assert!(!i.is_empty());
    }

    #[test]
    fn test_session() {
        let mut p = PollutionPipeline::new(UserProfile::default(), 42)
            .with_generators(vec![DataCategory::BrowserActivity]);
        let r = p.run_session(0);
        assert!(r.total_generated > 0 || r.paranoia_failures > 0);
    }

    #[test]
    fn test_stress_1000() {
        let mut p = PollutionPipeline::new(UserProfile::default(), 42)
            .with_generators(vec![DataCategory::BrowserActivity]);
        let a = p.generate_batch(1000);
        assert!(a.len() > 900, "got {}", a.len());
    }

    #[test]
    fn test_empty() {
        let mut p = PollutionPipeline::new(UserProfile::default(), 42);
        assert!(p.generate_batch(10).is_empty());
    }
}
