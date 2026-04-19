//! # PlausiDen Engine Pipeline
//!
//! End-to-end pollution pipeline connecting engine data generation to
//! inject-ready output. This crate orchestrates:
//!
//! 1. Generator initialization based on selected [`DataCategory`] values
//! 2. Organic timing via [`OrganicScheduler`] (no regular intervals)
//! 3. Defense-in-depth validation via [`paranoia::deep_validate_artifact`]
//! 4. Metadata stripping (removes `meta` field so output is injection-safe)
//! 5. Conversion to the JSON format that `plausiden-inject` expects
//!
//! # Example
//!
//! ```no_run
//! use engine_pipeline::{PollutionPipeline, InjectionTarget};
//! use engine_core::profile::UserProfile;
//! use engine_core::traits::DataCategory;
//!
//! let profile = UserProfile::default();
//! let mut pipeline = PollutionPipeline::new(profile, 42)
//!     .with_generators(vec![DataCategory::BrowserActivity]);
//!
//! let artifacts = pipeline.generate_batch(10);
//! assert_eq!(artifacts.len(), 10);
//!
//! let injectable = pipeline.generate_injectable(5, InjectionTarget::FirefoxHistory);
//! assert_eq!(injectable.len(), 5);
//! ```

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use engine_browser::{CookieGenerator, HistoryGenerator, SearchGenerator};
use engine_core::error::{EngineError, Result};
use engine_core::paranoia;
use engine_core::profile::UserProfile;
use engine_core::schedule::OrganicScheduler;
use engine_core::traits::{Artifact, DataCategory, DataGenerator, GenerationContext};
use engine_fs::files::RecentDocumentsGenerator as FileGenerator;
use engine_network::dns::DnsQueryGenerator as DnsGenerator;
use engine_social::activity::ActivityGenerator as SocialGenerator;
use engine_system::logs::LogGenerator;
use engine_system::processes::ProcessGenerator;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Enum dispatch — covers ALL generator categories
// ---------------------------------------------------------------------------

enum AnyGenerator {
    History(HistoryGenerator),
    Cookie(CookieGenerator),
    Search(SearchGenerator),
    File(FileGenerator),
    Dns(DnsGenerator),
    Log(LogGenerator),
    Process(ProcessGenerator),
    Social(SocialGenerator),
}

impl AnyGenerator {
    fn generate_artifact(
        &self,
        profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut ChaCha20Rng,
    ) -> Result<Box<dyn Artifact>> {
        match self {
            Self::History(g) => g.generate(profile, context, rng),
            Self::Cookie(g) => g.generate(profile, context, rng),
            Self::Search(g) => g.generate(profile, context, rng),
            Self::File(g) => g.generate(profile, context, rng),
            Self::Dns(g) => g.generate(profile, context, rng),
            Self::Log(g) => g.generate(profile, context, rng),
            Self::Process(g) => g.generate(profile, context, rng),
            Self::Social(g) => g.generate(profile, context, rng),
        }
    }

    fn category(&self) -> DataCategory {
        match self {
            Self::History(g) => g.category(),
            Self::Cookie(g) => g.category(),
            Self::Search(g) => g.category(),
            Self::File(g) => g.category(),
            Self::Dns(g) => g.category(),
            Self::Log(g) => g.category(),
            Self::Process(g) => g.category(),
            Self::Social(g) => g.category(),
        }
    }
}

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A generated artifact ready for optional sanitization and injection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneratedArtifact {
    /// Data category this artifact belongs to.
    pub category: DataCategory,
    /// Serialized artifact bytes (JSON, with `meta` field stripped).
    pub bytes: Vec<u8>,
    /// Simulated timestamp for this artifact.
    pub timestamp: DateTime<Utc>,
}

/// Target browser database for injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InjectionTarget {
    /// Firefox `places.sqlite` history table.
    FirefoxHistory,
    /// Firefox `cookies.sqlite` cookie table.
    FirefoxCookies,
    /// Chrome `History` SQLite database.
    ChromeHistory,
    /// Chrome `Cookies` SQLite database.
    ChromeCookies,
}

/// Summary report for a pipeline session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionReport {
    /// Total number of artifacts successfully generated.
    pub total_generated: usize,
    /// Artifact counts broken down by category name.
    pub by_category: HashMap<String, usize>,
    /// Duration of the session in seconds.
    pub duration_secs: u64,
    /// Number of artifacts that failed paranoia validation.
    pub paranoia_failures: usize,
}

// ---------------------------------------------------------------------------
// Pipeline
// ---------------------------------------------------------------------------

/// Orchestrates data generation with organic timing, paranoia validation,
/// and metadata stripping.
pub struct PollutionPipeline {
    /// User behavioral profile driving generation patterns.
    profile: UserProfile,
    /// Organic timing scheduler (circadian rhythm, jitter).
    scheduler: OrganicScheduler,
    /// Active data generators (one per sub-type).
    generators: Vec<AnyGenerator>,
    /// Deterministic, cryptographically secure RNG.
    rng: ChaCha20Rng,
}

impl PollutionPipeline {
    /// Create a new pipeline with the given profile and deterministic seed.
    ///
    /// The pipeline starts with no generators; call
    /// [`with_generators`](Self::with_generators) to enable data categories.
    pub fn new(profile: UserProfile, seed: u64) -> Self {
        let scheduler =
            OrganicScheduler::new(profile.activity_schedule.clone(), profile.risk_level);
        Self {
            profile,
            scheduler,
            generators: Vec::new(),
            rng: ChaCha20Rng::seed_from_u64(seed),
        }
    }

    /// Enable generators for the specified data categories.
    ///
    /// Currently supports [`DataCategory::BrowserActivity`] (history,
    /// cookies, searches). Other categories will be added as their
    /// engine crates move beyond scaffold status.
    pub fn with_generators(mut self, categories: Vec<DataCategory>) -> Self {
        for category in &categories {
            match category {
                DataCategory::BrowserActivity => {
                    self.generators
                        .push(AnyGenerator::History(HistoryGenerator::new()));
                    self.generators
                        .push(AnyGenerator::Cookie(CookieGenerator::new()));
                    self.generators
                        .push(AnyGenerator::Search(SearchGenerator::new()));
                }
                DataCategory::FileSystem => {
                    self.generators
                        .push(AnyGenerator::File(FileGenerator::new()));
                }
                DataCategory::Network => {
                    self.generators.push(AnyGenerator::Dns(DnsGenerator::new()));
                }
                DataCategory::System => {
                    self.generators.push(AnyGenerator::Log(LogGenerator::new()));
                    self.generators
                        .push(AnyGenerator::Process(ProcessGenerator::new()));
                }
                DataCategory::Social => {
                    self.generators
                        .push(AnyGenerator::Social(SocialGenerator::new()));
                }
                other => {
                    warn!(category = ?other, "category generators coming soon -- skipping");
                }
            }
        }
        self
    }

    /// Generate a batch of artifacts with organic timing.
    ///
    /// Timestamps are spread backward from the current wall-clock time using
    /// organic intervals, so all artifacts appear to have been created in the
    /// recent past. Each artifact is validated through
    /// [`paranoia::deep_validate_artifact`] before inclusion. Failed
    /// artifacts are logged and skipped.
    pub fn generate_batch(&mut self, count: usize) -> Vec<GeneratedArtifact> {
        let mut artifacts = Vec::with_capacity(count);

        if self.generators.is_empty() {
            warn!("no generators configured -- returning empty batch");
            return artifacts;
        }

        // Pre-compute organic intervals, then spread timestamps backward
        // from "now". This ensures all generated timestamps are in the
        // recent past, passing paranoia validation (which rejects
        // timestamps >1h in the future).
        let now = Utc::now();
        let mut interval_secs = Vec::with_capacity(count);
        let mut cursor = now;
        for _ in 0..count {
            let next = self.scheduler.next_timestamp(cursor, &mut self.rng);
            let delta = (next - cursor).num_seconds();
            interval_secs.push(delta);
            cursor = next;
        }

        // Total time span -- all intervals summed
        let total_span: i64 = interval_secs.iter().sum();
        // Start from (now - total_span) and walk forward
        let mut artifact_time = now - chrono::Duration::seconds(total_span);

        for (i, &interval) in interval_secs.iter().enumerate() {
            artifact_time += chrono::Duration::seconds(interval);

            // Round-robin across generators for variety
            let generator_idx = i % self.generators.len();
            let generator = &self.generators[generator_idx];

            let context = GenerationContext {
                now: artifact_time,
                session_artifact_count: i as u64,
                total_artifact_count: i as u64,
            };

            match generator.generate_artifact(&self.profile, &context, &mut self.rng) {
                Ok(artifact) => {
                    // Defense-in-depth: paranoia validation on every output
                    if let Err(e) = paranoia::deep_validate_artifact(artifact.as_ref()) {
                        warn!(
                            index = i,
                            error = %e,
                            "artifact failed paranoia validation -- skipping"
                        );
                        continue;
                    }

                    match artifact.to_bytes() {
                        Ok(raw_bytes) => {
                            let timestamp = artifact.metadata().created_at;
                            let category = generator.category();

                            // Strip internal metadata before storing
                            let bytes = strip_meta_field(&raw_bytes).unwrap_or(raw_bytes);

                            artifacts.push(GeneratedArtifact {
                                category,
                                bytes,
                                timestamp,
                            });
                        }
                        Err(e) => {
                            warn!(
                                index = i,
                                error = %e,
                                "artifact serialization failed -- skipping"
                            );
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        index = i,
                        error = %e,
                        "generation failed -- skipping"
                    );
                }
            }
        }

        debug!(
            count = artifacts.len(),
            requested = count,
            "batch generation complete"
        );
        artifacts
    }

    /// Generate artifacts as sanitized JSON ready for injection.
    ///
    /// The output bytes have the `meta` field stripped so that internal
    /// engine metadata never reaches the target database. The result is
    /// the exact JSON that `plausiden-inject` expects.
    pub fn generate_injectable(&mut self, count: usize, target: InjectionTarget) -> Vec<Vec<u8>> {
        let category_filter = target_to_category(target);
        let raw = self.generate_batch(count);

        raw.into_iter()
            .filter(|a| a.category == category_filter)
            .map(|a| a.bytes)
            .collect()
    }

    /// Run a timed session, generating artifacts at organic intervals
    /// until `duration_secs` of simulated time elapses.
    ///
    /// Returns a [`SessionReport`] summarizing what was generated.
    ///
    /// REGRESSION-GUARD: an earlier version anchored every artifact's
    /// `context.now` at the session-start wall-clock time, then walked
    /// `current_time` forward into the simulated future. The result
    /// was that ALL generated artifacts in a session had identical
    /// timestamps (start time), and the "advance simulated time"
    /// step was decorative — it controlled the loop bound but
    /// produced no per-artifact effect. The original workaround was
    /// "future timestamps are rejected by paranoia, so anchor at
    /// start." The correct fix is to walk THROUGH PAST wall-clock
    /// time: start = now - duration, end = now. Each artifact then
    /// gets a unique past timestamp from current_time, the paranoia
    /// future-check is never triggered, and the simulated session
    /// actually has the spread it claims to.
    pub fn run_session(&mut self, duration_secs: u64) -> SessionReport {
        let now = Utc::now();
        let start = now - chrono::Duration::seconds(duration_secs as i64);
        let end = now;

        let mut total_generated: usize = 0;
        let mut by_category: HashMap<String, usize> = HashMap::new();
        let mut paranoia_failures: usize = 0;

        if self.generators.is_empty() {
            warn!("no generators configured -- session produces nothing");
            return SessionReport {
                total_generated: 0,
                by_category,
                duration_secs,
                paranoia_failures: 0,
            };
        }

        let mut current_time = start;
        let mut iteration: usize = 0;

        while current_time < end {
            let generator_idx = iteration % self.generators.len();
            let generator = &self.generators[generator_idx];

            // Anchor each artifact at the current simulated time. The
            // walk through PAST wall-clock time (start = now - duration,
            // end = now) keeps every timestamp safely behind the
            // paranoia "1h in the future" cutoff while still giving
            // every artifact a distinct simulated timestamp.
            let context = GenerationContext {
                now: current_time,
                session_artifact_count: total_generated as u64,
                total_artifact_count: total_generated as u64,
            };

            match generator.generate_artifact(&self.profile, &context, &mut self.rng) {
                Ok(artifact) => {
                    if let Err(e) = paranoia::deep_validate_artifact(artifact.as_ref()) {
                        debug!(
                            error = %e,
                            "paranoia failure in session"
                        );
                        paranoia_failures += 1;
                    } else {
                        let cat_name = format!("{:?}", generator.category());
                        *by_category.entry(cat_name).or_insert(0) += 1;
                        total_generated += 1;
                    }
                }
                Err(e) => {
                    debug!(error = %e, "generation error in session");
                    paranoia_failures += 1;
                }
            }

            // Advance simulated time with organic timing
            current_time = self.scheduler.next_timestamp(current_time, &mut self.rng);
            iteration += 1;
        }

        info!(
            total = total_generated,
            failures = paranoia_failures,
            duration_secs = duration_secs,
            "session complete"
        );

        SessionReport {
            total_generated,
            by_category,
            duration_secs,
            paranoia_failures,
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map an [`InjectionTarget`] to the [`DataCategory`] it consumes.
fn target_to_category(target: InjectionTarget) -> DataCategory {
    match target {
        InjectionTarget::FirefoxHistory
        | InjectionTarget::FirefoxCookies
        | InjectionTarget::ChromeHistory
        | InjectionTarget::ChromeCookies => DataCategory::BrowserActivity,
    }
}

/// Strip the `meta` field from JSON artifact bytes.
///
/// This mirrors the sanitization that `inject-core`'s sanitizer performs.
/// By doing it here in the pipeline, we guarantee the output is
/// injection-safe before it ever leaves the engine boundary.
fn strip_meta_field(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut value: serde_json::Value =
        serde_json::from_slice(bytes).map_err(EngineError::Serialization)?;

    if let serde_json::Value::Object(ref mut map) = value {
        map.remove("meta");
    }

    serde_json::to_vec(&value).map_err(EngineError::Serialization)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::profile::UserProfile;
    use engine_core::traits::DataCategory;
    use std::collections::HashSet;

    /// Helper: build a pipeline with browser generators and a deterministic seed.
    fn browser_pipeline(seed: u64) -> PollutionPipeline {
        PollutionPipeline::new(UserProfile::default(), seed)
            .with_generators(vec![DataCategory::BrowserActivity])
    }

    // -----------------------------------------------------------------
    // Core functionality
    // -----------------------------------------------------------------

    #[test]
    fn test_pipeline_generates_artifacts_for_all_browser_categories() {
        let mut pipeline = browser_pipeline(42);
        let artifacts = pipeline.generate_batch(30);

        // Should have generated all 30
        assert_eq!(
            artifacts.len(),
            30,
            "pipeline must produce exactly the requested number of artifacts"
        );

        // All should be BrowserActivity (since we only enabled that)
        for artifact in &artifacts {
            assert_eq!(
                artifact.category,
                DataCategory::BrowserActivity,
                "all artifacts must be BrowserActivity"
            );
        }
    }

    #[test]
    fn test_paranoia_validation_passes_on_all_outputs() {
        let mut pipeline = browser_pipeline(42);
        let batch = pipeline.generate_batch(50);

        assert_eq!(batch.len(), 50, "all 50 artifacts must pass paranoia");

        for (i, artifact) in batch.iter().enumerate() {
            // Parse back to verify the bytes are valid JSON
            let value: serde_json::Value = serde_json::from_slice(&artifact.bytes)
                .unwrap_or_else(|e| panic!("artifact {i} is not valid JSON: {e}"));

            // Verify it is a non-empty JSON object
            assert!(value.is_object(), "artifact {i} must be a JSON object");
            assert!(
                !value.as_object().unwrap().is_empty(),
                "artifact {i} must not be empty"
            );
        }
    }

    #[test]
    fn test_organic_timing_produces_variable_intervals() {
        let mut pipeline = browser_pipeline(42);
        let artifacts = pipeline.generate_batch(20);

        assert!(
            artifacts.len() >= 2,
            "need at least 2 artifacts to compare intervals"
        );

        let timestamps: Vec<i64> = artifacts.iter().map(|a| a.timestamp.timestamp()).collect();
        let intervals: Vec<i64> = timestamps.windows(2).map(|w| w[1] - w[0]).collect();

        // Intervals should not all be identical (organic jitter)
        let unique_intervals: HashSet<i64> = intervals.iter().copied().collect();
        assert!(
            unique_intervals.len() > 1,
            "organic timing must produce variable intervals, got {:?}",
            intervals
        );
    }

    #[test]
    fn test_injectable_output_is_valid_json_without_meta() {
        let mut pipeline = browser_pipeline(42);
        let injectable = pipeline.generate_injectable(20, InjectionTarget::FirefoxHistory);

        assert_eq!(injectable.len(), 20, "must produce 20 injectable outputs");

        for (i, bytes) in injectable.iter().enumerate() {
            let value: serde_json::Value = serde_json::from_slice(bytes)
                .unwrap_or_else(|e| panic!("injectable {i} is not valid JSON: {e}"));

            // The "meta" field must be stripped
            assert!(
                value.get("meta").is_none(),
                "injectable {i} must not contain 'meta' field"
            );

            // Should still have real payload fields
            assert!(value.is_object(), "injectable {i} must be a JSON object");
            let obj = value.as_object().unwrap();
            assert!(
                !obj.is_empty(),
                "injectable {i} must not be an empty object"
            );
        }
    }

    #[test]
    fn test_session_report_counts_match() {
        let mut pipeline = browser_pipeline(42);

        // Run a short simulated session (300 simulated seconds)
        let report = pipeline.run_session(300);

        // Total must equal the sum of per-category counts
        let sum: usize = report.by_category.values().sum();
        assert_eq!(
            report.total_generated, sum,
            "total_generated ({}) must equal sum of by_category ({})",
            report.total_generated, sum
        );

        // Duration must match requested
        assert_eq!(report.duration_secs, 300);

        // Should have generated at least some artifacts in 300s
        // (default Medium risk = ~2min base interval, so 300s should get several)
        assert!(
            report.total_generated > 0,
            "300s session must generate at least one artifact"
        );
    }

    #[test]
    fn test_stress_1000_artifacts() {
        let mut pipeline = browser_pipeline(12345);
        let artifacts = pipeline.generate_batch(1000);

        // All 1000 should succeed (no paranoia failures expected from
        // well-implemented browser generators)
        assert_eq!(
            artifacts.len(),
            1000,
            "stress test: expected 1000 artifacts, got {}",
            artifacts.len()
        );

        // Every artifact must be valid JSON with no meta field
        for (i, artifact) in artifacts.iter().enumerate() {
            let value: serde_json::Value = serde_json::from_slice(&artifact.bytes)
                .unwrap_or_else(|e| panic!("artifact {i} failed JSON parse: {e}"));
            assert!(
                value.get("meta").is_none(),
                "artifact {i} must not contain meta field"
            );
        }
    }

    // -----------------------------------------------------------------
    // Edge cases
    // -----------------------------------------------------------------

    #[test]
    fn test_empty_generators_produces_empty_batch() {
        let mut pipeline = PollutionPipeline::new(UserProfile::default(), 42);
        // No .with_generators() call
        let artifacts = pipeline.generate_batch(10);
        assert!(artifacts.is_empty(), "no generators = no artifacts");
    }

    #[test]
    fn test_empty_generators_session_report() {
        let mut pipeline = PollutionPipeline::new(UserProfile::default(), 42);
        let report = pipeline.run_session(60);
        assert_eq!(report.total_generated, 0);
        assert_eq!(report.paranoia_failures, 0);
        assert_eq!(report.duration_secs, 60);
    }

    // REGRESSION-GUARD: an earlier run_session pinned every generated
    // artifact's timestamp at the wall-clock session start, so an N-
    // artifact session produced N artifacts with identical
    // created_at. The simulated-time advance was decorative.
    //
    // This test verifies the fix indirectly: it runs a 600-second
    // session, then asserts that the report's by_category counts add
    // up to total_generated (proves at least the loop ran), AND
    // that the session generated multiple artifacts. The deeper
    // timestamp-distinctness check is hard to do without exposing
    // generator timestamps through the session API; instead the
    // session integration test exercises the new code path and the
    // SHIP fix is documented in the function comment.
    #[test]
    fn test_session_walks_through_past_time() {
        let before = Utc::now();
        let mut pipeline = browser_pipeline(42);
        let report = pipeline.run_session(600);
        let after = Utc::now();

        // The session is anchored at (now - 600s, now), so it must
        // have completed at or before the wall-clock `after`.
        // Sanity check that the call returned promptly (real test).
        let elapsed = (after - before).num_seconds();
        assert!(elapsed < 30, "session should run quickly, took {elapsed}s",);

        assert_eq!(
            report.total_generated,
            report.by_category.values().sum::<usize>(),
        );
        assert!(
            report.total_generated >= 2,
            "600s session should produce multiple artifacts",
        );
    }

    #[test]
    fn test_different_seeds_produce_different_output() {
        let mut p1 = browser_pipeline(111);
        let mut p2 = browser_pipeline(222);

        let batch1 = p1.generate_batch(5);
        let batch2 = p2.generate_batch(5);

        // With different seeds, at least some artifacts should differ
        let differ = batch1
            .iter()
            .zip(batch2.iter())
            .any(|(a, b)| a.bytes != b.bytes);
        assert!(differ, "different seeds must produce different artifacts");
    }

    #[test]
    fn test_injection_targets_all_map_to_browser() {
        let targets = [
            InjectionTarget::FirefoxHistory,
            InjectionTarget::FirefoxCookies,
            InjectionTarget::ChromeHistory,
            InjectionTarget::ChromeCookies,
        ];
        for target in targets {
            assert_eq!(
                target_to_category(target),
                DataCategory::BrowserActivity,
                "{:?} must map to BrowserActivity",
                target,
            );
        }
    }

    #[test]
    fn test_strip_meta_field_preserves_payload() {
        let input = serde_json::json!({
            "meta": {"id": "should-be-removed", "category": "BrowserActivity"},
            "url": "https://example.org/article",
            "title": "Test Article",
            "visit_count": 3,
        });
        let bytes = serde_json::to_vec(&input).unwrap();
        let stripped = strip_meta_field(&bytes).unwrap();
        let output: serde_json::Value = serde_json::from_slice(&stripped).unwrap();

        assert!(output.get("meta").is_none(), "meta must be removed");
        assert_eq!(output["url"], "https://example.org/article");
        assert_eq!(output["title"], "Test Article");
        assert_eq!(output["visit_count"], 3);
    }

    #[test]
    fn test_strip_meta_field_handles_no_meta() {
        let input = serde_json::json!({"url": "https://test.com"});
        let bytes = serde_json::to_vec(&input).unwrap();
        let stripped = strip_meta_field(&bytes).unwrap();
        let output: serde_json::Value = serde_json::from_slice(&stripped).unwrap();
        assert_eq!(output["url"], "https://test.com");
    }

    #[test]
    fn test_injectable_batch_count_matches_request() {
        let mut pipeline = browser_pipeline(42);
        // Request 30 -- all generators produce BrowserActivity, so all
        // should pass the category filter.
        let injectable = pipeline.generate_injectable(30, InjectionTarget::ChromeCookies);
        assert_eq!(
            injectable.len(),
            30,
            "all 30 requested artifacts should pass the category filter"
        );
    }

    #[test]
    fn test_generated_artifact_timestamps_are_plausible() {
        let mut pipeline = browser_pipeline(42);
        let artifacts = pipeline.generate_batch(20);
        let now = Utc::now();

        for (i, artifact) in artifacts.iter().enumerate() {
            // Timestamp should be recent (within a day, accounting for
            // backward spread and generator jitter)
            let age = now.signed_duration_since(artifact.timestamp);
            assert!(
                age.num_hours().abs() < 24,
                "artifact {i} timestamp {ts} is too far from now ({now})",
                ts = artifact.timestamp,
            );
        }
    }
}
