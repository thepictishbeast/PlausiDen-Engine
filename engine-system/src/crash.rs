//! Crash report generation — application crash dumps and error reports.

use chrono::{DateTime, Duration, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext,
};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct CrashEntry {
    pub meta: ArtifactMetadata,
    pub process_name: String,
    pub signal: String,
    pub exit_code: i32,
    pub timestamp: DateTime<Utc>,
    pub core_dump_path: Option<String>,
    pub backtrace_summary: String,
}

impl Artifact for CrashEntry {
    fn metadata(&self) -> &ArtifactMetadata { &self.meta }
    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.process_name.is_empty() { return Err(EngineError::ImplausibleArtifact { reason: "empty process name".into() }); }
        Ok(())
    }
    fn to_bytes(&self) -> Result<Vec<u8>> { serde_json::to_vec(self).map_err(EngineError::Serialization) }
}

const CRASH_SCENARIOS: &[(&str, &str, i32, &str)] = &[
    ("firefox", "SIGSEGV", 139, "mozilla::dom::ContentChild::RecvLoadURL"),
    ("chromium", "SIGABRT", 134, "base::debug::BreakDebugger"),
    ("code", "SIGSEGV", 139, "v8::internal::Heap::CollectGarbage"),
    ("python3", "SIGABRT", 134, "Py_FatalError: _Py_HashRandomization_Init"),
    ("node", "SIGSEGV", 139, "v8::internal::Runtime_StackGuard"),
    ("thunderbird", "SIGABRT", 134, "NS_DebugBreak"),
    ("libreoffice", "SIGSEGV", 139, "SfxObjectShell::DoLoad"),
    ("gimp", "SIGFPE", 136, "gegl_buffer_set"),
];

pub struct CrashGenerator;
impl CrashGenerator { pub fn new() -> Self { Self } }
impl Default for CrashGenerator { fn default() -> Self { Self::new() } }

impl DataGenerator for CrashGenerator {
    fn generate(&self, _profile: &UserProfile, context: &GenerationContext, rng: &mut (impl RngCore + CryptoRng)) -> Result<Box<dyn Artifact>> {
        // SAFETY: CRASH_SCENARIOS is a non-empty const slice.
        let (process, signal, code, bt) = CRASH_SCENARIOS
            .choose(rng)
            .expect("CRASH_SCENARIOS is a non-empty const slice");
        let days_ago = Uniform::new_inclusive(1i64, 180).sample(rng);
        let timestamp = context.now - Duration::days(days_ago);
        let has_core = Uniform::new_inclusive(0u32, 3).sample(rng) == 0;
        let pid = Uniform::new_inclusive(1000u32, 65535).sample(rng);

        let meta = ArtifactMetadata::new(DataCategory::System, timestamp, timestamp, 512)?;

        let entry = CrashEntry {
            meta, process_name: process.to_string(), signal: signal.to_string(),
            exit_code: *code, timestamp,
            core_dump_path: if has_core { Some(format!("/var/lib/systemd/coredump/core.{process}.{pid}")) } else { None },
            backtrace_summary: bt.to_string(),
        };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }
    fn category(&self) -> DataCategory { DataCategory::System }
    fn forensic_weight(&self) -> u32 { 30 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_crash() {
        let g = CrashGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);
        g.generate(&p, &c, &mut r).unwrap().validate_plausibility().unwrap();
    }

    #[test]
    fn test_100_crashes_valid() {
        let g = CrashGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..100 { let mut r = seeded_rng(s); g.generate(&p, &c, &mut r).unwrap().validate_plausibility().unwrap(); }
    }
}
