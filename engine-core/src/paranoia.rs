//! Paranoia module — defense-in-depth validation layer.
//!
//! Every assumption is verified. Every invariant is checked at runtime.
//! Every output is validated before emission. This module exists because
//! we assume our own code is buggy.
//!
//! Philosophy: if you can't find the bug, make the bug irrelevant.
//! If you can't eliminate the vulnerability, make exploitation impossible
//! even if the vulnerability exists.

use crate::error::{EngineError, Result};
use crate::traits::{Artifact, ArtifactMetadata, DataCategory};

/// Validate an artifact through multiple independent checks.
///
/// This is NOT the same as `validate_plausibility()` — that checks
/// forensic plausibility. This checks internal consistency, memory safety
/// invariants, and catches bugs in the generator itself.
///
/// Check order matters for adversarial inputs. `validate_size_bounds`
/// MUST run before `validate_serialization_integrity` because the
/// latter does a full `serde_json::from_slice::<Value>` parse — which
/// allocates an unbounded-size tree of `Value` nodes. A 1 GB
/// adversarial artifact would allocate 2–3 GB before the 10 MB size
/// check fires if the checks ran in the other order.
pub fn deep_validate_artifact(artifact: &dyn Artifact) -> Result<()> {
    let meta = artifact.metadata();

    // 1. Timestamp sanity (redundant with plausibility check — intentionally duplicated)
    validate_timestamps(meta)?;

    // 2. Produce the serialized bytes ONCE.
    let bytes = artifact.to_bytes()?;

    // 3. Size sanity FIRST — bound the allocation before the JSON
    //    parser gets a chance to walk a hostile payload. See
    //    function-level doc above for the DOS rationale.
    validate_size_bounds(&bytes, meta)?;

    // 4. Serialization roundtrip — now safe to parse because size
    //    is capped at 10 MB by the previous step.
    validate_serialization_integrity(&bytes)?;

    // 5. Category consistency
    validate_category(meta)?;

    Ok(())
}

/// Timestamps: defense-in-depth checks beyond what plausibility catches.
fn validate_timestamps(meta: &ArtifactMetadata) -> Result<()> {
    // Modification must be >= creation (also checked in plausibility, but we don't trust that check)
    if meta.modified_at < meta.created_at {
        return Err(EngineError::ImplausibleArtifact {
            reason: "[PARANOIA] modified_at < created_at — generator bug".to_string(),
        });
    }

    // No timestamps before 2020-01-01 — anything older is certainly wrong
    let min_timestamp = chrono::NaiveDate::from_ymd_opt(2020, 1, 1)
        .unwrap() // SAFETY: 2020-01-01 is a valid calendar date
        .and_hms_opt(0, 0, 0)
        .unwrap() // SAFETY: 00:00:00 is a valid time
        .and_utc();

    if meta.created_at < min_timestamp {
        return Err(EngineError::ImplausibleArtifact {
            reason: format!(
                "[PARANOIA] created_at {} is before 2020 — generator bug or clock issue",
                meta.created_at
            ),
        });
    }

    // No timestamps more than 1 hour in the future
    let max_future = chrono::Utc::now() + chrono::Duration::hours(1);
    if meta.created_at > max_future {
        return Err(EngineError::ImplausibleArtifact {
            reason: format!(
                "[PARANOIA] created_at {} is >1h in the future — clock drift or generator bug",
                meta.created_at
            ),
        });
    }

    Ok(())
}

/// Serialization integrity: the bytes must be valid JSON (our canonical format).
fn validate_serialization_integrity(bytes: &[u8]) -> Result<()> {
    // Must be valid UTF-8
    if std::str::from_utf8(bytes).is_err() {
        return Err(EngineError::ImplausibleArtifact {
            reason: "[PARANOIA] serialized artifact is not valid UTF-8".to_string(),
        });
    }

    // Must be valid JSON
    if serde_json::from_slice::<serde_json::Value>(bytes).is_err() {
        return Err(EngineError::ImplausibleArtifact {
            reason: "[PARANOIA] serialized artifact is not valid JSON".to_string(),
        });
    }

    // Must not be empty
    if bytes.is_empty() {
        return Err(EngineError::ImplausibleArtifact {
            reason: "[PARANOIA] serialized artifact is empty".to_string(),
        });
    }

    Ok(())
}

/// Size bounds: detect unbounded generation or memory corruption.
fn validate_size_bounds(bytes: &[u8], meta: &ArtifactMetadata) -> Result<()> {
    // No artifact should be larger than 10 MB
    let max_size = 10 * 1024 * 1024;
    if bytes.len() > max_size {
        return Err(EngineError::ImplausibleArtifact {
            reason: format!(
                "[PARANOIA] artifact size {} exceeds 10 MB limit — unbounded generation",
                bytes.len()
            ),
        });
    }

    // Metadata size_bytes should roughly match actual size (within 10x)
    if meta.size_bytes > 0 {
        let ratio = bytes.len() as f64 / meta.size_bytes as f64;
        if !(0.1..=10.0).contains(&ratio) {
            tracing::warn!(
                "[PARANOIA] size mismatch: metadata says {} bytes, actual {} bytes (ratio {:.1})",
                meta.size_bytes,
                bytes.len(),
                ratio,
            );
        }
    }

    Ok(())
}

/// Category sanity check.
fn validate_category(meta: &ArtifactMetadata) -> Result<()> {
    // Verify the category has a valid forensic weight
    let weight = meta.category.default_forensic_weight();
    if weight == 0 {
        return Err(EngineError::ImplausibleArtifact {
            reason: "[PARANOIA] artifact category has zero forensic weight".to_string(),
        });
    }

    Ok(())
}

/// Audit trail — log every generation event for post-incident analysis.
///
/// These logs NEVER contain artifact content. Only metadata:
/// category, size, timestamp, generation duration.
pub fn audit_generation(
    category: DataCategory,
    artifact_count: u32,
    duration_us: u64,
    success: bool,
) {
    if success {
        tracing::info!(
            target: "plausiden::audit",
            category = ?category,
            count = artifact_count,
            duration_us = duration_us,
            "generation complete"
        );
    } else {
        tracing::error!(
            target: "plausiden::audit",
            category = ?category,
            count = artifact_count,
            duration_us = duration_us,
            "generation FAILED"
        );
    }
}

/// Canary value — detect memory corruption.
///
/// Placed at the boundaries of sensitive data structures.
/// If the canary value changes, memory was corrupted.
#[derive(Debug)]
pub struct MemoryCanary {
    value: u64,
}

impl MemoryCanary {
    const EXPECTED: u64 = 0xDEAD_BEEF_CAFE_BABE;

    pub fn new() -> Self {
        Self {
            value: Self::EXPECTED,
        }
    }

    /// Check if the canary is intact.
    pub fn verify(&self) -> bool {
        self.value == Self::EXPECTED
    }

    /// Panic if the canary was corrupted.
    pub fn assert_intact(&self) {
        if !self.verify() {
            // This is the one place we intentionally panic —
            // memory corruption is unrecoverable.
            panic!(
                "[PARANOIA] Memory canary corrupted: expected 0x{:X}, found 0x{:X}. \
                 Possible buffer overflow or use-after-free.",
                Self::EXPECTED,
                self.value,
            );
        }
    }
}

impl Default for MemoryCanary {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canary_intact() {
        let canary = MemoryCanary::new();
        assert!(canary.verify());
    }

    #[test]
    fn test_canary_detects_corruption() {
        let mut canary = MemoryCanary::new();
        canary.value = 0; // Simulate corruption
        assert!(!canary.verify());
    }

    #[test]
    fn test_serialization_integrity_rejects_invalid_utf8() {
        let bad_bytes = vec![0xFF, 0xFE, 0xFD];
        let result = validate_serialization_integrity(&bad_bytes);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialization_integrity_rejects_empty() {
        let result = validate_serialization_integrity(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn test_serialization_integrity_accepts_valid_json() {
        let json = br#"{"key": "value"}"#;
        let result = validate_serialization_integrity(json);
        assert!(result.is_ok());
    }

    #[test]
    fn test_size_bounds_rejects_oversized() {
        let huge = vec![0u8; 11 * 1024 * 1024]; // 11 MB
        let meta = ArtifactMetadata {
            id: uuid::Uuid::new_v4(),
            category: DataCategory::BrowserActivity,
            created_at: chrono::Utc::now(),
            modified_at: chrono::Utc::now(),
            size_bytes: 100,
        };
        let result = validate_size_bounds(&huge, &meta);
        assert!(result.is_err());
    }

    /// Mock artifact that reports a small metadata size but returns
    /// an adversarial 11 MB blob from `to_bytes`. Used to prove the
    /// size bound check fires BEFORE the JSON parser walks a hostile
    /// payload.
    struct OversizedMockArtifact {
        meta: ArtifactMetadata,
        blob: Vec<u8>,
    }

    impl Artifact for OversizedMockArtifact {
        fn metadata(&self) -> &ArtifactMetadata {
            &self.meta
        }
        fn validate_plausibility(&self) -> Result<()> {
            Ok(())
        }
        fn to_bytes(&self) -> Result<Vec<u8>> {
            Ok(self.blob.clone())
        }
    }

    // REGRESSION-GUARD: validate_size_bounds must run BEFORE
    // validate_serialization_integrity inside deep_validate_artifact.
    // Earlier version parsed the full byte buffer as JSON before
    // checking its size, letting a 1 GB adversarial artifact allocate
    // gigabytes of Value nodes before the 10 MB cap fired.
    //
    // This test constructs an 11 MB blob of *invalid* JSON bytes.
    // If size-check runs first, we get the size error (correct).
    // If JSON-check runs first, we get the JSON error (the old,
    // unsafe behaviour — the parser would have walked 11 MB already).
    #[test]
    fn test_deep_validate_size_check_runs_before_json_parse() {
        let meta = ArtifactMetadata {
            id: uuid::Uuid::new_v4(),
            category: DataCategory::BrowserActivity,
            created_at: chrono::Utc::now(),
            modified_at: chrono::Utc::now(),
            size_bytes: 100,
        };
        // 11 MB of non-JSON bytes. If JSON parse runs before size
        // check the error message will say "not valid UTF-8" or
        // "not valid JSON"; if size check runs first it will say
        // "exceeds 10 MB limit".
        let blob = vec![0xFFu8; 11 * 1024 * 1024];
        let artifact = OversizedMockArtifact { meta, blob };
        let err =
            deep_validate_artifact(&artifact).expect_err("11 MB artifact must fail validation");
        let msg = format!("{err}");
        assert!(
            msg.contains("exceeds 10 MB limit"),
            "size check did not run first: error was {msg:?}",
        );
    }

    #[test]
    fn test_deep_validate_accepts_small_valid_json_artifact() {
        struct GoodMock {
            meta: ArtifactMetadata,
        }
        impl Artifact for GoodMock {
            fn metadata(&self) -> &ArtifactMetadata {
                &self.meta
            }
            fn validate_plausibility(&self) -> Result<()> {
                Ok(())
            }
            fn to_bytes(&self) -> Result<Vec<u8>> {
                Ok(br#"{"ok":true}"#.to_vec())
            }
        }
        let meta = ArtifactMetadata {
            id: uuid::Uuid::new_v4(),
            category: DataCategory::BrowserActivity,
            created_at: chrono::Utc::now(),
            modified_at: chrono::Utc::now(),
            size_bytes: 11,
        };
        let artifact = GoodMock { meta };
        assert!(deep_validate_artifact(&artifact).is_ok());
    }
}
