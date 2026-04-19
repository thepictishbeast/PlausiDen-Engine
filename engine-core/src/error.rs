//! Error types for the PlausiDen engine core.

use thiserror::Error;

/// Errors that can occur during data generation.
#[derive(Debug, Error)]
pub enum EngineError {
    /// The generated artifact failed plausibility validation.
    #[error("artifact failed plausibility check: {reason}")]
    ImplausibleArtifact { reason: String },

    /// A required field in the user profile is missing or invalid.
    #[error("invalid user profile: {field} — {reason}")]
    InvalidProfile { field: String, reason: String },

    /// Serialization or deserialization failed.
    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    /// The generation context is invalid for this generator.
    #[error("invalid generation context: {0}")]
    InvalidContext(String),

    /// Resource limits exceeded.
    #[error("resource limit exceeded: {resource} (limit: {limit}, requested: {requested})")]
    ResourceLimitExceeded {
        resource: String,
        limit: u64,
        requested: u64,
    },

    /// Scheduling error.
    #[error("scheduling error: {0}")]
    Schedule(String),

    /// Configuration error.
    #[error("configuration error: {0}")]
    Config(String),

    /// Failed to mlock memory for secret material — typically RLIMIT_MEMLOCK
    /// exhausted or the process lacks CAP_IPC_LOCK on Linux.
    #[error("mlock failed: {0}")]
    MlockFailed(#[source] std::io::Error),
}

/// Result type alias for engine operations.
pub type Result<T> = std::result::Result<T, EngineError>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn mlock_failed_formats_with_source() {
        let e = EngineError::MlockFailed(io::Error::new(
            io::ErrorKind::OutOfMemory,
            "cannot allocate memory (RLIMIT_MEMLOCK exhausted)",
        ));
        let s = format!("{e}");
        assert!(s.starts_with("mlock failed:"), "got: {s}");
        assert!(
            s.contains("cannot allocate memory"),
            "wrapped io error lost: {s}"
        );
        // Source chain should point at the inner io::Error.
        use std::error::Error;
        let src = e.source().expect("MlockFailed should have a source");
        assert!(src.to_string().contains("cannot allocate memory"));
    }

    #[test]
    fn implausible_artifact_includes_reason() {
        let e = EngineError::ImplausibleArtifact {
            reason: "visit count is zero".into(),
        };
        assert_eq!(
            format!("{e}"),
            "artifact failed plausibility check: visit count is zero"
        );
    }

    #[test]
    fn invalid_profile_includes_field_and_reason() {
        let e = EngineError::InvalidProfile {
            field: "interests".into(),
            reason: "empty".into(),
        };
        assert!(format!("{e}").contains("interests"));
        assert!(format!("{e}").contains("empty"));
    }

    #[test]
    fn serialization_from_serde_error() {
        // Serialization error auto-converts via #[from]
        let bad_json: std::result::Result<serde_json::Value, _> = serde_json::from_str("{not json");
        let err = bad_json.unwrap_err();
        let engine_err: EngineError = err.into();
        assert!(matches!(engine_err, EngineError::Serialization(_)));
    }

    #[test]
    fn resource_limit_exceeded_formats_all_fields() {
        let e = EngineError::ResourceLimitExceeded {
            resource: "keys".into(),
            limit: 16,
            requested: 17,
        };
        let s = format!("{e}");
        assert!(s.contains("keys"));
        assert!(s.contains("16"));
        assert!(s.contains("17"));
    }
}
