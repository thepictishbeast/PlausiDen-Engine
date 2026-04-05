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
}

/// Result type alias for engine operations.
pub type Result<T> = std::result::Result<T, EngineError>;
