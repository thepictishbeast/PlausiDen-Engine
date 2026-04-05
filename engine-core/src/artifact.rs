//! Artifact metadata and common artifact implementations.

use crate::error::{EngineError, Result};
use crate::traits::{Artifact, ArtifactMetadata, DataCategory};
use serde::Serialize;

impl ArtifactMetadata {
    /// Create new metadata with basic validation.
    pub fn new(
        category: DataCategory,
        created_at: chrono::DateTime<chrono::Utc>,
        modified_at: chrono::DateTime<chrono::Utc>,
        size_bytes: u64,
    ) -> Result<Self> {
        if modified_at < created_at {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!(
                    "modification time ({modified_at}) before creation time ({created_at})"
                ),
            });
        }
        Ok(Self {
            id: uuid::Uuid::new_v4(),
            category,
            created_at,
            modified_at,
            size_bytes,
        })
    }

    /// Validate that timestamps are forensically plausible.
    pub fn validate_timestamps(&self) -> Result<()> {
        if self.modified_at < self.created_at {
            return Err(EngineError::ImplausibleArtifact {
                reason: "modification time before creation time".to_string(),
            });
        }

        // Reject timestamps in the far future
        let max_future = chrono::Utc::now() + chrono::Duration::hours(24);
        if self.created_at > max_future {
            return Err(EngineError::ImplausibleArtifact {
                reason: "creation time too far in the future".to_string(),
            });
        }

        Ok(())
    }
}

/// A generic artifact wrapping any serializable data.
///
/// Used when a generator produces data that doesn't need a specialized artifact type.
#[derive(Debug, Clone, Serialize)]
pub struct GenericArtifact {
    /// Artifact metadata.
    pub meta: ArtifactMetadata,
    /// The artifact payload as JSON value.
    pub payload: serde_json::Value,
}

impl Artifact for GenericArtifact {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}
