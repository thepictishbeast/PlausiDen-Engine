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
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
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

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::{Duration, Utc};

    #[test]
    fn test_artifact_metadata_modified_before_created_fails() {
        let now = Utc::now();
        let earlier = now - Duration::hours(1);

        let result = ArtifactMetadata::new(
            DataCategory::BrowserActivity,
            now,     // created
            earlier, // modified — before created
            100,
        );
        assert!(result.is_err(), "modified < created must fail validation");
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("modification time"),
            "error message should mention modification time: {err_msg}"
        );
    }

    #[test]
    fn test_artifact_metadata_equal_timestamps_ok() {
        let now = Utc::now();
        let result = ArtifactMetadata::new(DataCategory::FileSystem, now, now, 42);
        assert!(result.is_ok(), "equal created and modified should be valid");
    }

    #[test]
    fn test_artifact_metadata_modified_after_created_ok() {
        let now = Utc::now();
        let later = now + Duration::seconds(30);
        let result = ArtifactMetadata::new(DataCategory::Network, now, later, 256);
        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_timestamps_rejects_far_future() {
        let far_future = Utc::now() + Duration::days(365);
        let meta = ArtifactMetadata {
            id: uuid::Uuid::new_v4(),
            category: DataCategory::BrowserActivity,
            created_at: far_future,
            modified_at: far_future,
            size_bytes: 100,
        };
        assert!(meta.validate_timestamps().is_err());
    }

    #[test]
    fn test_generic_artifact_roundtrip() {
        let now = Utc::now();
        let meta = ArtifactMetadata::new(DataCategory::BrowserActivity, now, now, 64).unwrap();
        let artifact = GenericArtifact {
            meta,
            payload: serde_json::json!({"key": "value", "count": 42}),
        };

        // Validate plausibility
        artifact.validate_plausibility().unwrap();

        // Serialize and deserialize
        let bytes = artifact.to_bytes().unwrap();
        let deserialized: GenericArtifact = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(deserialized.payload["key"], "value");
        assert_eq!(deserialized.payload["count"], 42);
    }

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_modified_before_created_always_fails(
            offset_secs in 1i64..1_000_000
        ) {
            let now = Utc::now();
            let earlier = now - Duration::seconds(offset_secs);
            let result = ArtifactMetadata::new(
                DataCategory::BrowserActivity,
                now,
                earlier,
                100,
            );
            prop_assert!(result.is_err());
        }
    }
}
