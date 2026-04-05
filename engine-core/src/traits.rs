//! Core traits for data generation and artifact handling.
//!
//! All data generators in the PlausiDen engine implement [`DataGenerator`].
//! Generated data implements [`Artifact`] for serialization and plausibility validation.

use crate::error::Result;
use crate::profile::UserProfile;
use rand::CryptoRng;
use rand::RngCore;
use serde::Serialize;

/// Context provided to generators for each generation cycle.
#[derive(Debug, Clone)]
pub struct GenerationContext {
    /// Current timestamp for generation reference.
    pub now: chrono::DateTime<chrono::Utc>,
    /// Previously generated artifacts in this session (for consistency).
    pub session_artifact_count: u64,
    /// Total artifacts generated across all sessions.
    pub total_artifact_count: u64,
}

impl GenerationContext {
    /// Create a new generation context anchored at the current time.
    pub fn new() -> Self {
        Self {
            now: chrono::Utc::now(),
            session_artifact_count: 0,
            total_artifact_count: 0,
        }
    }

    /// Create a context at a specific time (for testing and deterministic generation).
    pub fn at(time: chrono::DateTime<chrono::Utc>) -> Self {
        Self {
            now: time,
            session_artifact_count: 0,
            total_artifact_count: 0,
        }
    }
}

impl Default for GenerationContext {
    fn default() -> Self {
        Self::new()
    }
}

/// Forensic data categories ordered by how heavily they are relied upon in investigations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, serde::Deserialize)]
pub enum DataCategory {
    /// Browser history, cookies, searches — most commonly used in prosecution.
    BrowserActivity,
    /// Filesystem — files, metadata, timestamps.
    FileSystem,
    /// Communications — contacts, call logs, messages.
    Communications,
    /// Location — GPS, WiFi, cell towers.
    Location,
    /// Network — DNS queries, traffic patterns.
    Network,
    /// Input — keystrokes, touch, mouse.
    Input,
    /// System — logs, processes, installs.
    System,
    /// Social — social media activity.
    Social,
}

impl DataCategory {
    /// Returns the default forensic weight for this category.
    ///
    /// Higher weight means forensic analysts rely more heavily on this data type.
    /// Browser activity and filesystem timestamps are the primary anchors
    /// used to build forensic timelines in court.
    pub fn default_forensic_weight(&self) -> u32 {
        match self {
            Self::BrowserActivity => 100,
            Self::FileSystem => 95,
            Self::Communications => 90,
            Self::Location => 85,
            Self::Network => 70,
            Self::System => 60,
            Self::Input => 40,
            Self::Social => 50,
        }
    }
}

/// Estimated resource cost for a single generation cycle.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResourceCost {
    /// Estimated CPU time in microseconds.
    pub cpu_us: u64,
    /// Estimated disk bytes written.
    pub disk_bytes: u64,
    /// Estimated network bytes (zero for most generators).
    pub network_bytes: u64,
}

/// Metadata attached to every generated artifact.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ArtifactMetadata {
    /// Unique artifact identifier.
    pub id: uuid::Uuid,
    /// Data category this artifact belongs to.
    pub category: DataCategory,
    /// Simulated creation timestamp.
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Simulated modification timestamp (>= created_at).
    pub modified_at: chrono::DateTime<chrono::Utc>,
    /// Approximate size in bytes when serialized.
    pub size_bytes: u64,
}

/// A generated data artifact ready for injection.
///
/// Every artifact can be validated for forensic plausibility and serialized
/// to bytes for storage or transmission. The `to_bytes()` method is the
/// canonical serialization path — no `Serialize` supertrait is required
/// so that WASM and minimal consumers avoid the serde cost.
pub trait Artifact: Send + Sync {
    /// Returns the artifact's metadata (timestamps, size, category).
    fn metadata(&self) -> &ArtifactMetadata;

    /// Validate that the artifact is forensically plausible.
    ///
    /// Returns `Err` if the artifact would be obviously synthetic
    /// (e.g., creation time after modification time, impossible timestamps).
    fn validate_plausibility(&self) -> Result<()>;

    /// Serialize to bytes for storage or transmission.
    fn to_bytes(&self) -> Result<Vec<u8>>;
}

/// Every data generator implements this trait.
///
/// Generators produce artifacts of a specific type based on a user profile
/// and generation context. The RNG must be both cryptographically secure
/// and provide standard random number generation.
pub trait DataGenerator: Send + Sync {
    /// Generate a single artifact based on the user profile and context.
    fn generate(
        &self,
        profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>>;

    /// Returns the data category this generator targets.
    fn category(&self) -> DataCategory;

    /// Returns the forensic weight — how much forensic analysts rely on this data type.
    /// Higher weight = higher priority for generation.
    fn forensic_weight(&self) -> u32 {
        self.category().default_forensic_weight()
    }

    /// Returns estimated resource cost for one generation cycle.
    fn resource_cost(&self) -> ResourceCost {
        ResourceCost::default()
    }
}
