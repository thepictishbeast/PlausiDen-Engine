//! # PlausiDen Engine Core
//!
//! Core traits, types, and scheduling for the PlausiDen data generation engine.
//!
//! This crate defines the foundational abstractions that all data generators
//! implement. It provides:
//!
//! - [`traits::DataGenerator`] — the trait every generator implements
//! - [`traits::Artifact`] — the trait every generated artifact implements
//! - [`profile::UserProfile`] — behavioral profiles driving data generation
//! - [`schedule::OrganicScheduler`] — human-like timing patterns
//! - [`config::EngineConfig`] — engine configuration and resource limits
//! - [`entropy`] — cryptographically secure RNG management

pub mod artifact;
pub mod config;
pub mod dedup;
pub mod entropy;
pub mod error;
pub mod paranoia;
pub mod profile;
pub mod rate_governor;
pub mod schedule;
pub mod traits;

// Re-export primary types for convenience.
pub use config::EngineConfig;
pub use error::{EngineError, Result};
pub use profile::{RiskLevel, UserProfile, UserProfileBuilder};
pub use traits::{Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext};
