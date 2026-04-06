//! Package install/update history generation -- dpkg/apt-style event logs.
//!
//! Forensic analysis of Linux systems examines `/var/log/dpkg.log` and
//! `/var/log/apt/history.log` for software installation patterns. Synthetic
//! package history must include realistic Debian package names with proper
//! version numbering, install clusters that mimic `apt upgrade` batches,
//! and natural spacing between manual installs.

use chrono::{DateTime, Duration, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext, ResourceCost,
};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use serde::Serialize;

/// Package management action types.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum PackageAction {
    /// Fresh installation of a package.
    Install,
    /// Upgrade from a previous version.
    Update,
    /// Explicit removal (keeps config files).
    Remove,
    /// Automatic removal of unused dependency.
    Autoremove,
}

/// Source repository for the package.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum PackageSource {
    /// Official distribution repository.
    Official,
    /// Third-party PPA or external repository.
    ThirdParty,
    /// Manually installed .deb file.
    Manual,
}

/// A generated package event artifact.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct PackageEvent {
    /// Artifact metadata.
    pub meta: ArtifactMetadata,
    /// Package name (e.g., "libssl3").
    pub package_name: String,
    /// Version string (e.g., "3.0.13-1ubuntu3.1").
    pub version: String,
    /// What happened to the package.
    pub action: PackageAction,
    /// When the event occurred.
    pub timestamp: DateTime<Utc>,
    /// Where the package came from.
    pub source: PackageSource,
    /// Installed size in bytes.
    pub installed_size_bytes: u64,
}

impl Artifact for PackageEvent {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.package_name.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty package name".into(),
            });
        }
        if self.version.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty package version".into(),
            });
        }
        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

/// Debian/Ubuntu package definitions: (name, version, installed_size_bytes).
const SYSTEM_LIBS: &[(&str, &str, u64)] = &[
    ("libc6", "2.38-6ubuntu2", 13_000_000),
    ("libstdc++6", "13.2.0-7ubuntu1", 2_800_000),
    ("libgcc-s1", "13.2.0-7ubuntu1", 120_000),
    ("libssl3", "3.0.13-1ubuntu3.1", 4_200_000),
    ("libgnutls30", "3.8.3-1ubuntu1", 1_900_000),
    ("libsystemd0", "255.2-3ubuntu1", 900_000),
    ("libudev1", "255.2-3ubuntu1", 200_000),
    ("libpam0g", "1.5.3-5ubuntu5", 250_000),
    ("libselinux1", "3.5-2ubuntu2", 180_000),
    ("libzstd1", "1.5.5-1ubuntu2", 700_000),
    ("libsqlite3-0", "3.44.2-1", 1_700_000),
    ("libcurl4", "8.5.0-2ubuntu10", 600_000),
    ("libxml2", "2.12.3-1ubuntu1", 1_200_000),
    ("libjpeg-turbo8", "2.1.5-2ubuntu1", 500_000),
    ("libpng16-16", "1.6.40-2ubuntu1", 300_000),
];

/// Common user-facing packages.
const USER_PACKAGES: &[(&str, &str, u64)] = &[
    ("firefox", "124.0-1", 200_000_000),
    ("chromium-browser", "122.0.6261.128-0ubuntu1", 300_000_000),
    ("thunderbird", "115.9.0-1", 180_000_000),
    ("libreoffice-writer", "24.2.1-0ubuntu1", 90_000_000),
    ("gimp", "2.10.36-3build1", 50_000_000),
    ("vlc", "3.0.20-1build3", 20_000_000),
    ("code", "1.86.2-1707854558", 350_000_000),
    ("vim", "9.1.0016-1ubuntu7", 15_000_000),
    ("git", "2.43.0-1ubuntu7", 30_000_000),
    ("curl", "8.5.0-2ubuntu10", 500_000),
    ("openssh-client", "9.6p1-3ubuntu13", 2_000_000),
    ("openssh-server", "9.6p1-3ubuntu13", 1_500_000),
    ("python3", "3.12.3-0ubuntu1", 50_000_000),
    ("nodejs", "20.11.1-1nodesource1", 30_000_000),
    ("docker-ce", "26.0.0-1ubuntu1", 50_000_000),
    ("nginx", "1.24.0-2ubuntu7", 1_500_000),
    ("htop", "3.3.0-4build1", 200_000),
    ("tmux", "3.4-1build1", 500_000),
    ("zsh", "5.9-6ubuntu2", 5_000_000),
    ("neovim", "0.9.5-6ubuntu2", 20_000_000),
    ("build-essential", "12.10ubuntu1", 10_000_000),
    ("net-tools", "2.10-0.1ubuntu4", 400_000),
    ("tree", "2.1.1-1", 100_000),
    ("jq", "1.7.1-1build1", 150_000),
    ("nmap", "7.94+git20231201-3build1", 8_000_000),
    ("wireshark", "4.2.2-1ubuntu1", 25_000_000),
];

/// Development library packages (installed during upgrade batches).
const DEV_PACKAGES: &[(&str, &str, u64)] = &[
    ("libssl-dev", "3.0.13-1ubuntu3.1", 8_000_000),
    ("libcurl4-openssl-dev", "8.5.0-2ubuntu10", 1_200_000),
    ("libsqlite3-dev", "3.44.2-1", 900_000),
    ("libpq-dev", "16.2-1build1", 600_000),
    ("pkg-config", "1.8.1-2build1", 80_000),
    ("cmake", "3.28.3-1build3", 20_000_000),
    ("libffi-dev", "3.4.6-1build1", 200_000),
    ("python3-dev", "3.12.3-0ubuntu1", 600_000),
    ("libxml2-dev", "2.12.3-1ubuntu1", 2_000_000),
    ("zlib1g-dev", "1.3.1-1ubuntu1", 300_000),
];

/// Generates realistic package install/update history events.
///
/// Produces events with realistic Debian package names, proper version
/// numbering, and natural install patterns. Includes both single installs
/// and batch upgrade clusters mimicking `apt upgrade` runs.
pub struct PackageHistoryGenerator;

impl PackageHistoryGenerator {
    /// Create a new package history generator.
    pub fn new() -> Self {
        Self
    }
}

impl Default for PackageHistoryGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for PackageHistoryGenerator {
    fn generate(
        &self,
        _profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        // Choose which pool to draw from: system libs (upgrade batches),
        // user packages (manual installs), or dev packages.
        let pool_selector = Uniform::new_inclusive(0u32, 9).sample(rng);
        let (name, version, size) = if pool_selector <= 3 {
            // 40% system library (typical of batch upgrades)
            let pkg = SYSTEM_LIBS
                .choose(rng)
                .ok_or_else(|| EngineError::InvalidContext("empty system lib pool".into()))?;
            *pkg
        } else if pool_selector <= 7 {
            // 40% user-facing packages
            let pkg = USER_PACKAGES
                .choose(rng)
                .ok_or_else(|| EngineError::InvalidContext("empty user package pool".into()))?;
            *pkg
        } else {
            // 20% dev packages
            let pkg = DEV_PACKAGES
                .choose(rng)
                .ok_or_else(|| EngineError::InvalidContext("empty dev package pool".into()))?;
            *pkg
        };

        // Determine action: system libs are mostly upgrades, user packages
        // are mostly installs, removals are rare.
        let action = if pool_selector <= 3 {
            // System libs: mostly upgrades
            match Uniform::new_inclusive(0u32, 9).sample(rng) {
                0..=7 => PackageAction::Update,
                8 => PackageAction::Install,
                _ => PackageAction::Autoremove,
            }
        } else {
            // User/dev packages: mostly installs
            match Uniform::new_inclusive(0u32, 9).sample(rng) {
                0..=5 => PackageAction::Install,
                6..=8 => PackageAction::Update,
                _ => PackageAction::Remove,
            }
        };

        // Determine source based on package type.
        let source = match Uniform::new_inclusive(0u32, 9).sample(rng) {
            0..=7 => PackageSource::Official,
            8 => PackageSource::ThirdParty,
            _ => PackageSource::Manual,
        };

        // Spread events across the last year.
        let days_ago = Uniform::new_inclusive(1i64, 365).sample(rng);
        let hours_offset = Uniform::new_inclusive(0i64, 23).sample(rng);
        let minutes_offset = Uniform::new_inclusive(0i64, 59).sample(rng);
        let timestamp = context.now
            - Duration::days(days_ago)
            - Duration::hours(hours_offset)
            - Duration::minutes(minutes_offset);

        let meta = ArtifactMetadata::new(
            DataCategory::System,
            timestamp,
            timestamp,
            size,
        )?;

        let event = PackageEvent {
            meta,
            package_name: name.to_string(),
            version: version.to_string(),
            action,
            timestamp,
            source,
            installed_size_bytes: size,
        };

        event.validate_plausibility()?;
        Ok(Box::new(event))
    }

    fn category(&self) -> DataCategory {
        DataCategory::System
    }

    fn forensic_weight(&self) -> u32 {
        50
    }

    fn resource_cost(&self) -> ResourceCost {
        ResourceCost {
            cpu_us: 30,
            disk_bytes: 128,
            network_bytes: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_package_event() {
        let generator = PackageHistoryGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);
        let artifact = generator
            .generate(&profile, &ctx, &mut rng)
            .expect("generation must succeed");
        assert!(artifact.validate_plausibility().is_ok());
        let bytes = artifact.to_bytes().expect("serialization ok");
        let event: PackageEvent = serde_json::from_slice(&bytes).expect("deserialization ok");
        assert!(!event.package_name.is_empty());
        assert!(!event.version.is_empty());
        assert!(event.installed_size_bytes > 0);
    }

    #[test]
    fn test_500_package_events_all_valid() {
        let generator = PackageHistoryGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        for seed in 0..500 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation must not fail");
            assert!(
                artifact.validate_plausibility().is_ok(),
                "seed {seed} produced implausible artifact"
            );
        }
    }

    #[test]
    fn test_package_actions_include_install_and_update() {
        let generator = PackageHistoryGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut found_install = false;
        let mut found_update = false;
        for seed in 0..500 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation ok");
            let bytes = artifact.to_bytes().expect("serialize ok");
            let event: PackageEvent = serde_json::from_slice(&bytes).expect("deserialize ok");
            match event.action {
                PackageAction::Install => found_install = true,
                PackageAction::Update => found_update = true,
                _ => {}
            }
            if found_install && found_update {
                break;
            }
        }
        assert!(found_install, "should produce Install actions");
        assert!(found_update, "should produce Update actions");
    }

    #[test]
    fn test_package_sources_include_official() {
        let generator = PackageHistoryGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut found_official = false;
        for seed in 0..200 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation ok");
            let bytes = artifact.to_bytes().expect("serialize ok");
            let event: PackageEvent = serde_json::from_slice(&bytes).expect("deserialize ok");
            if event.source == PackageSource::Official {
                found_official = true;
                break;
            }
        }
        assert!(found_official, "majority of packages should come from official repos");
    }

    #[test]
    fn test_package_names_are_realistic_debian() {
        let generator = PackageHistoryGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        for seed in 0..100 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation ok");
            let bytes = artifact.to_bytes().expect("serialize ok");
            let event: PackageEvent = serde_json::from_slice(&bytes).expect("deserialize ok");
            // Debian package names are lowercase with hyphens, digits, dots, and plus signs.
            assert!(
                event
                    .package_name
                    .chars()
                    .all(|c| c.is_ascii_lowercase()
                        || c.is_ascii_digit()
                        || c == '-'
                        || c == '+'
                        || c == '.'),
                "package name '{}' contains invalid characters for Debian naming",
                event.package_name
            );
        }
    }

    #[test]
    fn test_package_versions_contain_digits() {
        let generator = PackageHistoryGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        for seed in 0..50 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation ok");
            let bytes = artifact.to_bytes().expect("serialize ok");
            let event: PackageEvent = serde_json::from_slice(&bytes).expect("deserialize ok");
            assert!(
                event.version.chars().any(|c| c.is_ascii_digit()),
                "version '{}' must contain at least one digit",
                event.version
            );
        }
    }

    #[test]
    fn test_package_event_deterministic() {
        let generator = PackageHistoryGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::at(
            chrono::NaiveDate::from_ymd_opt(2025, 6, 15)
                .expect("valid date")
                .and_hms_opt(12, 0, 0)
                .expect("valid time")
                .and_utc(),
        );
        let mut rng1 = seeded_rng(7777);
        let mut rng2 = seeded_rng(7777);
        let a1 = generator
            .generate(&profile, &ctx, &mut rng1)
            .expect("ok");
        let a2 = generator
            .generate(&profile, &ctx, &mut rng2)
            .expect("ok");
        // Compare via deserialized fields (UUID is non-deterministic).
        let e1: PackageEvent =
            serde_json::from_slice(&a1.to_bytes().expect("serialize")).expect("deser");
        let e2: PackageEvent =
            serde_json::from_slice(&a2.to_bytes().expect("serialize")).expect("deser");
        assert_eq!(e1.package_name, e2.package_name);
        assert_eq!(e1.version, e2.version);
        assert_eq!(e1.timestamp, e2.timestamp);
        assert_eq!(e1.installed_size_bytes, e2.installed_size_bytes);
        assert_eq!(format!("{:?}", e1.action), format!("{:?}", e2.action));
        assert_eq!(format!("{:?}", e1.source), format!("{:?}", e2.source));
    }
}
