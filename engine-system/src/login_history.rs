//! Login/logout history generation -- wtmp/lastlog-compatible entries.
//!
//! Forensic investigators examine `/var/log/wtmp` and `lastlog` to
//! reconstruct user session timelines. Synthetic login history must
//! include realistic session types (local console, SSH remote, GUI
//! desktop), natural session durations, and plausible source IPs for
//! remote sessions.

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

/// Type of login session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum SessionType {
    /// Local console login (tty1-tty6).
    Local,
    /// SSH remote session (pts/N).
    Ssh,
    /// GUI desktop session (e.g., GDM, SDDM, LightDM).
    Gui,
}

/// A generated login history entry artifact.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct LoginEntry {
    /// Artifact metadata.
    pub meta: ArtifactMetadata,
    /// Username that logged in.
    pub username: String,
    /// Terminal device (tty1, pts/0, :0, etc.).
    pub tty: String,
    /// Source IP for remote sessions (None for local/GUI).
    pub source_ip: Option<String>,
    /// When the session started.
    pub login_time: DateTime<Utc>,
    /// When the session ended (None if still active).
    pub logout_time: Option<DateTime<Utc>>,
    /// Session type classification.
    pub session_type: SessionType,
}

impl LoginEntry {
    /// Returns the session duration, if the session has ended.
    pub fn session_duration(&self) -> Option<Duration> {
        self.logout_time.map(|lt| lt - self.login_time)
    }
}

impl Artifact for LoginEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.username.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty username".into(),
            });
        }
        if self.tty.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty tty".into(),
            });
        }
        // SSH sessions must have a source IP.
        if self.session_type == SessionType::Ssh && self.source_ip.is_none() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "SSH session without source IP".into(),
            });
        }
        // Logout must be after login.
        if let Some(lt) = self.logout_time
            && lt < self.login_time {
                return Err(EngineError::ImplausibleArtifact {
                    reason: format!("logout time ({lt}) before login time ({})", self.login_time),
                });
            }
        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

/// Usernames commonly found in wtmp.
const USERNAMES: &[&str] = &[
    "user", "admin", "deploy", "dev", "backup", "www-data", "postgres",
];

/// Private/internal source IPs for SSH sessions.
const SSH_SOURCE_IPS: &[&str] = &[
    "192.168.1.10",
    "192.168.1.50",
    "192.168.1.100",
    "192.168.1.200",
    "10.0.0.2",
    "10.0.0.5",
    "10.0.0.10",
    "10.0.0.50",
    "172.16.0.5",
    "172.16.0.20",
    // External IPs (VPN, cloud, other offices)
    "203.0.113.10",
    "203.0.113.42",
    "198.51.100.5",
    "198.51.100.100",
];

/// Generates realistic login/logout history entries.
///
/// Produces entries with three session types, each with characteristic
/// durations:
/// - **SSH**: Short sessions (5-30 minutes for quick commands, occasionally longer)
/// - **GUI desktop**: Long sessions (2-12 hours for daily work)
/// - **Local console**: Brief sessions (1-15 minutes for maintenance)
///
/// Session data is compatible with `wtmp`/`lastlog` format expectations.
pub struct LoginHistoryGenerator;

impl LoginHistoryGenerator {
    /// Create a new login history generator.
    pub fn new() -> Self {
        Self
    }
}

impl Default for LoginHistoryGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for LoginHistoryGenerator {
    fn generate(
        &self,
        _profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        // Pick session type with realistic distribution:
        // GUI ~40%, SSH ~45%, Local ~15%
        let type_selector = Uniform::new_inclusive(0u32, 19).sample(rng);
        let session_type = if type_selector <= 7 {
            SessionType::Gui
        } else if type_selector <= 16 {
            SessionType::Ssh
        } else {
            SessionType::Local
        };

        let username = *USERNAMES
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("no usernames available".into()))?;

        // Build tty string based on session type.
        let tty = match session_type {
            SessionType::Local => {
                let tty_num = Uniform::new_inclusive(1u32, 6).sample(rng);
                format!("tty{tty_num}")
            }
            SessionType::Ssh => {
                let pts_num = Uniform::new_inclusive(0u32, 15).sample(rng);
                format!("pts/{pts_num}")
            }
            SessionType::Gui => {
                let display = Uniform::new_inclusive(0u32, 1).sample(rng);
                format!(":{display}")
            }
        };

        // SSH sessions get a source IP.
        let source_ip = if session_type == SessionType::Ssh {
            Some(
                SSH_SOURCE_IPS
                    .choose(rng)
                    .ok_or_else(|| EngineError::InvalidContext("no source IPs available".into()))?
                    .to_string(),
            )
        } else {
            None
        };

        // Place login within the last 30 days.
        let days_ago = Uniform::new_inclusive(0i64, 30).sample(rng);
        let hours_offset = Uniform::new_inclusive(0i64, 23).sample(rng);
        let minutes_offset = Uniform::new_inclusive(0i64, 59).sample(rng);
        let login_time = context.now
            - Duration::days(days_ago)
            - Duration::hours(hours_offset)
            - Duration::minutes(minutes_offset);

        // Session duration depends on type.
        let session_secs = match session_type {
            SessionType::Ssh => {
                // SSH: bimodal -- short commands (5-30 min) or longer work (30 min - 3 hours)
                if Uniform::new_inclusive(0u32, 2).sample(rng) == 0 {
                    // Short SSH session: 5-30 minutes
                    Uniform::new_inclusive(300i64, 1800).sample(rng)
                } else {
                    // Longer SSH session: 30 min - 3 hours
                    Uniform::new_inclusive(1800i64, 10800).sample(rng)
                }
            }
            SessionType::Gui => {
                // GUI desktop: 2-12 hours, occasionally overnight (12-18 hours)
                if Uniform::new_inclusive(0u32, 4).sample(rng) == 0 {
                    // Overnight session: 12-18 hours
                    Uniform::new_inclusive(43200i64, 64800).sample(rng)
                } else {
                    // Normal workday session: 2-12 hours
                    Uniform::new_inclusive(7200i64, 43200).sample(rng)
                }
            }
            SessionType::Local => {
                // Local console: 1-15 minutes (quick maintenance)
                Uniform::new_inclusive(60i64, 900).sample(rng)
            }
        };

        let session_duration = Duration::seconds(session_secs);

        // ~10% of sessions are still active (no logout time).
        let still_active = Uniform::new_inclusive(0u32, 9).sample(rng) == 0;
        let logout_time = if still_active {
            None
        } else {
            Some(login_time + session_duration)
        };

        // Use login_time as created_at, logout_time (or now) as modified_at.
        let modified_at = logout_time.unwrap_or(context.now);
        // Ensure modified_at >= login_time to satisfy metadata constraints.
        let safe_modified_at = if modified_at < login_time {
            login_time
        } else {
            modified_at
        };

        let meta = ArtifactMetadata::new(DataCategory::System, login_time, safe_modified_at, 256)?;

        let entry = LoginEntry {
            meta,
            username: username.to_string(),
            tty,
            source_ip,
            login_time,
            logout_time,
            session_type,
        };

        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory {
        DataCategory::System
    }

    fn forensic_weight(&self) -> u32 {
        65
    }

    fn resource_cost(&self) -> ResourceCost {
        ResourceCost {
            cpu_us: 40,
            disk_bytes: 256,
            network_bytes: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_login_entry() {
        let generator = LoginHistoryGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);
        let artifact = generator
            .generate(&profile, &ctx, &mut rng)
            .expect("generation must succeed");
        assert!(artifact.validate_plausibility().is_ok());
        let bytes = artifact.to_bytes().expect("serialization ok");
        let entry: LoginEntry = serde_json::from_slice(&bytes).expect("deserialization ok");
        assert!(!entry.username.is_empty());
        assert!(!entry.tty.is_empty());
    }

    #[test]
    fn test_1000_login_entries_all_valid() {
        let generator = LoginHistoryGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        for seed in 0..1000 {
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
    fn test_login_includes_all_session_types() {
        let generator = LoginHistoryGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut found_local = false;
        let mut found_ssh = false;
        let mut found_gui = false;
        for seed in 0..500 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation ok");
            let bytes = artifact.to_bytes().expect("serialize ok");
            let entry: LoginEntry = serde_json::from_slice(&bytes).expect("deserialize ok");
            match entry.session_type {
                SessionType::Local => found_local = true,
                SessionType::Ssh => found_ssh = true,
                SessionType::Gui => found_gui = true,
            }
            if found_local && found_ssh && found_gui {
                break;
            }
        }
        assert!(found_local, "should produce Local sessions");
        assert!(found_ssh, "should produce SSH sessions");
        assert!(found_gui, "should produce GUI sessions");
    }

    #[test]
    fn test_ssh_sessions_have_source_ip() {
        let generator = LoginHistoryGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        for seed in 0..500 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation ok");
            let bytes = artifact.to_bytes().expect("serialize ok");
            let entry: LoginEntry = serde_json::from_slice(&bytes).expect("deserialize ok");
            if entry.session_type == SessionType::Ssh {
                assert!(
                    entry.source_ip.is_some(),
                    "SSH sessions must have a source IP"
                );
            }
        }
    }

    #[test]
    fn test_local_and_gui_sessions_no_source_ip() {
        let generator = LoginHistoryGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        for seed in 0..500 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation ok");
            let bytes = artifact.to_bytes().expect("serialize ok");
            let entry: LoginEntry = serde_json::from_slice(&bytes).expect("deserialize ok");
            if entry.session_type == SessionType::Local || entry.session_type == SessionType::Gui {
                assert!(
                    entry.source_ip.is_none(),
                    "Local/GUI sessions should not have a source IP"
                );
            }
        }
    }

    #[test]
    fn test_ssh_session_duration_short() {
        let generator = LoginHistoryGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut found_short_ssh = false;
        for seed in 0..500 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation ok");
            let bytes = artifact.to_bytes().expect("serialize ok");
            let entry: LoginEntry = serde_json::from_slice(&bytes).expect("deserialize ok");
            if entry.session_type == SessionType::Ssh
                && let Some(duration) = entry.session_duration()
                    && duration.num_minutes() <= 30 {
                        found_short_ssh = true;
                        break;
                    }
        }
        assert!(
            found_short_ssh,
            "should produce short SSH sessions (5-30 min)"
        );
    }

    #[test]
    fn test_gui_session_duration_long() {
        let generator = LoginHistoryGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut found_long_gui = false;
        for seed in 0..500 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation ok");
            let bytes = artifact.to_bytes().expect("serialize ok");
            let entry: LoginEntry = serde_json::from_slice(&bytes).expect("deserialize ok");
            if entry.session_type == SessionType::Gui
                && let Some(duration) = entry.session_duration()
                    && duration.num_hours() >= 2 {
                        found_long_gui = true;
                        break;
                    }
        }
        assert!(
            found_long_gui,
            "should produce long GUI desktop sessions (2+ hours)"
        );
    }

    #[test]
    fn test_overnight_sessions_exist() {
        let generator = LoginHistoryGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut found_overnight = false;
        for seed in 0..1000 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation ok");
            let bytes = artifact.to_bytes().expect("serialize ok");
            let entry: LoginEntry = serde_json::from_slice(&bytes).expect("deserialize ok");
            if let Some(duration) = entry.session_duration()
                && duration.num_hours() >= 12 {
                    found_overnight = true;
                    break;
                }
        }
        assert!(
            found_overnight,
            "should produce overnight sessions (12+ hours)"
        );
    }

    #[test]
    fn test_login_tty_format() {
        let generator = LoginHistoryGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        for seed in 0..200 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation ok");
            let bytes = artifact.to_bytes().expect("serialize ok");
            let entry: LoginEntry = serde_json::from_slice(&bytes).expect("deserialize ok");
            match entry.session_type {
                SessionType::Local => {
                    assert!(
                        entry.tty.starts_with("tty"),
                        "local session tty '{}' should start with 'tty'",
                        entry.tty
                    );
                }
                SessionType::Ssh => {
                    assert!(
                        entry.tty.starts_with("pts/"),
                        "SSH session tty '{}' should start with 'pts/'",
                        entry.tty
                    );
                }
                SessionType::Gui => {
                    assert!(
                        entry.tty.starts_with(':'),
                        "GUI session tty '{}' should start with ':'",
                        entry.tty
                    );
                }
            }
        }
    }

    #[test]
    fn test_login_logout_time_ordering() {
        let generator = LoginHistoryGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        for seed in 0..500 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation ok");
            let bytes = artifact.to_bytes().expect("serialize ok");
            let entry: LoginEntry = serde_json::from_slice(&bytes).expect("deserialize ok");
            if let Some(logout) = entry.logout_time {
                assert!(
                    logout >= entry.login_time,
                    "logout ({logout}) must be >= login ({})",
                    entry.login_time
                );
            }
        }
    }

    #[test]
    fn test_login_deterministic() {
        let generator = LoginHistoryGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::at(
            chrono::NaiveDate::from_ymd_opt(2025, 6, 15)
                .expect("valid date")
                .and_hms_opt(12, 0, 0)
                .expect("valid time")
                .and_utc(),
        );
        let mut rng1 = seeded_rng(555);
        let mut rng2 = seeded_rng(555);
        let a1 = generator.generate(&profile, &ctx, &mut rng1).expect("ok");
        let a2 = generator.generate(&profile, &ctx, &mut rng2).expect("ok");
        // Compare via deserialized fields (UUID is non-deterministic).
        let e1: LoginEntry =
            serde_json::from_slice(&a1.to_bytes().expect("serialize")).expect("deser");
        let e2: LoginEntry =
            serde_json::from_slice(&a2.to_bytes().expect("serialize")).expect("deser");
        assert_eq!(e1.username, e2.username);
        assert_eq!(e1.tty, e2.tty);
        assert_eq!(e1.source_ip, e2.source_ip);
        assert_eq!(e1.login_time, e2.login_time);
        assert_eq!(e1.logout_time, e2.logout_time);
        assert_eq!(
            format!("{:?}", e1.session_type),
            format!("{:?}", e2.session_type)
        );
    }
}
