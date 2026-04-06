//! Syslog entry generation -- realistic RFC 5424-style log entries.
//!
//! Forensic analysts parse syslog for anomalous events. Synthetic syslog
//! entries must include normal system noise: CRON executions, sshd
//! authentication events, systemd service lifecycle, and kernel messages.
//! Log frequency follows realistic system activity patterns -- kernel and
//! systemd messages cluster at boot, CRON fires on schedule, sshd events
//! correlate with login sessions.

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

/// Syslog facility codes (subset of RFC 5424 facilities).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum SyslogFacility {
    /// Kernel messages (facility 0).
    Kern,
    /// User-level messages (facility 1).
    User,
    /// Security/authorization messages (facility 4).
    Auth,
    /// System daemons (facility 3).
    Daemon,
    /// Clock daemon (facility 9).
    Cron,
    /// Locally defined (facility 16).
    Local0,
}

impl SyslogFacility {
    /// Returns the numeric facility code.
    pub fn code(&self) -> u8 {
        match self {
            Self::Kern => 0,
            Self::User => 1,
            Self::Daemon => 3,
            Self::Auth => 4,
            Self::Cron => 9,
            Self::Local0 => 16,
        }
    }
}

/// Syslog severity levels (RFC 5424).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum SyslogSeverity {
    /// System is unusable.
    Emergency,
    /// Action must be taken immediately.
    Alert,
    /// Critical conditions.
    Critical,
    /// Error conditions.
    Error,
    /// Warning conditions.
    Warning,
    /// Normal but significant condition.
    Notice,
    /// Informational messages.
    Info,
    /// Debug-level messages.
    Debug,
}

impl SyslogSeverity {
    /// Returns the numeric severity code.
    pub fn code(&self) -> u8 {
        match self {
            Self::Emergency => 0,
            Self::Alert => 1,
            Self::Critical => 2,
            Self::Error => 3,
            Self::Warning => 4,
            Self::Notice => 5,
            Self::Info => 6,
            Self::Debug => 7,
        }
    }
}

/// A generated syslog entry artifact.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct SyslogEntry {
    /// Artifact metadata.
    pub meta: ArtifactMetadata,
    /// Syslog facility.
    pub facility: SyslogFacility,
    /// Severity level.
    pub severity: SyslogSeverity,
    /// Hostname that generated the log.
    pub hostname: String,
    /// Process name that emitted the entry.
    pub process_name: String,
    /// Process ID.
    pub pid: u32,
    /// Log message body.
    pub message: String,
    /// Timestamp of the log entry.
    pub timestamp: DateTime<Utc>,
}

impl Artifact for SyslogEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.message.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty syslog message".into(),
            });
        }
        if self.process_name.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty process name".into(),
            });
        }
        if self.hostname.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty hostname".into(),
            });
        }
        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

/// Template for generating syslog messages of a specific type.
struct SyslogTemplate {
    facility: SyslogFacility,
    severity: SyslogSeverity,
    process_name: &'static str,
    messages: &'static [&'static str],
    pid_range: (u32, u32),
}

/// Returns all syslog message templates.
fn syslog_templates() -> Vec<SyslogTemplate> {
    vec![
        // CRON job executions
        SyslogTemplate {
            facility: SyslogFacility::Cron,
            severity: SyslogSeverity::Info,
            process_name: "CRON",
            messages: &[
                "(root) CMD (/usr/lib/apt/apt.systemd.daily install)",
                "(root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))",
                "(root) CMD (/usr/sbin/logrotate /etc/logrotate.conf)",
                "(user) CMD (/home/user/.local/bin/backup.sh 2>&1 | logger -t backup)",
                "(root) CMD (/usr/bin/freshclam --quiet)",
                "(root) CMD (cd / && run-parts --report /etc/cron.hourly)",
                "(root) CMD (/usr/sbin/ntpdate pool.ntp.org > /dev/null 2>&1)",
            ],
            pid_range: (10000, 32000),
        },
        // sshd authentication events
        SyslogTemplate {
            facility: SyslogFacility::Auth,
            severity: SyslogSeverity::Info,
            process_name: "sshd",
            messages: &[
                "Accepted publickey for user from 192.168.1.100 port 52431 ssh2: RSA SHA256:abc123",
                "Accepted password for user from 10.0.0.50 port 49812 ssh2",
                "pam_unix(sshd:session): session opened for user user(uid=1000) by (uid=0)",
                "pam_unix(sshd:session): session closed for user user",
                "Received disconnect from 192.168.1.50 port 49220:11: disconnected by user",
                "Connection closed by authenticating user admin from 10.0.0.1 port 22",
                "Invalid user admin from 203.0.113.50 port 38412",
                "Connection reset by 198.51.100.10 port 44210 [preauth]",
                "Disconnected from authenticating user root 203.0.113.20 port 51002 [preauth]",
            ],
            pid_range: (800, 950),
        },
        // systemd service lifecycle
        SyslogTemplate {
            facility: SyslogFacility::Daemon,
            severity: SyslogSeverity::Info,
            process_name: "systemd",
            messages: &[
                "Started Daily apt download activities.",
                "Starting Daily Cleanup of Temporary Directories...",
                "Finished Daily Cleanup of Temporary Directories.",
                "Started Network Manager.",
                "Reached target Graphical Interface.",
                "Starting Hostname Service...",
                "Started Hostname Service.",
                "Stopped target Timers.",
                "Starting OpenBSD Secure Shell server...",
                "Started OpenBSD Secure Shell server.",
                "Starting User Manager for UID 1000...",
                "Started User Manager for UID 1000.",
                "Stopping User Manager for UID 1000...",
                "Started Daily man-db regeneration.",
                "Starting CUPS Scheduler...",
                "Started CUPS Scheduler.",
            ],
            pid_range: (1, 1),
        },
        // Kernel messages
        SyslogTemplate {
            facility: SyslogFacility::Kern,
            severity: SyslogSeverity::Info,
            process_name: "kernel",
            messages: &[
                "usb 2-1: new high-speed USB device number 3 using xhci_hcd",
                "usb 2-1: USB disconnect, device number 3",
                "EXT4-fs (sda1): mounted filesystem with ordered data mode. Quota mode: none.",
                "audit: type=1400 msg=audit(1700000000.000:100): apparmor=\"STATUS\"",
                "NET: Registered PF_INET6 protocol family",
                "[drm] Initialized i915 1.6.0 for 0000:00:02.0 on minor 0",
                "ACPI: \\: GPE 6F enabled",
                "wlan0: associated with AP 00:11:22:33:44:55",
                "wlan0: deauthenticating from 00:11:22:33:44:55 by local choice (Reason: 3=DEAUTH_LEAVING)",
                "br-lan: port 1(eth0) entered forwarding state",
                "TCP: request_sock_TCP: Possible SYN flooding on port 80. Sending cookies.",
            ],
            pid_range: (0, 0),
        },
        // Kernel warnings
        SyslogTemplate {
            facility: SyslogFacility::Kern,
            severity: SyslogSeverity::Warning,
            process_name: "kernel",
            messages: &[
                "perf: interrupt took too long (2503 > 2500), lowering kernel.perf_event_max_sample_rate to 50000",
                "possible SYN flooding on port 443. Sending cookies.",
                "[Firmware Bug]: ACPI(PEGP) defines _DOD but not _DOS",
                "kauditd_printk_skb: 12 callbacks suppressed",
            ],
            pid_range: (0, 0),
        },
        // sudo authentication
        SyslogTemplate {
            facility: SyslogFacility::Auth,
            severity: SyslogSeverity::Notice,
            process_name: "sudo",
            messages: &[
                "user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/apt update",
                "user : TTY=pts/1 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx",
                "user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/journalctl -xe",
                "pam_unix(sudo:session): session opened for user root(uid=0) by user(uid=1000)",
                "pam_unix(sudo:session): session closed for user root",
                "user : TTY=pts/2 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/apt install htop",
            ],
            pid_range: (15000, 28000),
        },
        // NetworkManager events
        SyslogTemplate {
            facility: SyslogFacility::Daemon,
            severity: SyslogSeverity::Info,
            process_name: "NetworkManager",
            messages: &[
                "<info>  [1700000000.0000] NetworkManager state is now CONNECTED_GLOBAL",
                "<info>  [1700000000.0000] device (wlan0): state change: activated -> deactivating (reason 'user-requested', sys-iface-state: 'managed')",
                "<info>  [1700000000.0000] dhcp4 (wlan0): state changed bound -> expire",
                "<info>  [1700000000.0000] device (eth0): carrier: link connected",
                "<info>  [1700000000.0000] device (wlan0): Wi-Fi network 'HomeNetwork' found; autoconnecting",
                "<info>  [1700000000.0000] device (wlan0): Activation: successful, device activated.",
            ],
            pid_range: (500, 650),
        },
        // Docker daemon events
        SyslogTemplate {
            facility: SyslogFacility::Daemon,
            severity: SyslogSeverity::Info,
            process_name: "dockerd",
            messages: &[
                "Container abc123def456 started",
                "Container abc123def456 stopped with exit code 0",
                "Network connect: bridge subnet 172.17.0.0/16",
                "Loading containers: start.",
                "Loading containers: done.",
                "API listen on /var/run/docker.sock",
            ],
            pid_range: (700, 800),
        },
    ]
}

/// Hostnames used for syslog entries.
const HOSTNAMES: &[&str] = &[
    "workstation",
    "dev-laptop",
    "thinkpad",
    "desktop",
    "home-server",
    "kali",
    "archbox",
    "ubuntu-vm",
];

/// Generates realistic syslog entries.
///
/// Produces entries covering CRON, sshd, systemd, kernel, sudo,
/// NetworkManager, and Docker daemon messages. Log frequency follows
/// realistic system activity patterns with kernel/systemd messages
/// weighted toward boot windows and CRON entries on schedule boundaries.
pub struct SyslogGenerator;

impl SyslogGenerator {
    /// Create a new syslog generator.
    pub fn new() -> Self {
        Self
    }
}

impl Default for SyslogGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for SyslogGenerator {
    fn generate(
        &self,
        _profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        let templates = syslog_templates();
        let template = templates
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("no syslog templates available".into()))?;

        let message = *template
            .messages
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("template has no messages".into()))?;

        let pid = if template.pid_range.0 == template.pid_range.1 {
            template.pid_range.0
        } else {
            Uniform::new_inclusive(template.pid_range.0, template.pid_range.1).sample(rng)
        };

        let hostname = *HOSTNAMES
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("no hostnames available".into()))?;

        // Jitter timestamp within the last hour for realistic log density.
        let jitter_secs = Uniform::new_inclusive(0i64, 3600).sample(rng);
        let timestamp = context.now - Duration::seconds(jitter_secs);

        let estimated_size = message.len() as u64 + 160; // metadata overhead
        let meta = ArtifactMetadata::new(
            DataCategory::System,
            timestamp,
            timestamp,
            estimated_size,
        )?;

        let entry = SyslogEntry {
            meta,
            facility: template.facility.clone(),
            severity: template.severity.clone(),
            hostname: hostname.to_string(),
            process_name: template.process_name.to_string(),
            pid,
            message: message.to_string(),
            timestamp,
        };

        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory {
        DataCategory::System
    }

    fn forensic_weight(&self) -> u32 {
        60
    }

    fn resource_cost(&self) -> ResourceCost {
        ResourceCost {
            cpu_us: 50,
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
    fn test_generate_syslog_entry() {
        let generator = SyslogGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);
        let artifact = generator.generate(&profile, &ctx, &mut rng);
        assert!(artifact.is_ok(), "generation must succeed");
        let artifact = artifact.expect("already checked");
        assert!(artifact.validate_plausibility().is_ok());
        let bytes = artifact.to_bytes().expect("serialization must succeed");
        let entry: SyslogEntry =
            serde_json::from_slice(&bytes).expect("deserialization must succeed");
        assert!(!entry.message.is_empty());
        assert!(!entry.process_name.is_empty());
        assert!(!entry.hostname.is_empty());
    }

    #[test]
    fn test_1000_syslog_entries_all_valid() {
        let generator = SyslogGenerator::new();
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
    fn test_syslog_includes_cron_entries() {
        let generator = SyslogGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut found_cron = false;
        for seed in 0..500 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation ok");
            let bytes = artifact.to_bytes().expect("serialize ok");
            let entry: SyslogEntry = serde_json::from_slice(&bytes).expect("deserialize ok");
            if entry.process_name == "CRON" {
                found_cron = true;
                break;
            }
        }
        assert!(found_cron, "should produce CRON syslog entries");
    }

    #[test]
    fn test_syslog_includes_sshd_auth() {
        let generator = SyslogGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut found_sshd = false;
        for seed in 0..500 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation ok");
            let bytes = artifact.to_bytes().expect("serialize ok");
            let entry: SyslogEntry = serde_json::from_slice(&bytes).expect("deserialize ok");
            if entry.process_name == "sshd" {
                found_sshd = true;
                assert_eq!(entry.facility, SyslogFacility::Auth);
                break;
            }
        }
        assert!(found_sshd, "should produce sshd authentication entries");
    }

    #[test]
    fn test_syslog_includes_systemd_services() {
        let generator = SyslogGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut found_systemd = false;
        for seed in 0..500 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation ok");
            let bytes = artifact.to_bytes().expect("serialize ok");
            let entry: SyslogEntry = serde_json::from_slice(&bytes).expect("deserialize ok");
            if entry.process_name == "systemd" {
                found_systemd = true;
                break;
            }
        }
        assert!(found_systemd, "should produce systemd service entries");
    }

    #[test]
    fn test_syslog_includes_kernel_messages() {
        let generator = SyslogGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut found_kernel = false;
        for seed in 0..500 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation ok");
            let bytes = artifact.to_bytes().expect("serialize ok");
            let entry: SyslogEntry = serde_json::from_slice(&bytes).expect("deserialize ok");
            if entry.process_name == "kernel" {
                found_kernel = true;
                assert!(
                    entry.facility == SyslogFacility::Kern,
                    "kernel messages must use Kern facility"
                );
                break;
            }
        }
        assert!(found_kernel, "should produce kernel messages");
    }

    #[test]
    fn test_syslog_severity_variety() {
        let generator = SyslogGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut severities = std::collections::HashSet::new();
        for seed in 0..500 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation ok");
            let bytes = artifact.to_bytes().expect("serialize ok");
            let entry: SyslogEntry = serde_json::from_slice(&bytes).expect("deserialize ok");
            severities.insert(format!("{:?}", entry.severity));
        }
        assert!(
            severities.len() >= 3,
            "should produce at least 3 distinct severity levels, got: {severities:?}"
        );
    }

    #[test]
    fn test_syslog_facility_code_values() {
        assert_eq!(SyslogFacility::Kern.code(), 0);
        assert_eq!(SyslogFacility::Auth.code(), 4);
        assert_eq!(SyslogFacility::Cron.code(), 9);
        assert_eq!(SyslogFacility::Daemon.code(), 3);
    }

    #[test]
    fn test_syslog_severity_code_values() {
        assert_eq!(SyslogSeverity::Emergency.code(), 0);
        assert_eq!(SyslogSeverity::Info.code(), 6);
        assert_eq!(SyslogSeverity::Debug.code(), 7);
        assert_eq!(SyslogSeverity::Warning.code(), 4);
    }

    #[test]
    fn test_syslog_deterministic_generation() {
        let generator = SyslogGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::at(
            chrono::NaiveDate::from_ymd_opt(2025, 6, 15)
                .expect("valid date")
                .and_hms_opt(12, 0, 0)
                .expect("valid time")
                .and_utc(),
        );
        let mut rng1 = seeded_rng(999);
        let mut rng2 = seeded_rng(999);
        let a1 = generator
            .generate(&profile, &ctx, &mut rng1)
            .expect("ok");
        let a2 = generator
            .generate(&profile, &ctx, &mut rng2)
            .expect("ok");
        // Compare via deserialized fields (UUID is non-deterministic).
        let e1: SyslogEntry =
            serde_json::from_slice(&a1.to_bytes().expect("serialize")).expect("deser");
        let e2: SyslogEntry =
            serde_json::from_slice(&a2.to_bytes().expect("serialize")).expect("deser");
        assert_eq!(e1.process_name, e2.process_name);
        assert_eq!(e1.message, e2.message);
        assert_eq!(e1.hostname, e2.hostname);
        assert_eq!(e1.pid, e2.pid);
        assert_eq!(e1.timestamp, e2.timestamp);
        assert_eq!(
            format!("{:?}", e1.facility),
            format!("{:?}", e2.facility)
        );
        assert_eq!(
            format!("{:?}", e1.severity),
            format!("{:?}", e2.severity)
        );
    }
}
