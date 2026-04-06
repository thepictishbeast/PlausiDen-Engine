//! System log generation — journald/syslog-style entries.
//!
//! Forensic analysts check system logs for anomalies. Synthetic logs
//! must include normal system events: service starts, authentication,
//! package updates, kernel messages, cron jobs.

use chrono::{DateTime, Duration, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext,
};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use serde::Serialize;

/// A generated system log entry.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct LogEntry {
    pub meta: ArtifactMetadata,
    /// Log timestamp.
    pub timestamp: DateTime<Utc>,
    /// Syslog facility (kern, auth, daemon, etc.).
    pub facility: String,
    /// Severity level.
    pub severity: LogSeverity,
    /// Process/service that generated the log.
    pub source: String,
    /// PID of the process.
    pub pid: u32,
    /// Log message.
    pub message: String,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub enum LogSeverity {
    Debug,
    Info,
    Notice,
    Warning,
    Error,
    Critical,
}

impl Artifact for LogEntry {
    fn metadata(&self) -> &ArtifactMetadata { &self.meta }
    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.message.is_empty() {
            return Err(EngineError::ImplausibleArtifact { reason: "empty log message".into() });
        }
        if self.source.is_empty() {
            return Err(EngineError::ImplausibleArtifact { reason: "empty log source".into() });
        }
        Ok(())
    }
    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

struct LogTemplate {
    facility: &'static str,
    source: &'static str,
    severity: LogSeverity,
    messages: &'static [&'static str],
    pid_range: (u32, u32),
}

fn log_templates() -> Vec<LogTemplate> {
    vec![
        LogTemplate {
            facility: "kern", source: "kernel", severity: LogSeverity::Info,
            messages: &[
                "usb 2-1: new high-speed USB device number 3 using xhci_hcd",
                "usb 2-1: USB disconnect, device number 3",
                "EXT4-fs (sda1): mounted filesystem with ordered data mode",
                "audit: type=1400 msg=audit(1700000000.000:100): apparmor=\"STATUS\"",
                "NET: Registered PF_INET6 protocol family",
            ],
            pid_range: (0, 0),
        },
        LogTemplate {
            facility: "auth", source: "sshd", severity: LogSeverity::Info,
            messages: &[
                "Accepted publickey for user from 192.168.1.100 port 52431 ssh2",
                "pam_unix(sshd:session): session opened for user(uid=1000) by (uid=0)",
                "pam_unix(sshd:session): session closed for user",
                "Connection closed by authenticating user from 10.0.0.1 port 22",
                "Received disconnect from 192.168.1.50 port 49220: Normal Shutdown",
            ],
            pid_range: (800, 900),
        },
        LogTemplate {
            facility: "daemon", source: "systemd", severity: LogSeverity::Info,
            messages: &[
                "Started Daily apt download activities.",
                "Starting Daily Cleanup of Temporary Directories...",
                "Finished Daily Cleanup of Temporary Directories.",
                "Started Network Manager.",
                "Reached target Graphical Interface.",
                "Starting Hostname Service...",
                "Started Hostname Service.",
            ],
            pid_range: (1, 1),
        },
        LogTemplate {
            facility: "daemon", source: "NetworkManager", severity: LogSeverity::Info,
            messages: &[
                "<info>  NetworkManager state is now CONNECTED_GLOBAL",
                "<info>  device (wlan0): state change: activated -> deactivating",
                "<info>  dhcp4 (wlan0): state changed bound -> expire",
                "<info>  device (eth0): carrier: link connected",
            ],
            pid_range: (500, 600),
        },
        LogTemplate {
            facility: "cron", source: "CRON", severity: LogSeverity::Info,
            messages: &[
                "(root) CMD (/usr/lib/apt/apt.systemd.daily install)",
                "(root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))",
                "(user) CMD (/home/user/.local/bin/backup.sh)",
            ],
            pid_range: (10000, 30000),
        },
        LogTemplate {
            facility: "daemon", source: "dockerd", severity: LogSeverity::Info,
            messages: &[
                "Container started: abc123def456",
                "Container stopped: abc123def456",
                "Network connect: bridge",
            ],
            pid_range: (700, 800),
        },
        LogTemplate {
            facility: "auth", source: "sudo", severity: LogSeverity::Notice,
            messages: &[
                "user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/apt update",
                "user : TTY=pts/1 ; PWD=/home/user ; USER=root ; COMMAND=/usr/bin/systemctl restart nginx",
                "pam_unix(sudo:session): session opened for user root(uid=0) by user(uid=1000)",
            ],
            pid_range: (15000, 25000),
        },
    ]
}

/// Generates system log entries.
pub struct LogGenerator;
impl LogGenerator { pub fn new() -> Self { Self } }
impl Default for LogGenerator { fn default() -> Self { Self::new() } }

impl DataGenerator for LogGenerator {
    fn generate(&self, _profile: &UserProfile, context: &GenerationContext, rng: &mut (impl RngCore + CryptoRng)) -> Result<Box<dyn Artifact>> {
        let templates = log_templates();
        let template = templates.choose(rng).ok_or_else(|| EngineError::InvalidContext("no log templates".into()))?;

        // SAFETY: every log template's `messages` slice is non-empty by
        // construction in log_templates(); the template was just
        // selected from a slice constructed by the same function.
        let message = template
            .messages
            .choose(rng)
            .copied()
            .expect("log template messages slice is non-empty");
        let pid = if template.pid_range.0 == template.pid_range.1 {
            template.pid_range.0
        } else {
            Uniform::new_inclusive(template.pid_range.0, template.pid_range.1).sample(rng)
        };

        let jitter = Uniform::new_inclusive(0i64, 3600).sample(rng);
        let timestamp = context.now - Duration::seconds(jitter);

        let meta = ArtifactMetadata::new(
            DataCategory::System, timestamp, timestamp,
            message.len() as u64 + 128,
        )?;

        let entry = LogEntry {
            meta, timestamp, facility: template.facility.to_string(),
            severity: template.severity.clone(), source: template.source.to_string(),
            pid, message: message.to_string(),
        };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory { DataCategory::System }
    fn forensic_weight(&self) -> u32 { 60 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_log_entry() {
        let g = LogGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);
        let a = g.generate(&p, &c, &mut r).unwrap();
        a.validate_plausibility().unwrap();
        let b = a.to_bytes().unwrap();
        let e: LogEntry = serde_json::from_slice(&b).unwrap();
        assert!(!e.message.is_empty());
        assert!(!e.source.is_empty());
    }

    #[test]
    fn test_1000_logs_valid() {
        let g = LogGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..1000 {
            let mut r = seeded_rng(s);
            g.generate(&p, &c, &mut r).unwrap().validate_plausibility().unwrap();
        }
    }

    #[test]
    fn test_logs_include_auth() {
        let g = LogGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut found = false;
        for s in 0..200 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: LogEntry = serde_json::from_slice(&b).unwrap();
            if e.facility == "auth" { found = true; break; }
        }
        assert!(found, "should include auth facility logs");
    }

    #[test]
    fn test_log_severity_variety() {
        let g = LogGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut severities = std::collections::HashSet::new();
        for s in 0..500 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: LogEntry = serde_json::from_slice(&b).unwrap();
            severities.insert(format!("{:?}", e.severity));
        }
        assert!(severities.len() >= 2, "should have multiple severity levels");
    }
}
