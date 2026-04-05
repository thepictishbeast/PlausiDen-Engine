//! Process list generation — realistic /proc-style process snapshots.

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

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ProcessEntry {
    pub meta: ArtifactMetadata,
    pub pid: u32,
    pub ppid: u32,
    pub name: String,
    pub cmdline: String,
    pub user: String,
    pub state: String,
    pub cpu_percent: f32,
    pub mem_rss_kb: u64,
    pub start_time: DateTime<Utc>,
}

impl Artifact for ProcessEntry {
    fn metadata(&self) -> &ArtifactMetadata { &self.meta }
    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.name.is_empty() { return Err(EngineError::ImplausibleArtifact { reason: "empty process name".into() }); }
        Ok(())
    }
    fn to_bytes(&self) -> Result<Vec<u8>> { serde_json::to_vec(self).map_err(EngineError::Serialization) }
}

const SYSTEM_PROCESSES: &[(&str, &str, &str, u64)] = &[
    ("systemd", "/usr/lib/systemd/systemd --system", "root", 8192),
    ("kthreadd", "[kthreadd]", "root", 0),
    ("journald", "/usr/lib/systemd/systemd-journald", "root", 32768),
    ("udevd", "/usr/lib/systemd/systemd-udevd", "root", 12288),
    ("NetworkManager", "/usr/sbin/NetworkManager --no-daemon", "root", 16384),
    ("dbus-daemon", "/usr/bin/dbus-daemon --system", "messagebus", 4096),
    ("polkitd", "/usr/lib/polkit-1/polkitd --no-debug", "polkitd", 8192),
    ("sshd", "sshd: /usr/sbin/sshd -D", "root", 4096),
    ("cron", "/usr/sbin/cron -f", "root", 2048),
    ("rsyslogd", "/usr/sbin/rsyslogd -n", "syslog", 8192),
];

const USER_PROCESSES: &[(&str, &str, u64)] = &[
    ("bash", "-bash", 4096),
    ("vim", "vim /home/user/notes.txt", 16384),
    ("firefox", "/usr/lib/firefox/firefox", 524288),
    ("code", "/usr/share/code/code --unity-launch", 262144),
    ("thunderbird", "/usr/bin/thunderbird", 196608),
    ("htop", "htop", 8192),
    ("tmux", "tmux", 4096),
    ("python3", "python3 script.py", 32768),
    ("node", "node server.js", 65536),
    ("cargo", "cargo build", 131072),
];

pub struct ProcessGenerator;
impl ProcessGenerator { pub fn new() -> Self { Self } }
impl Default for ProcessGenerator { fn default() -> Self { Self::new() } }

impl DataGenerator for ProcessGenerator {
    fn generate(&self, _profile: &UserProfile, context: &GenerationContext, rng: &mut (impl RngCore + CryptoRng)) -> Result<Box<dyn Artifact>> {
        let is_system = Uniform::new_inclusive(0u32, 2).sample(rng) == 0;

        let (name, cmdline, user, base_rss) = if is_system {
            let p = SYSTEM_PROCESSES.choose(rng).unwrap();
            (p.0, p.1, p.2.to_string(), p.3)
        } else {
            let p = USER_PROCESSES.choose(rng).unwrap();
            (p.0, p.1, "user".to_string(), p.2)
        };

        let pid = Uniform::new_inclusive(100u32, 65535).sample(rng);
        let ppid = if is_system { 1 } else { Uniform::new_inclusive(1000u32, 5000).sample(rng) };
        let cpu = Uniform::new_inclusive(0.0f32, 15.0).sample(rng);
        let rss_jitter = Uniform::new_inclusive(0u64, base_rss / 2).sample(rng);
        let uptime_secs = Uniform::new_inclusive(60i64, 86400 * 30).sample(rng);
        let start_time = context.now - Duration::seconds(uptime_secs);

        let meta = ArtifactMetadata::new(DataCategory::System, start_time, context.now, 256)?;

        let entry = ProcessEntry {
            meta, pid, ppid, name: name.to_string(), cmdline: cmdline.to_string(),
            user, state: "S".to_string(), cpu_percent: cpu,
            mem_rss_kb: base_rss + rss_jitter, start_time,
        };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory { DataCategory::System }
    fn forensic_weight(&self) -> u32 { 55 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_process() {
        let g = ProcessGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);
        let a = g.generate(&p, &c, &mut r).unwrap();
        a.validate_plausibility().unwrap();
    }

    #[test]
    fn test_500_processes_valid() {
        let g = ProcessGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..500 { let mut r = seeded_rng(s); g.generate(&p, &c, &mut r).unwrap().validate_plausibility().unwrap(); }
    }

    #[test]
    fn test_includes_system_and_user() {
        let g = ProcessGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut sys = false;
        let mut usr = false;
        for s in 0..100 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: ProcessEntry = serde_json::from_slice(&b).unwrap();
            if e.user == "root" { sys = true; }
            if e.user == "user" { usr = true; }
            if sys && usr { break; }
        }
        assert!(sys && usr, "should include both system and user processes");
    }
}
