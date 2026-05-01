//! Download history generation — realistic file downloads.

use chrono::{DateTime, Duration, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::schedule::pick_active_timestamp;
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext, ResourceCost,
};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DownloadEntry {
    pub meta: ArtifactMetadata,
    pub url: String,
    pub filename: String,
    pub mime_type: String,
    pub size_bytes: u64,
    pub started_at: DateTime<Utc>,
    pub completed_at: DateTime<Utc>,
}

impl Artifact for DownloadEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }
    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.filename.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty download filename".into(),
            });
        }
        if self.completed_at < self.started_at {
            return Err(EngineError::ImplausibleArtifact {
                reason: "completed before started".into(),
            });
        }
        if self.size_bytes == 0 {
            return Err(EngineError::ImplausibleArtifact {
                reason: "zero-byte download".into(),
            });
        }
        Ok(())
    }
    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

struct DownloadTemplate {
    domain: &'static str,
    path: &'static str,
    filename: &'static str,
    mime: &'static str,
    min_size: u64,
    max_size: u64,
}

const DOWNLOAD_TEMPLATES: &[DownloadTemplate] = &[
    DownloadTemplate {
        domain: "github.com",
        path: "/releases/download/v1.0/",
        filename: "release.tar.gz",
        mime: "application/gzip",
        min_size: 1_000_000,
        max_size: 50_000_000,
    },
    DownloadTemplate {
        domain: "dl.google.com",
        path: "/chrome/",
        filename: "google-chrome-stable.deb",
        mime: "application/vnd.debian.binary-package",
        min_size: 80_000_000,
        max_size: 100_000_000,
    },
    DownloadTemplate {
        domain: "cdn.mozilla.net",
        path: "/firefox/releases/",
        filename: "firefox.tar.bz2",
        mime: "application/x-bzip2",
        min_size: 60_000_000,
        max_size: 80_000_000,
    },
    DownloadTemplate {
        domain: "files.pythonhosted.org",
        path: "/packages/",
        filename: "package.whl",
        mime: "application/zip",
        min_size: 50_000,
        max_size: 5_000_000,
    },
    DownloadTemplate {
        domain: "arxiv.org",
        path: "/pdf/2401.",
        filename: "paper.pdf",
        mime: "application/pdf",
        min_size: 200_000,
        max_size: 10_000_000,
    },
    DownloadTemplate {
        domain: "images.unsplash.com",
        path: "/photo-",
        filename: "photo.jpg",
        mime: "image/jpeg",
        min_size: 500_000,
        max_size: 15_000_000,
    },
    DownloadTemplate {
        domain: "download.documentfoundation.org",
        path: "/libreoffice/",
        filename: "LibreOffice.deb",
        mime: "application/vnd.debian.binary-package",
        min_size: 200_000_000,
        max_size: 300_000_000,
    },
    DownloadTemplate {
        domain: "releases.ubuntu.com",
        path: "/24.04/",
        filename: "ubuntu-desktop.iso",
        mime: "application/x-iso9660-image",
        min_size: 3_000_000_000,
        max_size: 5_000_000_000,
    },
    DownloadTemplate {
        domain: "zoom.us",
        path: "/client/",
        filename: "zoom_amd64.deb",
        mime: "application/vnd.debian.binary-package",
        min_size: 30_000_000,
        max_size: 50_000_000,
    },
    DownloadTemplate {
        domain: "static.rust-lang.org",
        path: "/dist/",
        filename: "rust-analyzer.tar.xz",
        mime: "application/x-xz",
        min_size: 10_000_000,
        max_size: 30_000_000,
    },
];

pub struct DownloadGenerator;
impl DownloadGenerator {
    pub fn new() -> Self {
        Self
    }
}
impl Default for DownloadGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for DownloadGenerator {
    fn generate(
        &self,
        profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        // SAFETY: DOWNLOAD_TEMPLATES is a non-empty const slice.
        let tpl = DOWNLOAD_TEMPLATES
            .choose(rng)
            .expect("DOWNLOAD_TEMPLATES is a non-empty const slice");
        let suffix = Uniform::new_inclusive(1000u32, 9999).sample(rng);
        let filename = format!("{}_{}", suffix, tpl.filename);
        let url = format!("https://{}{}{}", tpl.domain, tpl.path, filename);
        let size = Uniform::new_inclusive(tpl.min_size, tpl.max_size).sample(rng);

        // Pick a calendar day in the recent past, then snap the
        // hour-of-day to a circadian-active slot for `profile`. The
        // day-and-hour split ensures distinct downloads land on
        // different days *and* respect the user's wake/sleep cycle.
        // SECURITY: a forensic analyst comparing the download log
        // against the user's circadian baseline cannot flag synthetic
        // 3 AM downloads when the timestamp distribution mirrors
        // genuine activity. See `pick_active_timestamp` in engine-core
        // for the weighting rationale.
        let days_ago = Uniform::new_inclusive(1i64, 90).sample(rng);
        let target_date = context.now - Duration::days(days_ago);
        let started_at = pick_active_timestamp(profile, target_date, rng)?;
        // Download duration based on size (simulate ~10 MB/s connection)
        let download_secs = (size / 10_000_000).max(1);
        let completed_at = started_at + Duration::seconds(download_secs as i64);

        let meta = ArtifactMetadata::new(
            DataCategory::BrowserActivity,
            started_at,
            completed_at,
            size,
        )?;

        let entry = DownloadEntry {
            meta,
            url,
            filename,
            mime_type: tpl.mime.to_string(),
            size_bytes: size,
            started_at,
            completed_at,
        };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }
    fn category(&self) -> DataCategory {
        DataCategory::BrowserActivity
    }
    fn forensic_weight(&self) -> u32 {
        75
    }
    fn resource_cost(&self) -> ResourceCost {
        ResourceCost {
            cpu_us: 30,
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
    fn test_generate_download() {
        let g = DownloadGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);
        let a = g.generate(&p, &c, &mut r).unwrap();
        a.validate_plausibility().unwrap();
        let b = a.to_bytes().unwrap();
        let e: DownloadEntry = serde_json::from_slice(&b).unwrap();
        assert!(!e.filename.is_empty());
        assert!(e.size_bytes > 0);
        assert!(e.completed_at >= e.started_at);
    }

    #[test]
    fn test_200_downloads_valid() {
        let g = DownloadGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..200 {
            let mut r = seeded_rng(s);
            g.generate(&p, &c, &mut r)
                .unwrap()
                .validate_plausibility()
                .unwrap();
        }
    }

    #[test]
    fn test_download_duration_scales_with_size() {
        let g = DownloadGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..50 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: DownloadEntry = serde_json::from_slice(&b).unwrap();
            let duration = (e.completed_at - e.started_at).num_seconds();
            assert!(duration >= 1, "download should take at least 1 second");
        }
    }

    /// Forensic-plausibility regression: downloads must cluster in
    /// the user's circadian-active window. Previously the start time
    /// was sampled uniformly across the whole 24h clock, leaving a
    /// detectable signal for a forensic analyst comparing the
    /// download log against the user's known wake/sleep pattern.
    /// REGRESSION-GUARD: ≥80% of 1000 sampled downloads must land
    /// in the active hours of the default profile.
    #[test]
    fn test_downloads_cluster_in_active_hours() {
        use engine_core::profile::ActivitySchedule;
        use engine_core::schedule::OrganicScheduler;

        let g = DownloadGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let scheduler = OrganicScheduler::new(ActivitySchedule::default(), p.risk_level);
        let mut active = 0;
        let n = 1000;
        for s in 0..n {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: DownloadEntry = serde_json::from_slice(&b).unwrap();
            if scheduler.is_active_hour(e.started_at) {
                active += 1;
            }
        }
        let pct = active * 100 / n;
        assert!(
            pct >= 80,
            "expected ≥80% of downloads in active hours, got {}/{} ({}%)",
            active,
            n,
            pct
        );
    }
}
