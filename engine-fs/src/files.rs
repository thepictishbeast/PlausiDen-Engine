//! Recently-accessed document path generation.
//!
//! Generates plausible recently-opened document entries — the kind of artifacts
//! file managers, office suites, and desktop environments track in their
//! "recent files" lists. These entries are among the first things forensic
//! analysts inspect when building a usage timeline.

use chrono::{DateTime, Duration, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::{OccupationCategory, UserProfile};
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext,
};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, Rng, RngCore};
use serde::Serialize;

/// A recently-accessed document entry, mirroring what desktop environments
/// store in their recent-files databases (e.g., `recently-used.xbel`).
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct RecentDocumentEntry {
    /// Core artifact metadata (category, timestamps, size).
    pub meta: ArtifactMetadata,
    /// Full path to the document.
    pub path: String,
    /// Filename only (e.g., `Q3_Budget_Report.xlsx`).
    pub filename: String,
    /// MIME type of the document.
    pub mime_type: String,
    /// Estimated file size in bytes.
    pub file_size: u64,
    /// When the document was originally created.
    pub created: DateTime<Utc>,
    /// When the document was last modified.
    pub modified: DateTime<Utc>,
    /// When the document was last accessed/opened.
    pub accessed: DateTime<Utc>,
    /// Application used to open the file (e.g., `libreoffice`).
    pub application: String,
}

impl Artifact for RecentDocumentEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.filename.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty filename".into(),
            });
        }
        if self.file_size == 0 {
            return Err(EngineError::ImplausibleArtifact {
                reason: "zero-byte document".into(),
            });
        }
        if self.modified < self.created {
            return Err(EngineError::ImplausibleArtifact {
                reason: "modified before created".into(),
            });
        }
        if self.accessed < self.created {
            return Err(EngineError::ImplausibleArtifact {
                reason: "accessed before created".into(),
            });
        }
        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

/// Template for generating a specific type of document.
struct DocTemplate {
    prefixes: &'static [&'static str],
    ext: &'static str,
    mime: &'static str,
    min_bytes: u64,
    max_bytes: u64,
    dirs: &'static [&'static str],
    app: &'static str,
}

/// Base document templates applicable to any user.
const BASE_TEMPLATES: &[DocTemplate] = &[
    DocTemplate {
        prefixes: &[
            "Report", "Summary", "Notes", "Draft", "Memo", "Letter",
            "Proposal", "Overview", "Review", "Outline",
        ],
        ext: "docx",
        mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        min_bytes: 15_000,
        max_bytes: 800_000,
        dirs: &["~/Documents", "~/Downloads", "~/Desktop"],
        app: "libreoffice",
    },
    DocTemplate {
        prefixes: &[
            "Budget", "Expenses", "Inventory", "Timesheet", "Forecast",
            "Sales_Data", "Metrics", "Headcount", "Revenue",
        ],
        ext: "xlsx",
        mime: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        min_bytes: 20_000,
        max_bytes: 2_000_000,
        dirs: &["~/Documents", "~/Downloads"],
        app: "libreoffice",
    },
    DocTemplate {
        prefixes: &[
            "Presentation", "Slides", "Pitch", "Meeting_Deck",
            "Quarterly_Review", "Training", "Onboarding",
        ],
        ext: "pptx",
        mime: "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        min_bytes: 500_000,
        max_bytes: 15_000_000,
        dirs: &["~/Documents", "~/Downloads", "~/Desktop"],
        app: "libreoffice",
    },
    DocTemplate {
        prefixes: &[
            "Invoice", "Receipt", "Contract", "Agreement", "Form",
            "Manual", "Guide", "Whitepaper", "Specification", "Certificate",
        ],
        ext: "pdf",
        mime: "application/pdf",
        min_bytes: 30_000,
        max_bytes: 10_000_000,
        dirs: &["~/Documents", "~/Downloads", "/tmp"],
        app: "evince",
    },
];

/// Additional templates for journalist profiles.
const JOURNALIST_TEMPLATES: &[DocTemplate] = &[
    DocTemplate {
        prefixes: &[
            "Article_Draft", "Interview_Transcript", "Source_Notes",
            "Investigation", "Press_Release", "Briefing",
        ],
        ext: "docx",
        mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        min_bytes: 20_000,
        max_bytes: 500_000,
        dirs: &["~/Documents", "~/Documents/Articles"],
        app: "libreoffice",
    },
];

/// Additional templates for student profiles.
const STUDENT_TEMPLATES: &[DocTemplate] = &[
    DocTemplate {
        prefixes: &[
            "Essay", "Assignment", "Lab_Report", "Thesis_Chapter",
            "Study_Notes", "Homework", "Term_Paper",
        ],
        ext: "docx",
        mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        min_bytes: 10_000,
        max_bytes: 300_000,
        dirs: &["~/Documents", "~/Documents/School", "~/Desktop"],
        app: "libreoffice",
    },
];

/// Additional templates for tech worker profiles.
const TECH_TEMPLATES: &[DocTemplate] = &[
    DocTemplate {
        prefixes: &[
            "Architecture", "Design_Doc", "RFC", "Postmortem",
            "Runbook", "API_Spec", "Migration_Plan",
        ],
        ext: "pdf",
        mime: "application/pdf",
        min_bytes: 50_000,
        max_bytes: 5_000_000,
        dirs: &["~/Documents", "~/Downloads"],
        app: "evince",
    },
];

/// Qualifying suffixes appended to filenames for variety.
const SUFFIXES: &[&str] = &[
    "Q1", "Q2", "Q3", "Q4", "Final", "v2", "v3", "Draft",
    "Revised", "2024", "2025", "2026", "January", "February",
    "March", "April", "May",
];

/// Collect all applicable templates for the given user profile.
fn collect_templates(profile: &UserProfile) -> Vec<&'static DocTemplate> {
    let mut templates: Vec<&DocTemplate> = BASE_TEMPLATES.iter().collect();
    match profile.demographic.occupation {
        OccupationCategory::Journalist => {
            templates.extend(JOURNALIST_TEMPLATES.iter());
        }
        OccupationCategory::Student | OccupationCategory::Academic => {
            templates.extend(STUDENT_TEMPLATES.iter());
        }
        OccupationCategory::TechWorker => {
            templates.extend(TECH_TEMPLATES.iter());
        }
        _ => {}
    }
    templates
}

/// Generates plausible recently-accessed document paths with realistic
/// filenames, sizes, timestamps, and opening applications.
pub struct RecentDocumentsGenerator;

impl RecentDocumentsGenerator {
    /// Create a new `RecentDocumentsGenerator`.
    pub fn new() -> Self {
        Self
    }
}

impl Default for RecentDocumentsGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for RecentDocumentsGenerator {
    fn generate(
        &self,
        profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        let templates = collect_templates(profile);
        let tpl = templates
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("no document templates available".into()))?;

        // Build filename: Prefix_Suffix_YYYYMMDD.ext
        let prefix = tpl
            .prefixes
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("empty prefix list".into()))?;
        let use_suffix = rng.gen_bool(0.6);
        let suffix_part = if use_suffix {
            let s = SUFFIXES
                .choose(rng)
                .ok_or_else(|| EngineError::InvalidContext("empty suffix list".into()))?;
            format!("_{s}")
        } else {
            String::new()
        };
        let use_date = rng.gen_bool(0.4);
        let date_part = if use_date {
            format!("_{}", context.now.format("%Y%m%d"))
        } else {
            String::new()
        };
        let filename = format!("{prefix}{suffix_part}{date_part}.{}", tpl.ext);

        // Pick a directory.
        let dir = tpl
            .dirs
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("empty dirs list".into()))?;
        let path = format!("{dir}/{filename}");

        // File size within template range.
        let file_size = Uniform::new_inclusive(tpl.min_bytes, tpl.max_bytes).sample(rng);

        // Timestamps: created 1-180 days ago, modified between created and now,
        // accessed within the last 14 days (it is a "recent" document) but
        // never before creation.
        let days_ago_created = Uniform::new_inclusive(1i64, 180).sample(rng);
        let created = context.now - Duration::days(days_ago_created);
        let mod_offset_secs =
            Uniform::new_inclusive(0i64, days_ago_created * 86400).sample(rng);
        let modified = created + Duration::seconds(mod_offset_secs);
        let max_access_ago = 14i64.min(days_ago_created);
        let access_days_ago = Uniform::new_inclusive(0i64, max_access_ago).sample(rng);
        let accessed = context.now - Duration::days(access_days_ago);

        let meta = ArtifactMetadata::new(DataCategory::FileSystem, created, modified, file_size)?;

        let entry = RecentDocumentEntry {
            meta,
            path,
            filename,
            mime_type: tpl.mime.to_string(),
            file_size,
            created,
            modified,
            accessed,
            application: tpl.app.to_string(),
        };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory {
        DataCategory::FileSystem
    }

    fn forensic_weight(&self) -> u32 {
        90
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_recent_document() {
        let generator = RecentDocumentsGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);
        let artifact = generator.generate(&profile, &ctx, &mut rng).expect("generation failed");
        artifact.validate_plausibility().expect("plausibility failed");
        let bytes = artifact.to_bytes().expect("serialization failed");
        let entry: RecentDocumentEntry =
            serde_json::from_slice(&bytes).expect("deserialization failed");
        assert!(!entry.filename.is_empty());
        assert!(entry.file_size > 0);
        assert!(entry.modified >= entry.created);
        assert!(entry.accessed >= entry.created);
    }

    #[test]
    fn test_recent_documents_known_extensions() {
        let generator = RecentDocumentsGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let valid_exts = ["docx", "xlsx", "pptx", "pdf"];
        for seed in 0..100 {
            let mut rng = seeded_rng(seed);
            let artifact = generator.generate(&profile, &ctx, &mut rng).expect("generation failed");
            let bytes = artifact.to_bytes().expect("serialization failed");
            let entry: RecentDocumentEntry =
                serde_json::from_slice(&bytes).expect("deserialization failed");
            let has_valid_ext = valid_exts.iter().any(|e| entry.filename.ends_with(e));
            assert!(
                has_valid_ext,
                "filename '{}' does not end with a known extension",
                entry.filename
            );
        }
    }

    #[test]
    fn test_journalist_gets_article_drafts() {
        let generator = RecentDocumentsGenerator::new();
        let mut profile = UserProfile::default();
        profile.demographic.occupation = OccupationCategory::Journalist;
        let ctx = GenerationContext::new();
        let mut found_article = false;
        for seed in 0..300 {
            let mut rng = seeded_rng(seed);
            let artifact = generator.generate(&profile, &ctx, &mut rng).expect("generation failed");
            let bytes = artifact.to_bytes().expect("serialization failed");
            let entry: RecentDocumentEntry =
                serde_json::from_slice(&bytes).expect("deserialization failed");
            if entry.filename.contains("Article") || entry.filename.contains("Interview") {
                found_article = true;
                break;
            }
        }
        assert!(found_article, "journalist profile should produce article/interview docs");
    }

    #[test]
    fn test_500_recent_documents_all_plausible() {
        let generator = RecentDocumentsGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        for seed in 0..500 {
            let mut rng = seeded_rng(seed);
            generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation failed")
                .validate_plausibility()
                .expect("plausibility failed");
        }
    }
}
