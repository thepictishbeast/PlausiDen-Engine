//! Freedesktop Trash (recycle bin) entry generation.
//!
//! Generates plausible entries for `~/.local/share/Trash/` following the
//! [Freedesktop Trash Specification](https://specifications.freedesktop.org/trash-spec/latest/).
//! Each deleted file produces a `.trashinfo` metadata file in `info/` and the
//! actual file content in `files/`. This generator produces the metadata entries
//! that a forensic analyst would examine to reconstruct deletion activity.

use chrono::{DateTime, Duration, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext,
};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, Rng, RngCore};
use serde::Serialize;

/// A Freedesktop Trash entry with `.trashinfo` metadata.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct TrashEntry {
    /// Core artifact metadata.
    pub meta: ArtifactMetadata,
    /// Original absolute path of the deleted file.
    pub original_path: String,
    /// Filename as it appears in `Trash/files/`.
    pub trash_filename: String,
    /// Path to the `.trashinfo` metadata file.
    pub trashinfo_path: String,
    /// Full content of the `.trashinfo` file (INI-like format per the spec).
    pub trashinfo_content: String,
    /// When the file was moved to trash.
    pub deletion_date: DateTime<Utc>,
    /// Original file size in bytes.
    pub file_size: u64,
    /// MIME type of the trashed file.
    pub mime_type: String,
}

impl Artifact for TrashEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.original_path.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty original path".into(),
            });
        }
        if self.file_size == 0 {
            return Err(EngineError::ImplausibleArtifact {
                reason: "zero-byte trashed file".into(),
            });
        }
        if !self.trashinfo_content.starts_with("[Trash Info]") {
            return Err(EngineError::ImplausibleArtifact {
                reason: "trashinfo content must start with [Trash Info]".into(),
            });
        }
        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

/// Template for a type of file that commonly gets deleted.
struct TrashTemplate {
    dir: &'static str,
    names: &'static [&'static str],
    ext: &'static str,
    mime: &'static str,
    min_bytes: u64,
    max_bytes: u64,
}

const TRASH_TEMPLATES: &[TrashTemplate] = &[
    // Installers and archives (large, often deleted after use).
    TrashTemplate {
        dir: "/home/user/Downloads",
        names: &[
            "firefox-setup",
            "vscode-update",
            "zoom-installer",
            "slack-desktop",
            "libreoffice-installer",
            "steam_setup",
            "driver-update",
        ],
        ext: "deb",
        mime: "application/vnd.debian.binary-package",
        min_bytes: 10_000_000,
        max_bytes: 200_000_000,
    },
    TrashTemplate {
        dir: "/home/user/Downloads",
        names: &[
            "project-backup",
            "photos-2024",
            "old-documents",
            "archive",
            "export",
            "migration-data",
        ],
        ext: "tar.gz",
        mime: "application/gzip",
        min_bytes: 5_000_000,
        max_bytes: 500_000_000,
    },
    // Old document drafts.
    TrashTemplate {
        dir: "/home/user/Documents",
        names: &[
            "draft_v1",
            "old_report",
            "untitled",
            "notes_backup",
            "meeting_minutes_old",
            "todo_list",
            "scratch",
        ],
        ext: "docx",
        mime: "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        min_bytes: 15_000,
        max_bytes: 500_000,
    },
    // Screenshots and images.
    TrashTemplate {
        dir: "/home/user/Pictures",
        names: &[
            "screenshot_old",
            "blurry_photo",
            "duplicate",
            "IMG_temp",
            "cropped_image",
        ],
        ext: "png",
        mime: "image/png",
        min_bytes: 100_000,
        max_bytes: 5_000_000,
    },
    // Temp files.
    TrashTemplate {
        dir: "/home/user/Desktop",
        names: &["temp", "test", "Untitled", "New_Document", "Copy_of_file"],
        ext: "txt",
        mime: "text/plain",
        min_bytes: 100,
        max_bytes: 50_000,
    },
    // PDFs from downloads.
    TrashTemplate {
        dir: "/home/user/Downloads",
        names: &[
            "receipt",
            "boarding_pass",
            "ticket",
            "confirmation",
            "old_manual",
            "expired_certificate",
        ],
        ext: "pdf",
        mime: "application/pdf",
        min_bytes: 30_000,
        max_bytes: 5_000_000,
    },
    // Spreadsheets.
    TrashTemplate {
        dir: "/home/user/Documents",
        names: &["budget_old", "expenses_2023", "data_export", "calculations"],
        ext: "xlsx",
        mime: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        min_bytes: 20_000,
        max_bytes: 2_000_000,
    },
];

/// Build the `.trashinfo` file content per the Freedesktop spec.
///
/// Format:
/// ```text
/// [Trash Info]
/// Path=/original/absolute/path
/// DeletionDate=2025-03-15T14:30:22
/// ```
fn build_trashinfo(original_path: &str, deletion_date: &DateTime<Utc>) -> String {
    format!(
        "[Trash Info]\nPath={original_path}\nDeletionDate={}\n",
        deletion_date.format("%Y-%m-%dT%H:%M:%S")
    )
}

/// Generates trash/recycle bin entries following the Freedesktop Trash
/// Specification, including `.trashinfo` metadata with original paths
/// and RFC 3339 deletion dates.
pub struct TrashGenerator;

impl TrashGenerator {
    /// Create a new `TrashGenerator`.
    pub fn new() -> Self {
        Self
    }
}

impl Default for TrashGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for TrashGenerator {
    fn generate(
        &self,
        _profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        let tpl = TRASH_TEMPLATES
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("no trash templates".into()))?;
        let name = tpl
            .names
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("empty name list".into()))?;

        // Add optional numeric suffix for uniqueness.
        let use_suffix = rng.gen_bool(0.4);
        let suffix = if use_suffix {
            let n: u32 = Uniform::new_inclusive(1, 999).sample(rng);
            format!("_{n}")
        } else {
            String::new()
        };
        let original_filename = format!("{name}{suffix}.{}", tpl.ext);
        let original_path = format!("{}/{original_filename}", tpl.dir);

        // File size.
        let file_size = Uniform::new_inclusive(tpl.min_bytes, tpl.max_bytes).sample(rng);

        // Deletion date: 1-60 days ago (trash is typically emptied periodically).
        let days_ago = Uniform::new_inclusive(1i64, 60).sample(rng);
        let hours_offset = Uniform::new_inclusive(0i64, 23).sample(rng);
        let minutes_offset = Uniform::new_inclusive(0i64, 59).sample(rng);
        let deletion_date = context.now - Duration::days(days_ago)
            + Duration::hours(hours_offset)
            + Duration::minutes(minutes_offset);
        // Clamp to not exceed context.now.
        let deletion_date = if deletion_date > context.now {
            context.now
        } else {
            deletion_date
        };

        // The trash filename may have a numeric suffix if a file with the same
        // name was already in trash (e.g., `draft_v1.2.docx`).
        let collision_suffix = if rng.gen_bool(0.15) {
            let n: u32 = Uniform::new_inclusive(2, 5).sample(rng);
            format!(".{n}")
        } else {
            String::new()
        };
        let trash_filename = format!("{name}{suffix}{collision_suffix}.{}", tpl.ext);

        let trash_base = "/home/user/.local/share/Trash";
        let trashinfo_path = format!("{trash_base}/info/{trash_filename}.trashinfo");
        let trashinfo_content = build_trashinfo(&original_path, &deletion_date);

        let meta = ArtifactMetadata::new(
            DataCategory::FileSystem,
            deletion_date,
            deletion_date,
            file_size,
        )?;

        let entry = TrashEntry {
            meta,
            original_path,
            trash_filename,
            trashinfo_path,
            trashinfo_content,
            deletion_date,
            file_size,
            mime_type: tpl.mime.to_string(),
        };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory {
        DataCategory::FileSystem
    }

    fn forensic_weight(&self) -> u32 {
        55
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_trash_entry() {
        let generator = TrashGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);
        let artifact = generator
            .generate(&profile, &ctx, &mut rng)
            .expect("generation failed");
        artifact
            .validate_plausibility()
            .expect("plausibility failed");
        let bytes = artifact.to_bytes().expect("serialization failed");
        let entry: TrashEntry = serde_json::from_slice(&bytes).expect("deserialization failed");
        assert!(!entry.original_path.is_empty());
        assert!(entry.file_size > 0);
        assert!(entry.trashinfo_content.starts_with("[Trash Info]"));
        assert!(entry.trashinfo_path.ends_with(".trashinfo"));
    }

    #[test]
    fn test_trashinfo_format_compliance() {
        let generator = TrashGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        for seed in 0..100 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation failed");
            let bytes = artifact.to_bytes().expect("serialization failed");
            let entry: TrashEntry = serde_json::from_slice(&bytes).expect("deserialization failed");
            // Validate .trashinfo format.
            let lines: Vec<&str> = entry.trashinfo_content.lines().collect();
            assert_eq!(lines[0], "[Trash Info]", "first line must be [Trash Info]");
            assert!(
                lines[1].starts_with("Path="),
                "second line must start with Path="
            );
            assert!(
                lines[2].starts_with("DeletionDate="),
                "third line must start with DeletionDate="
            );
            // Path in trashinfo must match original_path.
            let path_value = lines[1].strip_prefix("Path=").expect("Path= prefix");
            assert_eq!(path_value, entry.original_path);
        }
    }

    #[test]
    fn test_trash_paths_under_trash_dir() {
        let generator = TrashGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        for seed in 0..50 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation failed");
            let bytes = artifact.to_bytes().expect("serialization failed");
            let entry: TrashEntry = serde_json::from_slice(&bytes).expect("deserialization failed");
            assert!(
                entry
                    .trashinfo_path
                    .starts_with("/home/user/.local/share/Trash/info/"),
                "trashinfo path should be under Trash/info/: {}",
                entry.trashinfo_path,
            );
        }
    }
}
