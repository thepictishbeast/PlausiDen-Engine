//! Extended file metadata and attribute generation.
//!
//! Generates plausible extended attributes (xattrs), ownership, permissions,
//! and provenance metadata for files. Forensic analysts inspect xattrs like
//! `user.xdg.origin.url` (download source), `user.xdg.referrer.url` (referrer),
//! and `user.creator_app` to establish file provenance and activity timelines.

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

/// Extended file metadata entry including xattrs, permissions, and provenance.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct FileMetadataEntry {
    /// Core artifact metadata.
    pub meta: ArtifactMetadata,
    /// Absolute path of the file.
    pub path: String,
    /// Unix permission string (e.g., `-rw-r--r--`).
    pub permissions: String,
    /// Octal permission mode (e.g., `0644`).
    pub mode: String,
    /// File owner username.
    pub owner: String,
    /// File group.
    pub group: String,
    /// Inode number.
    pub inode: u64,
    /// Number of hard links.
    pub hard_links: u32,
    /// File creation time (btime/birth time where supported).
    pub created: DateTime<Utc>,
    /// Last modification time (mtime).
    pub modified: DateTime<Utc>,
    /// Last access time (atime).
    pub accessed: DateTime<Utc>,
    /// Last status change time (ctime).
    pub status_changed: DateTime<Utc>,
    /// Extended attributes as key-value pairs.
    pub xattrs: Vec<XAttr>,
}

/// A single extended attribute entry.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct XAttr {
    /// Attribute name (e.g., `user.xdg.origin.url`).
    pub name: String,
    /// Attribute value.
    pub value: String,
}

impl Artifact for FileMetadataEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.path.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty file path".into(),
            });
        }
        if self.modified < self.created {
            return Err(EngineError::ImplausibleArtifact {
                reason: "mtime before btime".into(),
            });
        }
        if self.inode == 0 {
            return Err(EngineError::ImplausibleArtifact {
                reason: "inode 0 is reserved".into(),
            });
        }
        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

/// Template for a file type and its typical metadata.
struct MetadataTemplate {
    dir: &'static str,
    names: &'static [&'static str],
    ext: &'static str,
    perms: &'static str,
    mode: &'static str,
    owner: &'static str,
    group: &'static str,
    /// Whether this file type typically has download-origin xattrs.
    has_origin: bool,
    /// Application that typically creates this file type.
    creator_app: Option<&'static str>,
}

const METADATA_TEMPLATES: &[MetadataTemplate] = &[
    // User documents.
    MetadataTemplate {
        dir: "/home/user/Documents",
        names: &["report", "budget", "letter", "notes", "proposal", "memo"],
        ext: "docx",
        perms: "-rw-r--r--",
        mode: "0644",
        owner: "user",
        group: "user",
        has_origin: false,
        creator_app: Some("libreoffice"),
    },
    // Downloaded PDFs (have download origin xattrs).
    MetadataTemplate {
        dir: "/home/user/Downloads",
        names: &[
            "invoice", "receipt", "manual", "whitepaper", "form",
            "specification", "datasheet",
        ],
        ext: "pdf",
        perms: "-rw-r--r--",
        mode: "0644",
        owner: "user",
        group: "user",
        has_origin: true,
        creator_app: None,
    },
    // Downloaded images.
    MetadataTemplate {
        dir: "/home/user/Downloads",
        names: &[
            "photo", "image", "attachment", "scan", "capture",
        ],
        ext: "jpg",
        perms: "-rw-r--r--",
        mode: "0644",
        owner: "user",
        group: "user",
        has_origin: true,
        creator_app: None,
    },
    // Config files.
    MetadataTemplate {
        dir: "/home/user/.config",
        names: &["settings", "config", "preferences", "user"],
        ext: "json",
        perms: "-rw-------",
        mode: "0600",
        owner: "user",
        group: "user",
        has_origin: false,
        creator_app: None,
    },
    // Spreadsheets.
    MetadataTemplate {
        dir: "/home/user/Documents",
        names: &["expenses", "timesheet", "inventory", "data", "metrics"],
        ext: "xlsx",
        perms: "-rw-r--r--",
        mode: "0644",
        owner: "user",
        group: "user",
        has_origin: false,
        creator_app: Some("libreoffice"),
    },
    // System logs (read by forensics for timeline corroboration).
    MetadataTemplate {
        dir: "/var/log",
        names: &["syslog", "auth", "kern", "daemon", "messages"],
        ext: "log",
        perms: "-rw-r-----",
        mode: "0640",
        owner: "syslog",
        group: "adm",
        has_origin: false,
        creator_app: None,
    },
    // Executables.
    MetadataTemplate {
        dir: "/usr/bin",
        names: &["python3", "node", "git", "curl", "wget", "vim"],
        ext: "",
        perms: "-rwxr-xr-x",
        mode: "0755",
        owner: "root",
        group: "root",
        has_origin: false,
        creator_app: None,
    },
    // Temp files.
    MetadataTemplate {
        dir: "/tmp",
        names: &["temp_output", "cache_data", "session", "upload"],
        ext: "tmp",
        perms: "-rw-------",
        mode: "0600",
        owner: "user",
        group: "user",
        has_origin: false,
        creator_app: None,
    },
];

/// Download source domains for generating `user.xdg.origin.url` xattrs.
const DOWNLOAD_DOMAINS: &[&str] = &[
    "drive.google.com",
    "docs.google.com",
    "www.dropbox.com",
    "onedrive.live.com",
    "mail.google.com",
    "outlook.office365.com",
    "github.com",
    "stackoverflow.com",
    "arxiv.org",
    "www.irs.gov",
    "www.amazon.com",
    "www.adobe.com",
];

/// Referrer URLs for download-origin xattrs.
const REFERRER_PAGES: &[&str] = &[
    "https://mail.google.com/mail/u/0/",
    "https://drive.google.com/drive/my-drive",
    "https://www.google.com/search?q=download",
    "https://outlook.office365.com/mail/inbox",
    "https://github.com/notifications",
    "https://www.dropbox.com/home",
];

/// Creator application identifiers for xattrs.
const CREATOR_APPS: &[&str] = &[
    "LibreOffice/7.6",
    "LibreOffice/24.2",
    "GIMP/2.10",
    "Inkscape/1.3",
    "Firefox/125.0",
    "Chromium/124.0",
];

/// Generates extended file metadata entries including xattrs, permissions,
/// ownership, timestamps (btime, mtime, atime, ctime), and provenance
/// attributes like download source URLs and creator applications.
pub struct FileMetadataGenerator;

impl FileMetadataGenerator {
    /// Create a new `FileMetadataGenerator`.
    pub fn new() -> Self {
        Self
    }
}

impl Default for FileMetadataGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for FileMetadataGenerator {
    fn generate(
        &self,
        _profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        let tpl = METADATA_TEMPLATES
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("no metadata templates".into()))?;
        let name = tpl
            .names
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("empty name list".into()))?;

        // Build path.
        let filename = if tpl.ext.is_empty() {
            (*name).to_string()
        } else {
            format!("{name}.{}", tpl.ext)
        };
        let path = format!("{}/{filename}", tpl.dir);

        // Inode: realistic range for ext4/btrfs.
        let inode = Uniform::new_inclusive(100_000u64, 9_999_999).sample(rng);
        let hard_links = if tpl.ext.is_empty() { 1 } else {
            if rng.gen_bool(0.1) { 2 } else { 1 }
        };

        // Timestamps: created 1-365 days ago.
        let days_ago = Uniform::new_inclusive(1i64, 365).sample(rng);
        let created = context.now - Duration::days(days_ago);

        // Modified: between created and now.
        let mod_offset_secs =
            Uniform::new_inclusive(0i64, days_ago * 86400).sample(rng);
        let modified = created + Duration::seconds(mod_offset_secs);

        // Accessed: recently (within last 30 days), but not before created.
        let access_days_ago = Uniform::new_inclusive(0i64, 30.min(days_ago)).sample(rng);
        let accessed = context.now - Duration::days(access_days_ago);

        // Status changed (ctime): typically same as or slightly after mtime.
        let ctime_offset = Uniform::new_inclusive(0i64, 3600).sample(rng);
        let status_changed = modified + Duration::seconds(ctime_offset);
        // Clamp to not exceed context.now.
        let status_changed = if status_changed > context.now {
            context.now
        } else {
            status_changed
        };

        // Build xattrs.
        let mut xattrs = Vec::new();

        // Download origin xattrs (for downloaded files).
        if tpl.has_origin {
            let domain = DOWNLOAD_DOMAINS
                .choose(rng)
                .ok_or_else(|| EngineError::InvalidContext("no download domains".into()))?;
            let origin_url = format!("https://{domain}/download/{filename}");
            xattrs.push(XAttr {
                name: "user.xdg.origin.url".to_string(),
                value: origin_url,
            });
            // Referrer about 70% of the time.
            if rng.gen_bool(0.7) {
                let referrer = REFERRER_PAGES
                    .choose(rng)
                    .ok_or_else(|| {
                        EngineError::InvalidContext("no referrer pages".into())
                    })?;
                xattrs.push(XAttr {
                    name: "user.xdg.referrer.url".to_string(),
                    value: (*referrer).to_string(),
                });
            }
        }

        // Creator app xattr.
        if let Some(app) = tpl.creator_app {
            xattrs.push(XAttr {
                name: "user.creator_app".to_string(),
                value: app.to_string(),
            });
        } else if rng.gen_bool(0.2) {
            // Sometimes non-template files also have a creator app.
            let app = CREATOR_APPS
                .choose(rng)
                .ok_or_else(|| EngineError::InvalidContext("no creator apps".into()))?;
            xattrs.push(XAttr {
                name: "user.creator_app".to_string(),
                value: (*app).to_string(),
            });
        }

        // Security context xattr (SELinux/AppArmor) occasionally.
        if rng.gen_bool(0.15) {
            xattrs.push(XAttr {
                name: "security.selinux".to_string(),
                value: "unconfined_u:object_r:user_home_t:s0".to_string(),
            });
        }

        let meta_size = 256 + (xattrs.len() as u64 * 64);
        let meta = ArtifactMetadata::new(
            DataCategory::FileSystem,
            created,
            modified,
            meta_size,
        )?;

        let entry = FileMetadataEntry {
            meta,
            path,
            permissions: tpl.perms.to_string(),
            mode: tpl.mode.to_string(),
            owner: tpl.owner.to_string(),
            group: tpl.group.to_string(),
            inode,
            hard_links,
            created,
            modified,
            accessed,
            status_changed,
            xattrs,
        };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory {
        DataCategory::FileSystem
    }

    fn forensic_weight(&self) -> u32 {
        45
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_metadata_entry() {
        let generator = FileMetadataGenerator::new();
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
        let entry: FileMetadataEntry =
            serde_json::from_slice(&bytes).expect("deserialization failed");
        assert!(!entry.path.is_empty());
        assert!(entry.inode > 0);
        assert!(entry.modified >= entry.created);
    }

    #[test]
    fn test_downloaded_files_have_origin_xattr() {
        let generator = FileMetadataGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut found_origin = false;
        for seed in 0..200 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation failed");
            let bytes = artifact.to_bytes().expect("serialization failed");
            let entry: FileMetadataEntry =
                serde_json::from_slice(&bytes).expect("deserialization failed");
            if entry
                .xattrs
                .iter()
                .any(|xa| xa.name == "user.xdg.origin.url")
            {
                found_origin = true;
                // Origin URL should be well-formed.
                let origin = entry
                    .xattrs
                    .iter()
                    .find(|xa| xa.name == "user.xdg.origin.url")
                    .expect("origin xattr");
                assert!(
                    origin.value.starts_with("https://"),
                    "origin URL should start with https://"
                );
                break;
            }
        }
        assert!(found_origin, "at least one file should have download origin xattr");
    }

    #[test]
    fn test_creator_app_xattr_present() {
        let generator = FileMetadataGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut found_creator = false;
        for seed in 0..200 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation failed");
            let bytes = artifact.to_bytes().expect("serialization failed");
            let entry: FileMetadataEntry =
                serde_json::from_slice(&bytes).expect("deserialization failed");
            if entry
                .xattrs
                .iter()
                .any(|xa| xa.name == "user.creator_app")
            {
                found_creator = true;
                break;
            }
        }
        assert!(found_creator, "at least one file should have creator_app xattr");
    }

    #[test]
    fn test_500_metadata_entries_all_plausible() {
        let generator = FileMetadataGenerator::new();
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
