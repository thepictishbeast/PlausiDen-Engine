//! Freedesktop thumbnail cache entry generation.
//!
//! Generates plausible entries for the `~/.cache/thumbnails/` directory
//! following the [Freedesktop Thumbnail Managing Standard](https://specifications.freedesktop.org/thumbnail-spec/latest/).
//! Thumbnail filenames are MD5 hashes of the canonical `file://` URI,
//! stored as PNG files in `normal/` (128x128) or `large/` (256x256) subdirs.

use chrono::{DateTime, Duration, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext,
};
use md5::{Digest, Md5};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, Rng, RngCore};
use serde::Serialize;

/// A thumbnail cache entry following the Freedesktop spec.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ThumbnailCacheEntry {
    /// Core artifact metadata.
    pub meta: ArtifactMetadata,
    /// Absolute path of the source file that was thumbnailed.
    pub original_path: String,
    /// Canonical `file://` URI of the source file.
    pub original_uri: String,
    /// Path to the cached thumbnail PNG.
    pub thumbnail_path: String,
    /// MD5 hex digest of the canonical URI (used as thumbnail filename).
    pub uri_md5: String,
    /// MIME type of the original file.
    pub mime_type: String,
    /// Thumbnail size class.
    pub size_class: ThumbnailSize,
    /// Pixel width of the thumbnail.
    pub width: u32,
    /// Pixel height of the thumbnail.
    pub height: u32,
    /// Modification time of the original file (stored in the PNG tEXt chunk).
    pub original_mtime: DateTime<Utc>,
    /// When the thumbnail was generated/cached.
    pub cached_at: DateTime<Utc>,
}

/// Thumbnail size classes per the Freedesktop spec.
#[derive(Debug, Clone, Copy, Serialize, serde::Deserialize, PartialEq, Eq)]
pub enum ThumbnailSize {
    /// 128x128 max — stored in `normal/`.
    Normal,
    /// 256x256 max — stored in `large/`.
    Large,
}

impl ThumbnailSize {
    /// Maximum pixel dimension for this size class.
    pub fn max_dimension(&self) -> u32 {
        match self {
            Self::Normal => 128,
            Self::Large => 256,
        }
    }

    /// Subdirectory name per the Freedesktop spec.
    pub fn subdir(&self) -> &'static str {
        match self {
            Self::Normal => "normal",
            Self::Large => "large",
        }
    }
}

/// Source file templates for thumbnailable content.
struct ThumbSource {
    dir: &'static str,
    names: &'static [&'static str],
    ext: &'static str,
    mime: &'static str,
}

const THUMB_SOURCES: &[ThumbSource] = &[
    ThumbSource {
        dir: "/home/user/Pictures",
        names: &[
            "vacation", "family_photo", "selfie", "landscape", "sunset",
            "group_pic", "birthday", "IMG_20250315", "IMG_20241122",
            "screenshot_2025",
        ],
        ext: "jpg",
        mime: "image/jpeg",
    },
    ThumbSource {
        dir: "/home/user/Pictures",
        names: &[
            "screenshot", "wallpaper", "diagram", "infographic", "banner",
        ],
        ext: "png",
        mime: "image/png",
    },
    ThumbSource {
        dir: "/home/user/Documents",
        names: &[
            "report", "invoice", "contract", "resume", "cover_letter",
            "tax_return", "manual",
        ],
        ext: "pdf",
        mime: "application/pdf",
    },
    ThumbSource {
        dir: "/home/user/Videos",
        names: &[
            "clip", "recording", "tutorial", "presentation_recording",
            "screen_capture",
        ],
        ext: "mp4",
        mime: "video/mp4",
    },
    ThumbSource {
        dir: "/home/user/Downloads",
        names: &[
            "downloaded_image", "attachment", "scan", "photo_received",
        ],
        ext: "jpg",
        mime: "image/jpeg",
    },
    ThumbSource {
        dir: "/home/user/Documents",
        names: &[
            "spreadsheet", "budget", "grades", "schedule",
        ],
        ext: "xlsx",
        mime: "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    },
];

/// Compute the MD5 hex digest of a canonical `file://` URI, as used by the
/// Freedesktop thumbnail spec to derive the thumbnail filename.
fn md5_uri(uri: &str) -> String {
    let mut hasher = Md5::new();
    hasher.update(uri.as_bytes());
    let result = hasher.finalize();
    // Convert to lowercase hex string.
    result.iter().map(|b| format!("{b:02x}")).collect()
}

/// Generates thumbnail cache entries with proper Freedesktop-spec MD5 URI
/// hashing for filenames, realistic source file paths, and both normal
/// and large size classes.
pub struct ThumbnailCacheGenerator;

impl ThumbnailCacheGenerator {
    /// Create a new `ThumbnailCacheGenerator`.
    pub fn new() -> Self {
        Self
    }
}

impl Default for ThumbnailCacheGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for ThumbnailCacheGenerator {
    fn generate(
        &self,
        _profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        // Pick a source file.
        let source = THUMB_SOURCES
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("no thumbnail sources".into()))?;
        let name = source
            .names
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("empty name list".into()))?;

        // Add a numeric suffix sometimes for variety.
        let use_suffix = rng.gen_bool(0.3);
        let suffix = if use_suffix {
            let n: u32 = Uniform::new_inclusive(1, 99).sample(rng);
            format!("_{n}")
        } else {
            String::new()
        };
        let filename = format!("{name}{suffix}.{}", source.ext);
        let original_path = format!("{}/{filename}", source.dir);

        // Canonical URI per Freedesktop spec.
        let original_uri = format!("file://{original_path}");
        let uri_hash = md5_uri(&original_uri);

        // Pick size class.
        let size_class = if rng.gen_bool(0.6) {
            ThumbnailSize::Normal
        } else {
            ThumbnailSize::Large
        };
        let max_dim = size_class.max_dimension();

        // Thumbnail dimensions: maintain aspect ratio with max constraint.
        // Most images are wider than tall, but randomize.
        let (width, height) = if rng.gen_bool(0.7) {
            // Landscape
            let h = Uniform::new_inclusive(max_dim / 2, max_dim).sample(rng);
            (max_dim, h)
        } else {
            // Portrait
            let w = Uniform::new_inclusive(max_dim / 2, max_dim).sample(rng);
            (w, max_dim)
        };

        let thumbnail_path = format!(
            "{}/.cache/thumbnails/{}/{uri_hash}.png",
            "/home/user",
            size_class.subdir()
        );

        // Timestamps: original file created 1-365 days ago, thumbnail cached
        // sometime after that.
        let days_ago_original = Uniform::new_inclusive(1i64, 365).sample(rng);
        let original_mtime = context.now - Duration::days(days_ago_original);
        let cache_delay_hours = Uniform::new_inclusive(0i64, 24 * 30).sample(rng);
        let cached_at_candidate = original_mtime + Duration::hours(cache_delay_hours);
        // Ensure cached_at does not exceed context.now.
        let cached_at = if cached_at_candidate > context.now {
            context.now
        } else {
            cached_at_candidate
        };

        // Thumbnail PNG size: typically 5-50 KiB.
        let thumb_size = Uniform::new_inclusive(5_000u64, 50_000).sample(rng);
        let meta = ArtifactMetadata::new(DataCategory::FileSystem, cached_at, cached_at, thumb_size)?;

        let entry = ThumbnailCacheEntry {
            meta,
            original_path,
            original_uri,
            thumbnail_path,
            uri_md5: uri_hash,
            mime_type: source.mime.to_string(),
            size_class,
            width,
            height,
            original_mtime,
            cached_at,
        };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory {
        DataCategory::FileSystem
    }

    fn forensic_weight(&self) -> u32 {
        40
    }
}

impl Artifact for ThumbnailCacheEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.uri_md5.len() != 32 {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!(
                    "MD5 hash should be 32 hex chars, got {}",
                    self.uri_md5.len()
                ),
            });
        }
        if self.width == 0 || self.height == 0 {
            return Err(EngineError::ImplausibleArtifact {
                reason: "thumbnail dimensions must be non-zero".into(),
            });
        }
        let max_dim = self.size_class.max_dimension();
        if self.width > max_dim || self.height > max_dim {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!(
                    "dimensions {}x{} exceed {} limit for {:?}",
                    self.width, self.height, max_dim, self.size_class
                ),
            });
        }
        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_md5_uri_deterministic() {
        let uri = "file:///home/user/Pictures/vacation.jpg";
        let hash1 = md5_uri(uri);
        let hash2 = md5_uri(uri);
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
        // Should be lowercase hex only.
        assert!(hash1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_generate_thumbnail_entry() {
        let generator = ThumbnailCacheGenerator::new();
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
        let entry: ThumbnailCacheEntry =
            serde_json::from_slice(&bytes).expect("deserialization failed");
        assert!(entry.thumbnail_path.contains(".cache/thumbnails/"));
        assert!(entry.thumbnail_path.ends_with(".png"));
        assert_eq!(entry.uri_md5.len(), 32);
    }

    #[test]
    fn test_thumbnail_dimensions_within_size_class() {
        let generator = ThumbnailCacheGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        for seed in 0..200 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation failed");
            let bytes = artifact.to_bytes().expect("serialization failed");
            let entry: ThumbnailCacheEntry =
                serde_json::from_slice(&bytes).expect("deserialization failed");
            let max_dim = entry.size_class.max_dimension();
            assert!(
                entry.width <= max_dim && entry.height <= max_dim,
                "dimensions {}x{} exceed {:?} limit of {max_dim}",
                entry.width,
                entry.height,
                entry.size_class,
            );
        }
    }

    #[test]
    fn test_thumbnail_uri_matches_path() {
        let generator = ThumbnailCacheGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        for seed in 0..50 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .expect("generation failed");
            let bytes = artifact.to_bytes().expect("serialization failed");
            let entry: ThumbnailCacheEntry =
                serde_json::from_slice(&bytes).expect("deserialization failed");
            // URI should be file:// + original_path.
            let expected_uri = format!("file://{}", entry.original_path);
            assert_eq!(entry.original_uri, expected_uri);
            // MD5 should match the URI.
            let expected_md5 = md5_uri(&entry.original_uri);
            assert_eq!(entry.uri_md5, expected_md5);
        }
    }
}
