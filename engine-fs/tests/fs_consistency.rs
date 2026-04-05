//! Cross-artifact consistency tests for all engine-fs generators.
//!
//! Validates forensic plausibility invariants that hold across every
//! generated filesystem artifact, regardless of seed or profile.

use engine_core::entropy::seeded_rng;
use engine_core::profile::UserProfile;
use engine_core::traits::{DataGenerator, GenerationContext};
use engine_fs::files::{FileEntry, FileGenerator};
use engine_fs::metadata::{MetadataEntry, MetadataGenerator};
use engine_fs::thumbnails::{ThumbnailEntry, ThumbnailGenerator};
use engine_fs::trash::{TrashEntry, TrashGenerator};

// ---------------------------------------------------------------------------
// Helpers — generate & deserialize in one step
// ---------------------------------------------------------------------------

fn make_file(seed: u64) -> FileEntry {
    let generator = FileGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(seed);
    let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
    serde_json::from_slice(&artifact.to_bytes().unwrap()).unwrap()
}

fn make_thumbnail(seed: u64) -> ThumbnailEntry {
    let generator = ThumbnailGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(seed);
    let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
    serde_json::from_slice(&artifact.to_bytes().unwrap()).unwrap()
}

fn make_trash(seed: u64) -> TrashEntry {
    let generator = TrashGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(seed);
    let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
    serde_json::from_slice(&artifact.to_bytes().unwrap()).unwrap()
}

fn make_metadata(seed: u64) -> MetadataEntry {
    let generator = MetadataGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();
    let mut rng = seeded_rng(seed);
    let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
    serde_json::from_slice(&artifact.to_bytes().unwrap()).unwrap()
}

// ---------------------------------------------------------------------------
// 1. File sizes always > 0
// ---------------------------------------------------------------------------

#[test]
fn file_sizes_always_positive() {
    for seed in 0..500 {
        let entry = make_file(seed);
        assert!(
            entry.file_size > 0,
            "seed {seed}: file_size was 0 for '{}'",
            entry.filename,
        );
    }
}

// ---------------------------------------------------------------------------
// 2. Filenames never contain path separators (/ or \)
// ---------------------------------------------------------------------------

#[test]
fn filenames_never_contain_path_separators() {
    for seed in 0..500 {
        let entry = make_file(seed);
        assert!(
            !entry.filename.contains('/') && !entry.filename.contains('\\'),
            "seed {seed}: filename '{}' contains a path separator",
            entry.filename,
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Timestamps: modified >= created for all file entries
// ---------------------------------------------------------------------------

#[test]
fn file_modified_never_before_created() {
    for seed in 0..500 {
        let entry = make_file(seed);
        assert!(
            entry.modified >= entry.created,
            "seed {seed}: modified ({}) < created ({}) for '{}'",
            entry.modified,
            entry.created,
            entry.filename,
        );
    }
}

// ---------------------------------------------------------------------------
// 4. Thumbnail URIs point to cache directories
// ---------------------------------------------------------------------------

#[test]
fn thumbnail_uris_point_to_cache() {
    for seed in 0..500 {
        let entry = make_thumbnail(seed);
        assert!(
            entry.thumbnail_uri.contains(".cache/thumbnails"),
            "seed {seed}: thumbnail_uri '{}' does not reference a cache directory",
            entry.thumbnail_uri,
        );
    }
}

// ---------------------------------------------------------------------------
// 5. Trash entries have deletion timestamp after creation
// ---------------------------------------------------------------------------

#[test]
fn trash_deleted_at_after_artifact_creation() {
    for seed in 0..500 {
        let entry = make_trash(seed);
        // The artifact's own metadata created_at represents when the trash
        // record was made — deleted_at should be >= that timestamp.
        assert!(
            entry.deleted_at >= entry.meta.created_at,
            "seed {seed}: deleted_at ({}) < meta.created_at ({}) for '{}'",
            entry.deleted_at,
            entry.meta.created_at,
            entry.original_path,
        );
    }
}

// ---------------------------------------------------------------------------
// 6. Metadata permissions match Unix format (rwx pattern)
// ---------------------------------------------------------------------------

#[test]
fn metadata_permissions_match_unix_format() {
    // Standard Unix permission string: type char + 3 rwx triples.
    // Each position is the expected letter or '-'.
    let is_valid_perm = |s: &str| -> bool {
        let bytes = s.as_bytes();
        if bytes.len() != 10 {
            return false;
        }
        // First char: file type (-, d, l, c, b, p, s)
        if !b"-dlcbps".contains(&bytes[0]) {
            return false;
        }
        // Three rwx triples
        for triple in 0..3 {
            let base = 1 + triple * 3;
            if bytes[base] != b'r' && bytes[base] != b'-' {
                return false;
            }
            if bytes[base + 1] != b'w' && bytes[base + 1] != b'-' {
                return false;
            }
            // Execute can also be s/S/t/T for setuid/setgid/sticky
            if !b"-xsStT".contains(&bytes[base + 2]) {
                return false;
            }
        }
        true
    };

    for seed in 0..500 {
        let entry = make_metadata(seed);
        assert!(
            is_valid_perm(&entry.permissions),
            "seed {seed}: permissions '{}' do not match Unix rwx format",
            entry.permissions,
        );
    }
}

// ---------------------------------------------------------------------------
// 7. MIME types are valid (contain /)
// ---------------------------------------------------------------------------

#[test]
fn mime_types_contain_slash() {
    for seed in 0..500 {
        let file = make_file(seed);
        assert!(
            file.mime_type.contains('/'),
            "seed {seed}: file mime_type '{}' missing '/'",
            file.mime_type,
        );

        let thumb = make_thumbnail(seed);
        assert!(
            thumb.mime_type.contains('/'),
            "seed {seed}: thumbnail mime_type '{}' missing '/'",
            thumb.mime_type,
        );
    }
}

// ---------------------------------------------------------------------------
// 8. 500-entry stress across all 4 generators
// ---------------------------------------------------------------------------

#[test]
fn stress_500_entries_all_generators() {
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    let file_gen = FileGenerator::new();
    let thumb_gen = ThumbnailGenerator::new();
    let trash_gen = TrashGenerator::new();
    let meta_gen = MetadataGenerator::new();

    for seed in 0..500 {
        let mut rng = seeded_rng(seed);
        file_gen
            .generate(&profile, &ctx, &mut rng)
            .unwrap()
            .validate_plausibility()
            .unwrap();

        let mut rng = seeded_rng(seed);
        thumb_gen
            .generate(&profile, &ctx, &mut rng)
            .unwrap()
            .validate_plausibility()
            .unwrap();

        let mut rng = seeded_rng(seed);
        trash_gen
            .generate(&profile, &ctx, &mut rng)
            .unwrap()
            .validate_plausibility()
            .unwrap();

        let mut rng = seeded_rng(seed);
        meta_gen
            .generate(&profile, &ctx, &mut rng)
            .unwrap()
            .validate_plausibility()
            .unwrap();
    }
}
