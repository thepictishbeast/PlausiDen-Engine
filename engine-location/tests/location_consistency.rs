//! Cross-artifact consistency tests for all location generators.
//!
//! These tests verify that GPS, WiFi, cell tower, and EXIF generators
//! produce mutually consistent artifacts that would survive forensic
//! cross-referencing.

use engine_core::entropy::seeded_rng;
use engine_core::profile::UserProfile;
use engine_core::traits::{Artifact, DataGenerator, GenerationContext};
use engine_location::cell::{CellEntry, CellGenerator};
use engine_location::exif::{ExifEntry, ExifGenerator};
use engine_location::gps::GpsGenerator;
use engine_location::wifi::{WifiEntry, WifiGenerator};

/// Continental US latitude bounds.
const US_LAT_MIN: f64 = 24.5;
const US_LAT_MAX: f64 = 49.0;
/// Continental US longitude bounds.
const US_LON_MIN: f64 = -125.0;
const US_LON_MAX: f64 = -66.9;

/// Known US carrier (MCC, MNC) pairs.
const KNOWN_US_MCC_MNC: &[(u16, u16)] = &[
    (310, 260),  // T-Mobile
    (310, 410),  // AT&T
    (311, 480),  // Verizon
    (310, 120),  // Sprint
    (310, 150),  // Cricket
    (310, 580),  // US Cellular
];

fn default_profile() -> UserProfile {
    UserProfile::default()
}

fn default_context() -> GenerationContext {
    GenerationContext::new()
}

// ---------------------------------------------------------------------------
// 1. GPS coordinates always within continental US bounds
// ---------------------------------------------------------------------------

#[test]
fn gps_coordinates_within_continental_us() {
    let profile = default_profile();
    let ctx = default_context();

    // Test first-point generation across many seeds.
    // The first point is always seeded inside US bounds.
    // Subsequent trace points may drift, so we test initial generation here.
    for seed in 0..200 {
        let gps_gen = GpsGenerator::new();
        let mut rng = seeded_rng(seed);
        let artifact = gps_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: engine_location::GpsEntry = serde_json::from_slice(&bytes).unwrap();

        assert!(
            entry.lat >= US_LAT_MIN && entry.lat <= US_LAT_MAX,
            "seed {seed}: latitude {:.6} outside US bounds [{US_LAT_MIN}, {US_LAT_MAX}]",
            entry.lat,
        );
        assert!(
            entry.lon >= US_LON_MIN && entry.lon <= US_LON_MAX,
            "seed {seed}: longitude {:.6} outside US bounds [{US_LON_MIN}, {US_LON_MAX}]",
            entry.lon,
        );
    }
}

// ---------------------------------------------------------------------------
// 2. WiFi signal strength always negative (dBm) and within -90 to -30
// ---------------------------------------------------------------------------

#[test]
fn wifi_signal_strength_negative_and_in_range() {
    let wifi_gen = WifiGenerator::new();
    let profile = default_profile();
    let ctx = default_context();

    for seed in 0..500 {
        let mut rng = seeded_rng(seed);
        let artifact = wifi_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: WifiEntry = serde_json::from_slice(&bytes).unwrap();

        assert!(
            entry.signal_dbm < 0,
            "seed {seed}: WiFi signal must be negative, got {} dBm",
            entry.signal_dbm,
        );
        assert!(
            entry.signal_dbm >= -90 && entry.signal_dbm <= -30,
            "seed {seed}: WiFi signal {} dBm outside expected range [-90, -30]",
            entry.signal_dbm,
        );
    }
}

// ---------------------------------------------------------------------------
// 3. Cell tower signal always within -140 to 0 dBm
// ---------------------------------------------------------------------------

#[test]
fn cell_signal_within_valid_range() {
    let cell_gen = CellGenerator::new();
    let profile = default_profile();
    let ctx = default_context();

    for seed in 0..500 {
        let mut rng = seeded_rng(seed);
        let artifact = cell_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: CellEntry = serde_json::from_slice(&bytes).unwrap();

        assert!(
            entry.signal_dbm >= -140 && entry.signal_dbm <= 0,
            "seed {seed}: cell signal {} dBm outside range [-140, 0]",
            entry.signal_dbm,
        );
    }
}

// ---------------------------------------------------------------------------
// 4. EXIF GPS matches the same geographic region as GPS traces
// ---------------------------------------------------------------------------

#[test]
fn exif_gps_matches_gps_geographic_region() {
    let exif_gen = ExifGenerator::new();
    let profile = default_profile();
    let ctx = default_context();

    for seed in 0..200 {
        let mut rng = seeded_rng(seed);
        let artifact = exif_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let exif: ExifEntry = serde_json::from_slice(&bytes).unwrap();

        // EXIF GPS must fall within the same continental US bounds as GPS traces.
        assert!(
            exif.gps_latitude >= 25.0 && exif.gps_latitude <= 49.0,
            "seed {seed}: EXIF latitude {:.6} outside continental US",
            exif.gps_latitude,
        );
        assert!(
            exif.gps_longitude >= -125.0 && exif.gps_longitude <= -67.0,
            "seed {seed}: EXIF longitude {:.6} outside continental US",
            exif.gps_longitude,
        );
    }

    // Cross-check: fresh GPS first-points and EXIF photos both target
    // continental US, so a forensic analyst comparing the two data sets
    // would see overlapping geographic regions.
    let gps_gen = GpsGenerator::new();
    let mut rng = seeded_rng(12345);
    let gps_artifact = gps_gen.generate(&profile, &ctx, &mut rng).unwrap();
    let gps_bytes = gps_artifact.to_bytes().unwrap();
    let gps_entry: engine_location::GpsEntry =
        serde_json::from_slice(&gps_bytes).unwrap();

    let mut rng2 = seeded_rng(12345);
    let exif_artifact = exif_gen.generate(&profile, &ctx, &mut rng2).unwrap();
    let exif_bytes = exif_artifact.to_bytes().unwrap();
    let exif_entry: ExifEntry = serde_json::from_slice(&exif_bytes).unwrap();

    // Both should be in continental US — overlap check.
    assert!(gps_entry.lat >= US_LAT_MIN && gps_entry.lat <= US_LAT_MAX);
    assert!(exif_entry.gps_latitude >= 25.0 && exif_entry.gps_latitude <= 49.0);
}

// ---------------------------------------------------------------------------
// 5. WiFi BSSID format is valid MAC (XX:XX:XX:XX:XX:XX)
// ---------------------------------------------------------------------------

#[test]
fn wifi_bssid_valid_mac_format() {
    let wifi_gen = WifiGenerator::new();
    let profile = default_profile();
    let ctx = default_context();

    for seed in 0..500 {
        let mut rng = seeded_rng(seed);
        let artifact = wifi_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: WifiEntry = serde_json::from_slice(&bytes).unwrap();

        // Must be exactly 17 characters: XX:XX:XX:XX:XX:XX
        assert_eq!(
            entry.bssid.len(),
            17,
            "seed {seed}: BSSID length {} != 17: '{}'",
            entry.bssid.len(),
            entry.bssid,
        );

        let octets: Vec<&str> = entry.bssid.split(':').collect();
        assert_eq!(
            octets.len(),
            6,
            "seed {seed}: BSSID must have 6 octets, got {}: '{}'",
            octets.len(),
            entry.bssid,
        );

        for (i, octet) in octets.iter().enumerate() {
            assert_eq!(
                octet.len(),
                2,
                "seed {seed}: BSSID octet {i} length {} != 2: '{}'",
                octet.len(),
                entry.bssid,
            );
            assert!(
                octet.chars().all(|c| c.is_ascii_hexdigit()),
                "seed {seed}: BSSID octet {i} '{}' contains non-hex chars",
                octet,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 6. Cell tower MCC/MNC match known US carriers
// ---------------------------------------------------------------------------

#[test]
fn cell_mcc_mnc_match_known_us_carriers() {
    let cell_gen = CellGenerator::new();
    let profile = default_profile();
    let ctx = default_context();

    for seed in 0..500 {
        let mut rng = seeded_rng(seed);
        let artifact = cell_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: CellEntry = serde_json::from_slice(&bytes).unwrap();

        let pair = (entry.mcc, entry.mnc);
        assert!(
            KNOWN_US_MCC_MNC.contains(&pair),
            "seed {seed}: MCC/MNC ({}, {}) not in known US carriers",
            entry.mcc,
            entry.mnc,
        );
    }
}

// ---------------------------------------------------------------------------
// 7. All location timestamps within same time window
// ---------------------------------------------------------------------------

#[test]
fn all_location_timestamps_within_same_window() {
    let gps_gen = GpsGenerator::new();
    let wifi_gen = WifiGenerator::new();
    let cell_gen = CellGenerator::new();
    let exif_gen = ExifGenerator::new();
    let profile = default_profile();
    let ctx = default_context();
    let reference_now = ctx.now;

    // GPS: timestamp should be at or after context.now (first point = now)
    for seed in 0..50 {
        let mut rng = seeded_rng(seed);
        let artifact = gps_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: engine_location::GpsEntry =
            serde_json::from_slice(&bytes).unwrap();

        let drift = (entry.timestamp - reference_now).num_seconds().abs();
        assert!(
            drift <= 86400,
            "seed {seed}: GPS timestamp drifted {drift}s from context.now",
        );
    }

    // WiFi: connected_at is context.now minus up to 600s jitter
    for seed in 0..50 {
        let mut rng = seeded_rng(seed);
        let artifact = wifi_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: WifiEntry = serde_json::from_slice(&bytes).unwrap();

        let drift = (entry.connected_at - reference_now).num_seconds().abs();
        assert!(
            drift <= 86400,
            "seed {seed}: WiFi timestamp drifted {drift}s from context.now",
        );
    }

    // Cell: connected_at is context.now minus up to 86400s jitter
    for seed in 0..50 {
        let mut rng = seeded_rng(seed);
        let artifact = cell_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: CellEntry = serde_json::from_slice(&bytes).unwrap();

        let drift = (entry.connected_at - reference_now).num_seconds().abs();
        assert!(
            drift <= 86400,
            "seed {seed}: cell timestamp drifted {drift}s from context.now",
        );
    }

    // EXIF: datetime_original is up to 365 days before context.now
    for seed in 0..50 {
        let mut rng = seeded_rng(seed);
        let artifact = exif_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: ExifEntry = serde_json::from_slice(&bytes).unwrap();

        let drift_days = (reference_now - entry.datetime_original).num_days();
        assert!(
            drift_days >= 0 && drift_days <= 365,
            "seed {seed}: EXIF timestamp {drift_days} days from now, expected [0, 365]",
        );
    }
}

// ---------------------------------------------------------------------------
// 8. 1000-entry stress test across all 4 generators
// ---------------------------------------------------------------------------

#[test]
fn stress_1000_entries_all_generators() {
    let profile = default_profile();
    let ctx = default_context();

    // GPS: 250 entries via trace for path continuity
    let mut gps_gen = GpsGenerator::new();
    let mut rng = seeded_rng(1337);
    let gps_entries = gps_gen
        .generate_trace(&profile, &ctx, &mut rng, 250)
        .unwrap();
    assert_eq!(gps_entries.len(), 250);
    for (i, entry) in gps_entries.iter().enumerate() {
        entry.validate_plausibility().unwrap_or_else(|e| {
            panic!("GPS entry {i} failed plausibility: {e}");
        });
    }

    // WiFi: 250 entries
    let wifi_gen = WifiGenerator::new();
    for seed in 0..250u64 {
        let mut rng = seeded_rng(seed + 10_000);
        let artifact = wifi_gen
            .generate(&profile, &ctx, &mut rng)
            .unwrap_or_else(|e| panic!("WiFi seed {seed} failed: {e}"));
        artifact
            .validate_plausibility()
            .unwrap_or_else(|e| panic!("WiFi seed {seed} plausibility failed: {e}"));
    }

    // Cell: 250 entries
    let cell_gen = CellGenerator::new();
    for seed in 0..250u64 {
        let mut rng = seeded_rng(seed + 20_000);
        let artifact = cell_gen
            .generate(&profile, &ctx, &mut rng)
            .unwrap_or_else(|e| panic!("Cell seed {seed} failed: {e}"));
        artifact
            .validate_plausibility()
            .unwrap_or_else(|e| panic!("Cell seed {seed} plausibility failed: {e}"));
    }

    // EXIF: 250 entries
    let exif_gen = ExifGenerator::new();
    for seed in 0..250u64 {
        let mut rng = seeded_rng(seed + 30_000);
        let artifact = exif_gen
            .generate(&profile, &ctx, &mut rng)
            .unwrap_or_else(|e| panic!("EXIF seed {seed} failed: {e}"));
        artifact
            .validate_plausibility()
            .unwrap_or_else(|e| panic!("EXIF seed {seed} plausibility failed: {e}"));
    }
}
