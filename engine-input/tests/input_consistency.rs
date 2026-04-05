//! Cross-artifact consistency tests for all input generators.
//!
//! These integration tests exercise keystroke, touch, mouse, and gesture
//! generators together, verifying invariants that must hold across the
//! entire input subsystem.

use engine_core::entropy::seeded_rng;
use engine_core::profile::UserProfile;
use engine_core::traits::{Artifact, DataGenerator, GenerationContext};

use engine_input::gestures::{GestureEntry, GestureGenerator, GestureType};
use engine_input::keystrokes::{KeystrokeEntry, KeystrokeGenerator};
use engine_input::mouse::{MouseEntry, MouseGenerator};
use engine_input::touch::{TouchEntry, TouchGenerator};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn deserialize_keystrokes(artifact: &dyn Artifact) -> KeystrokeEntry {
    serde_json::from_slice(&artifact.to_bytes().unwrap()).unwrap()
}

fn deserialize_touch(artifact: &dyn Artifact) -> TouchEntry {
    serde_json::from_slice(&artifact.to_bytes().unwrap()).unwrap()
}

fn deserialize_mouse(artifact: &dyn Artifact) -> MouseEntry {
    serde_json::from_slice(&artifact.to_bytes().unwrap()).unwrap()
}

fn deserialize_gesture(artifact: &dyn Artifact) -> GestureEntry {
    serde_json::from_slice(&artifact.to_bytes().unwrap()).unwrap()
}

// ---------------------------------------------------------------------------
// 1. Keystroke dwell times always 40-200ms
// ---------------------------------------------------------------------------

#[test]
fn keystroke_dwell_times_40_to_200ms() {
    let keystroke_gen = KeystrokeGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    for seed in 0..500 {
        let mut rng = seeded_rng(seed);
        let artifact = keystroke_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let entry = deserialize_keystrokes(artifact.as_ref());

        for (i, k) in entry.keystrokes.iter().enumerate() {
            assert!(
                k.dwell_ms >= 40 && k.dwell_ms <= 200,
                "seed {seed}, keystroke {i}: dwell_ms {} outside [40, 200]",
                k.dwell_ms,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 2. Touch coordinates always within screen bounds (1080x2400)
// ---------------------------------------------------------------------------

#[test]
fn touch_coordinates_within_1080x2400() {
    let touch_gen = TouchGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    for seed in 0..500 {
        let mut rng = seeded_rng(seed);
        let artifact = touch_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let entry = deserialize_touch(artifact.as_ref());

        assert_eq!(entry.screen_width, 1080);
        assert_eq!(entry.screen_height, 2400);

        for (i, evt) in entry.events.iter().enumerate() {
            assert!(
                evt.start_x <= 1080,
                "seed {seed}, event {i}: start_x {} > 1080",
                evt.start_x,
            );
            assert!(
                evt.start_y <= 2400,
                "seed {seed}, event {i}: start_y {} > 2400",
                evt.start_y,
            );
            assert!(
                evt.end_x <= 1080,
                "seed {seed}, event {i}: end_x {} > 1080",
                evt.end_x,
            );
            assert!(
                evt.end_y <= 2400,
                "seed {seed}, event {i}: end_y {} > 2400",
                evt.end_y,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 3. Mouse coordinates always within screen bounds (1920x1080)
// ---------------------------------------------------------------------------

#[test]
fn mouse_coordinates_within_1920x1080() {
    let mouse_gen = MouseGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    for seed in 0..500 {
        let mut rng = seeded_rng(seed);
        let artifact = mouse_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let entry = deserialize_mouse(artifact.as_ref());

        assert_eq!(entry.screen_width, 1920);
        assert_eq!(entry.screen_height, 1080);

        for (i, evt) in entry.events.iter().enumerate() {
            assert!(
                evt.x <= 1920,
                "seed {seed}, event {i}: x {} > 1920",
                evt.x,
            );
            assert!(
                evt.y <= 1080,
                "seed {seed}, event {i}: y {} > 1080",
                evt.y,
            );
            for (j, pt) in evt.trajectory.iter().enumerate() {
                assert!(
                    pt.x <= 1920,
                    "seed {seed}, event {i}, trajectory {j}: x {} > 1920",
                    pt.x,
                );
                assert!(
                    pt.y <= 1080,
                    "seed {seed}, event {i}, trajectory {j}: y {} > 1080",
                    pt.y,
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 4. Gesture touch point count matches gesture type
// ---------------------------------------------------------------------------

#[test]
fn gesture_touch_point_count_matches_type() {
    let gesture_gen = GestureGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    for seed in 0..500 {
        let mut rng = seeded_rng(seed);
        let artifact = gesture_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let entry = deserialize_gesture(artifact.as_ref());

        let expected = match entry.gesture_type {
            GestureType::PinchZoomIn | GestureType::PinchZoomOut => Some(2),
            GestureType::TwoFingerRotate => Some(2),
            GestureType::ThreeFingerSwipe => Some(3),
            GestureType::EdgeSwipe => None,       // >= 1
            GestureType::PalmRejection => None,    // >= 3
        };

        let count = entry.touch_points.len();

        if let Some(exact) = expected {
            assert_eq!(
                count, exact,
                "seed {seed}: {:?} expected {exact} touch points, got {count}",
                entry.gesture_type,
            );
        } else {
            match entry.gesture_type {
                GestureType::EdgeSwipe => assert!(
                    count >= 1,
                    "seed {seed}: EdgeSwipe needs >= 1 point, got {count}",
                ),
                GestureType::PalmRejection => assert!(
                    count >= 3,
                    "seed {seed}: PalmRejection needs >= 3 points, got {count}",
                ),
                _ => unreachable!(),
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 5. All timestamps monotonically increasing within a sequence
// ---------------------------------------------------------------------------

#[test]
fn all_timestamps_monotonically_increasing() {
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    let keystroke_gen = KeystrokeGenerator::new();
    let touch_gen = TouchGenerator::new();
    let mouse_gen = MouseGenerator::new();

    for seed in 0..200 {
        let mut rng = seeded_rng(seed);

        // Keystrokes: press_time_ms must be monotonic
        let ks = deserialize_keystrokes(
            keystroke_gen.generate(&profile, &ctx, &mut rng).unwrap().as_ref(),
        );
        for w in ks.keystrokes.windows(2) {
            assert!(
                w[1].press_time_ms >= w[0].press_time_ms,
                "seed {seed}: keystroke timestamps not monotonic: {} then {}",
                w[0].press_time_ms,
                w[1].press_time_ms,
            );
        }

        // Touch: timestamp_ms must be monotonic
        let mut rng = seeded_rng(seed + 10_000);
        let te = deserialize_touch(
            touch_gen.generate(&profile, &ctx, &mut rng).unwrap().as_ref(),
        );
        for w in te.events.windows(2) {
            assert!(
                w[1].timestamp_ms >= w[0].timestamp_ms,
                "seed {seed}: touch timestamps not monotonic: {} then {}",
                w[0].timestamp_ms,
                w[1].timestamp_ms,
            );
        }

        // Mouse: timestamp_ms must be monotonic
        let mut rng = seeded_rng(seed + 20_000);
        let me = deserialize_mouse(
            mouse_gen.generate(&profile, &ctx, &mut rng).unwrap().as_ref(),
        );
        for w in me.events.windows(2) {
            assert!(
                w[1].timestamp_ms >= w[0].timestamp_ms,
                "seed {seed}: mouse timestamps not monotonic: {} then {}",
                w[0].timestamp_ms,
                w[1].timestamp_ms,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 6. Typing speed (CPM) always between 30 and 800
// ---------------------------------------------------------------------------

#[test]
fn typing_speed_cpm_between_30_and_800() {
    let keystroke_gen = KeystrokeGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    for seed in 0..500 {
        let mut rng = seeded_rng(seed);
        let artifact = keystroke_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let entry = deserialize_keystrokes(artifact.as_ref());

        assert!(
            entry.avg_cpm >= 30.0 && entry.avg_cpm <= 800.0,
            "seed {seed}: avg_cpm {} outside [30, 800]",
            entry.avg_cpm,
        );
    }
}

// ---------------------------------------------------------------------------
// 7. Touch pressure always 0.0-1.0
// ---------------------------------------------------------------------------

#[test]
fn touch_pressure_between_0_and_1() {
    let touch_gen = TouchGenerator::new();
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    for seed in 0..500 {
        let mut rng = seeded_rng(seed);
        let artifact = touch_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let entry = deserialize_touch(artifact.as_ref());

        for (i, evt) in entry.events.iter().enumerate() {
            assert!(
                (0.0..=1.0).contains(&evt.pressure),
                "seed {seed}, event {i}: pressure {} outside [0.0, 1.0]",
                evt.pressure,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// 8. 500-entry stress test across all 4 generators
// ---------------------------------------------------------------------------

#[test]
fn stress_500_entries_all_generators() {
    let profile = UserProfile::default();
    let ctx = GenerationContext::new();

    let keystroke_gen = KeystrokeGenerator::new();
    let touch_gen = TouchGenerator::new();
    let mouse_gen = MouseGenerator::new();
    let gesture_gen = GestureGenerator::new();

    for seed in 0..500 {
        let mut rng = seeded_rng(seed);
        keystroke_gen
            .generate(&profile, &ctx, &mut rng)
            .unwrap()
            .validate_plausibility()
            .unwrap();

        let mut rng = seeded_rng(seed + 100_000);
        touch_gen
            .generate(&profile, &ctx, &mut rng)
            .unwrap()
            .validate_plausibility()
            .unwrap();

        let mut rng = seeded_rng(seed + 200_000);
        mouse_gen
            .generate(&profile, &ctx, &mut rng)
            .unwrap()
            .validate_plausibility()
            .unwrap();

        let mut rng = seeded_rng(seed + 300_000);
        gesture_gen
            .generate(&profile, &ctx, &mut rng)
            .unwrap()
            .validate_plausibility()
            .unwrap();
    }
}
