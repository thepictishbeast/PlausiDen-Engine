//! Multi-touch gesture generation -- complex gesture patterns for mobile devices.
//!
//! Generates forensically plausible multi-touch gesture sequences: pinch-to-zoom,
//! two-finger rotation, three-finger app-switching swipes, edge swipes for
//! notification panels and back gestures, and palm rejection events. Each gesture
//! carries realistic touch point coordinates, scale factors, rotation angles,
//! durations, and timing offsets.

use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext,
};
use rand::distributions::{Distribution, Uniform};
use rand::{CryptoRng, RngCore};
use serde::Serialize;

/// Default phone screen dimensions (pixels).
const DEFAULT_SCREEN_WIDTH: u32 = 1080;
const DEFAULT_SCREEN_HEIGHT: u32 = 2400;

/// Edge zone thickness in pixels for edge-swipe detection.
const EDGE_ZONE_PX: u32 = 40;

/// Types of multi-touch gestures that can be generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum GestureType {
    /// Two-finger pinch zoom in (spread fingers apart).
    PinchZoomIn,
    /// Two-finger pinch zoom out (bring fingers together).
    PinchZoomOut,
    /// Two-finger rotation.
    TwoFingerRotate,
    /// Three-finger horizontal swipe (app switching on mobile).
    ThreeFingerSwipe,
    /// Swipe from the screen edge (notification panel, back gesture).
    EdgeSwipe,
    /// Accidental palm contact filtered by the touch subsystem.
    PalmRejection,
}

/// A single touch point in a gesture.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct TouchPoint {
    /// X coordinate of this touch contact.
    pub x: u32,
    /// Y coordinate of this touch contact.
    pub y: u32,
}

/// A single multi-touch gesture event with full spatial and temporal data.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct GestureEntry {
    /// Artifact metadata (id, category, timestamps, size).
    pub meta: ArtifactMetadata,
    /// Type of gesture performed.
    pub gesture_type: GestureType,
    /// Touch contact points involved in the gesture.
    pub touch_points: Vec<TouchPoint>,
    /// Scale factor for pinch gestures (1.0 = no change, >1.0 = zoom in, <1.0 = zoom out).
    pub scale_factor: f64,
    /// Rotation angle in degrees for rotation gestures (0.0 for non-rotation).
    pub rotation_angle: f64,
    /// Duration of the gesture in milliseconds.
    pub duration_ms: u64,
    /// Offset from start of sequence in milliseconds.
    pub timestamp_ms: u64,
    /// Screen width used for coordinate bounds.
    pub screen_width: u32,
    /// Screen height used for coordinate bounds.
    pub screen_height: u32,
}

impl Artifact for GestureEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;

        if self.touch_points.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "gesture has no touch points".into(),
            });
        }

        for pt in &self.touch_points {
            if pt.x > self.screen_width || pt.y > self.screen_height {
                return Err(EngineError::ImplausibleArtifact {
                    reason: format!(
                        "touch point out of bounds: ({}, {}), screen={}x{}",
                        pt.x, pt.y, self.screen_width, self.screen_height
                    ),
                });
            }
        }

        if self.scale_factor <= 0.0 {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!("scale factor must be positive: {}", self.scale_factor),
            });
        }

        // Validate gesture-specific constraints.
        match self.gesture_type {
            GestureType::PinchZoomIn | GestureType::PinchZoomOut => {
                if self.touch_points.len() != 2 {
                    return Err(EngineError::ImplausibleArtifact {
                        reason: format!(
                            "pinch gesture requires 2 touch points, got {}",
                            self.touch_points.len()
                        ),
                    });
                }
            }
            GestureType::TwoFingerRotate => {
                if self.touch_points.len() != 2 {
                    return Err(EngineError::ImplausibleArtifact {
                        reason: format!(
                            "rotation gesture requires 2 touch points, got {}",
                            self.touch_points.len()
                        ),
                    });
                }
            }
            GestureType::ThreeFingerSwipe => {
                if self.touch_points.len() != 3 {
                    return Err(EngineError::ImplausibleArtifact {
                        reason: format!(
                            "three-finger swipe requires 3 touch points, got {}",
                            self.touch_points.len()
                        ),
                    });
                }
            }
            GestureType::EdgeSwipe => {
                if self.touch_points.is_empty() {
                    return Err(EngineError::ImplausibleArtifact {
                        reason: "edge swipe must have at least one touch point".into(),
                    });
                }
            }
            GestureType::PalmRejection => {
                // Palm contacts typically have many simultaneous points.
                if self.touch_points.len() < 3 {
                    return Err(EngineError::ImplausibleArtifact {
                        reason: format!(
                            "palm rejection requires >= 3 touch points, got {}",
                            self.touch_points.len()
                        ),
                    });
                }
            }
        }

        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

/// Generates realistic multi-touch gesture sequences.
pub struct GestureGenerator;

impl GestureGenerator {
    /// Create a new gesture generator.
    pub fn new() -> Self {
        Self
    }
}

impl Default for GestureGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Pick a random gesture type from a weighted distribution.
fn random_gesture_type(rng: &mut (impl RngCore + CryptoRng)) -> GestureType {
    match Uniform::new_inclusive(0u32, 9).sample(rng) {
        0 | 1 => GestureType::PinchZoomIn,
        2 | 3 => GestureType::PinchZoomOut,
        4 | 5 => GestureType::TwoFingerRotate,
        6 => GestureType::ThreeFingerSwipe,
        7 | 8 => GestureType::EdgeSwipe,
        _ => GestureType::PalmRejection,
    }
}

/// Generate a two-finger pinch zoom gesture.
fn make_pinch_zoom(
    zoom_in: bool,
    timestamp_ms: u64,
    screen_w: u32,
    screen_h: u32,
    rng: &mut (impl RngCore + CryptoRng),
) -> (Vec<TouchPoint>, f64, f64, u64) {
    // Center point of the pinch.
    let cx = Uniform::new(screen_w / 4, 3 * screen_w / 4).sample(rng);
    let cy = Uniform::new(screen_h / 4, 3 * screen_h / 4).sample(rng);

    // Spread from center for the two fingers.
    let spread = Uniform::new_inclusive(60u32, 200).sample(rng);

    let f1 = TouchPoint {
        x: cx.saturating_sub(spread),
        y: cy,
    };
    let f2 = TouchPoint {
        x: (cx + spread).min(screen_w),
        y: cy,
    };

    let scale = if zoom_in {
        Uniform::new(1.2_f64, 3.0).sample(rng)
    } else {
        Uniform::new(0.3_f64, 0.8).sample(rng)
    };

    let duration = Uniform::new_inclusive(300u64, 900).sample(rng);
    let _ = timestamp_ms; // used by caller for offset tracking

    (vec![f1, f2], scale, 0.0, duration)
}

/// Generate a two-finger rotation gesture.
fn make_rotation(
    screen_w: u32,
    screen_h: u32,
    rng: &mut (impl RngCore + CryptoRng),
) -> (Vec<TouchPoint>, f64, f64, u64) {
    let cx = Uniform::new(screen_w / 4, 3 * screen_w / 4).sample(rng);
    let cy = Uniform::new(screen_h / 4, 3 * screen_h / 4).sample(rng);

    let radius = Uniform::new_inclusive(50u32, 150).sample(rng);

    // Two fingers positioned on opposite sides of the center.
    let f1 = TouchPoint {
        x: cx.saturating_sub(radius),
        y: cy,
    };
    let f2 = TouchPoint {
        x: (cx + radius).min(screen_w),
        y: cy,
    };

    // Rotation angle: -180 to +180 degrees (positive = clockwise).
    let angle = Uniform::new(-180.0_f64, 180.0).sample(rng);
    let duration = Uniform::new_inclusive(400u64, 1200).sample(rng);

    (vec![f1, f2], 1.0, angle, duration)
}

/// Generate a three-finger horizontal swipe (app switching).
fn make_three_finger_swipe(
    screen_w: u32,
    screen_h: u32,
    rng: &mut (impl RngCore + CryptoRng),
) -> (Vec<TouchPoint>, f64, f64, u64) {
    // Three fingers spread vertically near screen center.
    let base_x = Uniform::new(screen_w / 6, 5 * screen_w / 6).sample(rng);
    let base_y = Uniform::new(screen_h / 3, 2 * screen_h / 3).sample(rng);
    let finger_gap = Uniform::new_inclusive(40u32, 80).sample(rng);

    let f1 = TouchPoint {
        x: base_x,
        y: base_y.saturating_sub(finger_gap),
    };
    let f2 = TouchPoint {
        x: base_x,
        y: base_y,
    };
    let f3 = TouchPoint {
        x: base_x,
        y: (base_y + finger_gap).min(screen_h),
    };

    let duration = Uniform::new_inclusive(200u64, 600).sample(rng);

    (vec![f1, f2, f3], 1.0, 0.0, duration)
}

/// Generate an edge swipe (notification panel pull-down or back gesture).
fn make_edge_swipe(
    screen_w: u32,
    screen_h: u32,
    rng: &mut (impl RngCore + CryptoRng),
) -> (Vec<TouchPoint>, f64, f64, u64) {
    // Choose an edge: 0=top, 1=bottom, 2=left, 3=right.
    let edge = Uniform::new_inclusive(0u32, 3).sample(rng);

    let pt = match edge {
        0 => {
            // Top edge (notification panel).
            let x = Uniform::new(0u32, screen_w).sample(rng);
            let y = Uniform::new(0u32, EDGE_ZONE_PX.min(screen_h)).sample(rng);
            TouchPoint { x, y }
        }
        1 => {
            // Bottom edge (home gesture).
            let x = Uniform::new(0u32, screen_w).sample(rng);
            let y = Uniform::new(screen_h.saturating_sub(EDGE_ZONE_PX), screen_h).sample(rng);
            TouchPoint { x, y }
        }
        2 => {
            // Left edge (back gesture).
            let x = Uniform::new(0u32, EDGE_ZONE_PX.min(screen_w)).sample(rng);
            let y = Uniform::new(0u32, screen_h).sample(rng);
            TouchPoint { x, y }
        }
        _ => {
            // Right edge (back gesture on some devices).
            let x = Uniform::new(screen_w.saturating_sub(EDGE_ZONE_PX), screen_w).sample(rng);
            let y = Uniform::new(0u32, screen_h).sample(rng);
            TouchPoint { x, y }
        }
    };

    let duration = Uniform::new_inclusive(150u64, 500).sample(rng);

    (vec![pt], 1.0, 0.0, duration)
}

/// Generate a palm rejection event (accidental large-area contact).
fn make_palm_rejection(
    screen_w: u32,
    screen_h: u32,
    rng: &mut (impl RngCore + CryptoRng),
) -> (Vec<TouchPoint>, f64, f64, u64) {
    // Palms produce a cluster of 3-6 simultaneous contact points in a tight area.
    let count = Uniform::new_inclusive(3u32, 6).sample(rng);
    let center_x = Uniform::new(50u32, screen_w.saturating_sub(50)).sample(rng);
    let center_y = Uniform::new(50u32, screen_h.saturating_sub(50)).sample(rng);

    let mut points = Vec::with_capacity(count as usize);
    for _ in 0..count {
        let dx = Uniform::new_inclusive(0u32, 40).sample(rng);
        let dy = Uniform::new_inclusive(0u32, 40).sample(rng);
        points.push(TouchPoint {
            x: (center_x + dx).min(screen_w),
            y: (center_y + dy).min(screen_h),
        });
    }

    // Very short duration -- system rejects these quickly.
    let duration = Uniform::new_inclusive(20u64, 80).sample(rng);

    (points, 1.0, 0.0, duration)
}

impl DataGenerator for GestureGenerator {
    fn generate(
        &self,
        _profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        let gesture_type = random_gesture_type(rng);

        let (touch_points, scale_factor, rotation_angle, duration_ms) = match gesture_type {
            GestureType::PinchZoomIn => {
                make_pinch_zoom(true, 0, DEFAULT_SCREEN_WIDTH, DEFAULT_SCREEN_HEIGHT, rng)
            }
            GestureType::PinchZoomOut => {
                make_pinch_zoom(false, 0, DEFAULT_SCREEN_WIDTH, DEFAULT_SCREEN_HEIGHT, rng)
            }
            GestureType::TwoFingerRotate => {
                make_rotation(DEFAULT_SCREEN_WIDTH, DEFAULT_SCREEN_HEIGHT, rng)
            }
            GestureType::ThreeFingerSwipe => {
                make_three_finger_swipe(DEFAULT_SCREEN_WIDTH, DEFAULT_SCREEN_HEIGHT, rng)
            }
            GestureType::EdgeSwipe => {
                make_edge_swipe(DEFAULT_SCREEN_WIDTH, DEFAULT_SCREEN_HEIGHT, rng)
            }
            GestureType::PalmRejection => {
                make_palm_rejection(DEFAULT_SCREEN_WIDTH, DEFAULT_SCREEN_HEIGHT, rng)
            }
        };

        let timestamp_ms = Uniform::new_inclusive(0u64, 5000).sample(rng);

        let meta = ArtifactMetadata::new(
            DataCategory::Input,
            context.now,
            context.now,
            touch_points.len() as u64 * 16 + 64,
        )?;

        let entry = GestureEntry {
            meta,
            gesture_type,
            touch_points,
            scale_factor,
            rotation_angle,
            duration_ms,
            timestamp_ms,
            screen_width: DEFAULT_SCREEN_WIDTH,
            screen_height: DEFAULT_SCREEN_HEIGHT,
        };

        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory {
        DataCategory::Input
    }

    fn forensic_weight(&self) -> u32 {
        40
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_gesture_entry() {
        let g = GestureGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);
        let a = g.generate(&p, &c, &mut r).unwrap();
        a.validate_plausibility().unwrap();
        let b = a.to_bytes().unwrap();
        let e: GestureEntry = serde_json::from_slice(&b).unwrap();
        assert!(!e.touch_points.is_empty());
        assert!(e.scale_factor > 0.0);
        assert_eq!(e.screen_width, DEFAULT_SCREEN_WIDTH);
        assert_eq!(e.screen_height, DEFAULT_SCREEN_HEIGHT);
    }

    #[test]
    fn test_500_gesture_sequences_valid() {
        let g = GestureGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..500 {
            let mut r = seeded_rng(s);
            g.generate(&p, &c, &mut r)
                .unwrap()
                .validate_plausibility()
                .unwrap();
        }
    }

    #[test]
    fn test_gesture_type_variety() {
        let g = GestureGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut seen = std::collections::HashSet::new();
        for s in 0..500 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: GestureEntry = serde_json::from_slice(&b).unwrap();
            seen.insert(format!("{:?}", e.gesture_type));
        }
        assert!(seen.contains("PinchZoomIn"), "missing PinchZoomIn");
        assert!(seen.contains("PinchZoomOut"), "missing PinchZoomOut");
        assert!(seen.contains("TwoFingerRotate"), "missing TwoFingerRotate");
        assert!(
            seen.contains("ThreeFingerSwipe"),
            "missing ThreeFingerSwipe"
        );
        assert!(seen.contains("EdgeSwipe"), "missing EdgeSwipe");
        assert!(seen.contains("PalmRejection"), "missing PalmRejection");
    }

    #[test]
    fn test_touch_point_counts_match_gesture_type() {
        let g = GestureGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..500 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: GestureEntry = serde_json::from_slice(&b).unwrap();
            match e.gesture_type {
                GestureType::PinchZoomIn | GestureType::PinchZoomOut => {
                    assert_eq!(e.touch_points.len(), 2, "pinch must have 2 points");
                }
                GestureType::TwoFingerRotate => {
                    assert_eq!(e.touch_points.len(), 2, "rotation must have 2 points");
                }
                GestureType::ThreeFingerSwipe => {
                    assert_eq!(
                        e.touch_points.len(),
                        3,
                        "three-finger swipe must have 3 points"
                    );
                }
                GestureType::EdgeSwipe => {
                    assert!(
                        !e.touch_points.is_empty(),
                        "edge swipe must have >= 1 point"
                    );
                }
                GestureType::PalmRejection => {
                    assert!(
                        e.touch_points.len() >= 3,
                        "palm rejection must have >= 3 points"
                    );
                }
            }
        }
    }

    #[test]
    fn test_coordinates_within_bounds() {
        let g = GestureGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..200 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: GestureEntry = serde_json::from_slice(&b).unwrap();
            for pt in &e.touch_points {
                assert!(pt.x <= DEFAULT_SCREEN_WIDTH, "x out of bounds: {}", pt.x);
                assert!(pt.y <= DEFAULT_SCREEN_HEIGHT, "y out of bounds: {}", pt.y);
            }
        }
    }

    #[test]
    fn test_pinch_zoom_scale_factors() {
        let g = GestureGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut zoom_in_count = 0u32;
        let mut zoom_out_count = 0u32;
        for s in 0..500 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: GestureEntry = serde_json::from_slice(&b).unwrap();
            match e.gesture_type {
                GestureType::PinchZoomIn => {
                    assert!(
                        e.scale_factor > 1.0,
                        "zoom-in scale should be > 1.0, got {}",
                        e.scale_factor
                    );
                    zoom_in_count += 1;
                }
                GestureType::PinchZoomOut => {
                    assert!(
                        e.scale_factor < 1.0,
                        "zoom-out scale should be < 1.0, got {}",
                        e.scale_factor
                    );
                    zoom_out_count += 1;
                }
                _ => {}
            }
        }
        assert!(zoom_in_count > 0, "should generate some zoom-in gestures");
        assert!(zoom_out_count > 0, "should generate some zoom-out gestures");
    }
}
