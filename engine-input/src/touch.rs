//! Touch screen event generation -- realistic touch patterns for mobile devices.
//!
//! Generates forensically plausible touch sequences including taps, swipes,
//! long presses, pinches, and scrolls with realistic pressure, timing, and
//! coordinate distributions.

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

/// Touch event types that can be generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum TouchType {
    /// Single brief contact.
    Tap,
    /// Two taps in rapid succession.
    DoubleTap,
    /// Sustained contact without movement.
    LongPress,
    /// Drag across the screen in a direction.
    Swipe,
    /// Two-finger pinch (zoom in/out).
    Pinch,
    /// Vertical scroll gesture.
    Scroll,
}

/// A single touch event with full spatial and temporal data.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct TouchEvent {
    /// Type of touch interaction.
    pub touch_type: TouchType,
    /// X coordinate where touch began.
    pub start_x: u32,
    /// Y coordinate where touch began.
    pub start_y: u32,
    /// X coordinate where touch ended (same as start for taps/long press).
    pub end_x: u32,
    /// Y coordinate where touch ended (same as start for taps/long press).
    pub end_y: u32,
    /// Contact pressure (0.0 = feather, 1.0 = maximum).
    pub pressure: f64,
    /// Duration of the touch event in milliseconds.
    pub duration_ms: u64,
    /// Offset from start of sequence in milliseconds.
    pub timestamp_ms: u64,
}

/// A sequence of touch events forming a coherent interaction session.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct TouchEntry {
    /// Artifact metadata (id, category, timestamps, size).
    pub meta: ArtifactMetadata,
    /// Ordered sequence of touch events.
    pub events: Vec<TouchEvent>,
    /// Screen width used for coordinate bounds.
    pub screen_width: u32,
    /// Screen height used for coordinate bounds.
    pub screen_height: u32,
}

impl Artifact for TouchEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.events.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty touch sequence".into(),
            });
        }
        for evt in &self.events {
            if evt.start_x > self.screen_width || evt.end_x > self.screen_width {
                return Err(EngineError::ImplausibleArtifact {
                    reason: format!(
                        "x coordinate out of bounds: start={}, end={}, width={}",
                        evt.start_x, evt.end_x, self.screen_width
                    ),
                });
            }
            if evt.start_y > self.screen_height || evt.end_y > self.screen_height {
                return Err(EngineError::ImplausibleArtifact {
                    reason: format!(
                        "y coordinate out of bounds: start={}, end={}, height={}",
                        evt.start_y, evt.end_y, self.screen_height
                    ),
                });
            }
            if !(0.0..=1.0).contains(&evt.pressure) {
                return Err(EngineError::ImplausibleArtifact {
                    reason: format!("pressure out of range: {}", evt.pressure),
                });
            }
        }
        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

/// Generates realistic touch screen event sequences.
pub struct TouchGenerator;

impl TouchGenerator {
    /// Create a new touch generator.
    pub fn new() -> Self {
        Self
    }
}

impl Default for TouchGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Pick a random touch type from the distribution.
fn random_touch_type(rng: &mut (impl RngCore + CryptoRng)) -> TouchType {
    match Uniform::new_inclusive(0u32, 5).sample(rng) {
        0 => TouchType::Tap,
        1 => TouchType::DoubleTap,
        2 => TouchType::LongPress,
        3 => TouchType::Swipe,
        4 => TouchType::Pinch,
        _ => TouchType::Scroll,
    }
}

/// Generate a single touch event at the given timestamp offset.
fn make_event(
    touch_type: TouchType,
    current_ms: u64,
    screen_w: u32,
    screen_h: u32,
    rng: &mut (impl RngCore + CryptoRng),
) -> TouchEvent {
    let x_dist = Uniform::new(0u32, screen_w);
    let y_dist = Uniform::new(0u32, screen_h);
    let pressure_dist = Uniform::new(0.15_f64, 0.85);

    let start_x = x_dist.sample(rng);
    let start_y = y_dist.sample(rng);
    let pressure = pressure_dist.sample(rng);

    match touch_type {
        TouchType::Tap => {
            let duration = Uniform::new_inclusive(50u64, 150).sample(rng);
            TouchEvent {
                touch_type,
                start_x,
                start_y,
                end_x: start_x,
                end_y: start_y,
                pressure,
                duration_ms: duration,
                timestamp_ms: current_ms,
            }
        }
        TouchType::DoubleTap => {
            // Total duration covers both taps and the gap between them.
            let single = Uniform::new_inclusive(50u64, 120).sample(rng);
            let gap = Uniform::new_inclusive(80u64, 200).sample(rng);
            let duration = single * 2 + gap;
            TouchEvent {
                touch_type,
                start_x,
                start_y,
                end_x: start_x,
                end_y: start_y,
                pressure,
                duration_ms: duration,
                timestamp_ms: current_ms,
            }
        }
        TouchType::LongPress => {
            let duration = Uniform::new_inclusive(500u64, 2000).sample(rng);
            TouchEvent {
                touch_type,
                start_x,
                start_y,
                end_x: start_x,
                end_y: start_y,
                pressure,
                duration_ms: duration,
                timestamp_ms: current_ms,
            }
        }
        TouchType::Swipe => {
            let duration = Uniform::new_inclusive(200u64, 800).sample(rng);
            let end_x = x_dist.sample(rng);
            let end_y = y_dist.sample(rng);
            TouchEvent {
                touch_type,
                start_x,
                start_y,
                end_x,
                end_y,
                pressure,
                duration_ms: duration,
                timestamp_ms: current_ms,
            }
        }
        TouchType::Pinch => {
            // Pinch uses start/end to represent the two finger positions converging or diverging.
            let duration = Uniform::new_inclusive(300u64, 900).sample(rng);
            let end_x = x_dist.sample(rng);
            let end_y = y_dist.sample(rng);
            TouchEvent {
                touch_type,
                start_x,
                start_y,
                end_x,
                end_y,
                pressure,
                duration_ms: duration,
                timestamp_ms: current_ms,
            }
        }
        TouchType::Scroll => {
            // Scroll is primarily vertical.
            let duration = Uniform::new_inclusive(150u64, 600).sample(rng);
            let delta_y = Uniform::new_inclusive(100u32, 800).sample(rng);
            let end_y = start_y.saturating_add(delta_y).min(screen_h);
            // Slight horizontal drift during scroll.
            let drift = Uniform::new_inclusive(0u32, 20).sample(rng);
            let end_x = start_x.saturating_add(drift).min(screen_w);
            TouchEvent {
                touch_type,
                start_x,
                start_y,
                end_x,
                end_y,
                pressure,
                duration_ms: duration,
                timestamp_ms: current_ms,
            }
        }
    }
}

impl DataGenerator for TouchGenerator {
    fn generate(
        &self,
        _profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        let event_count = Uniform::new_inclusive(4u32, 12).sample(rng);
        let mut events = Vec::with_capacity(event_count as usize);
        let mut current_ms: u64 = 0;

        for _ in 0..event_count {
            let touch_type = random_touch_type(rng);
            let evt = make_event(
                touch_type,
                current_ms,
                DEFAULT_SCREEN_WIDTH,
                DEFAULT_SCREEN_HEIGHT,
                rng,
            );
            current_ms += evt.duration_ms;
            // Inter-event pause: 100-800ms.
            current_ms += Uniform::new_inclusive(100u64, 800).sample(rng);
            events.push(evt);
        }

        let meta = ArtifactMetadata::new(
            DataCategory::Input,
            context.now,
            context.now,
            events.len() as u64 * 64,
        )?;

        let entry = TouchEntry {
            meta,
            events,
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
    fn test_generate_touch_events() {
        let g = TouchGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);
        let a = g.generate(&p, &c, &mut r).unwrap();
        a.validate_plausibility().unwrap();
        let b = a.to_bytes().unwrap();
        let e: TouchEntry = serde_json::from_slice(&b).unwrap();
        assert!(!e.events.is_empty());
        assert_eq!(e.screen_width, DEFAULT_SCREEN_WIDTH);
        assert_eq!(e.screen_height, DEFAULT_SCREEN_HEIGHT);
    }

    #[test]
    fn test_500_touch_sequences_valid() {
        let g = TouchGenerator::new();
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
    fn test_touch_event_type_variety() {
        let g = TouchGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut seen = std::collections::HashSet::new();
        // Generate enough sequences to see all touch types.
        for s in 0..200 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: TouchEntry = serde_json::from_slice(&b).unwrap();
            for evt in &e.events {
                seen.insert(format!("{:?}", evt.touch_type));
            }
        }
        assert!(seen.contains("Tap"), "missing Tap events");
        assert!(seen.contains("Swipe"), "missing Swipe events");
        assert!(seen.contains("LongPress"), "missing LongPress events");
        assert!(seen.contains("DoubleTap"), "missing DoubleTap events");
        assert!(seen.contains("Pinch"), "missing Pinch events");
        assert!(seen.contains("Scroll"), "missing Scroll events");
    }

    #[test]
    fn test_coordinates_within_bounds() {
        let g = TouchGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..100 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: TouchEntry = serde_json::from_slice(&b).unwrap();
            for evt in &e.events {
                assert!(evt.start_x <= DEFAULT_SCREEN_WIDTH);
                assert!(evt.start_y <= DEFAULT_SCREEN_HEIGHT);
                assert!(evt.end_x <= DEFAULT_SCREEN_WIDTH);
                assert!(evt.end_y <= DEFAULT_SCREEN_HEIGHT);
                assert!((0.0..=1.0).contains(&evt.pressure));
            }
        }
    }

    #[test]
    fn test_timestamps_monotonic() {
        let g = TouchGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);
        let a = g.generate(&p, &c, &mut r).unwrap();
        let b = a.to_bytes().unwrap();
        let e: TouchEntry = serde_json::from_slice(&b).unwrap();
        for w in e.events.windows(2) {
            assert!(
                w[1].timestamp_ms >= w[0].timestamp_ms,
                "touch events not monotonically ordered"
            );
        }
    }
}
