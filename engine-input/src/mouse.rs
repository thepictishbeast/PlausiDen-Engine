//! Mouse event generation -- realistic cursor movement, clicks, and scrolling.
//!
//! Generates forensically plausible mouse interaction sequences with non-linear
//! movement trajectories (Bezier curve noise), varied click patterns, and
//! realistic timing distributions.

use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext,
};
use rand::distributions::{Distribution, Uniform};
use rand::{CryptoRng, RngCore};
use serde::Serialize;

/// Default desktop screen dimensions (pixels).
const DEFAULT_SCREEN_WIDTH: u32 = 1920;
const DEFAULT_SCREEN_HEIGHT: u32 = 1080;

/// Number of intermediate points in a movement trajectory.
const TRAJECTORY_POINTS: usize = 5;

/// Mouse button identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum MouseButton {
    /// Primary (left) button.
    Left,
    /// Secondary (right) button.
    Right,
    /// Middle (wheel) button.
    Middle,
    /// No button (movement/hover only).
    None,
}

/// Types of mouse events that can be generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum MouseEventType {
    /// Single left click.
    LeftClick,
    /// Single right click (context menu).
    RightClick,
    /// Two rapid left clicks.
    DoubleClick,
    /// Middle button click.
    MiddleClick,
    /// Scroll wheel event.
    Scroll,
    /// Cursor movement without clicking (hover).
    Hover,
}

/// A point along a mouse movement trajectory.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct TrajectoryPoint {
    /// X coordinate.
    pub x: u32,
    /// Y coordinate.
    pub y: u32,
    /// Offset from event start in milliseconds.
    pub offset_ms: u64,
}

/// A single mouse event with full spatial, button, and temporal data.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct MouseEvent {
    /// Type of mouse interaction.
    pub event_type: MouseEventType,
    /// Final X coordinate.
    pub x: u32,
    /// Final Y coordinate.
    pub y: u32,
    /// Button involved (None for hover/scroll).
    pub button: MouseButton,
    /// Scroll delta on X axis (0 for non-scroll events).
    pub scroll_delta_x: i32,
    /// Scroll delta on Y axis (0 for non-scroll events).
    pub scroll_delta_y: i32,
    /// Duration of the event in milliseconds.
    pub duration_ms: u64,
    /// Offset from start of sequence in milliseconds.
    pub timestamp_ms: u64,
    /// Movement trajectory points (non-linear path to destination).
    pub trajectory: Vec<TrajectoryPoint>,
}

/// A sequence of mouse events forming a coherent interaction session.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct MouseEntry {
    /// Artifact metadata (id, category, timestamps, size).
    pub meta: ArtifactMetadata,
    /// Ordered sequence of mouse events.
    pub events: Vec<MouseEvent>,
    /// Screen width used for coordinate bounds.
    pub screen_width: u32,
    /// Screen height used for coordinate bounds.
    pub screen_height: u32,
}

impl Artifact for MouseEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.events.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty mouse sequence".into(),
            });
        }
        for evt in &self.events {
            if evt.x > self.screen_width || evt.y > self.screen_height {
                return Err(EngineError::ImplausibleArtifact {
                    reason: format!(
                        "coordinates out of bounds: ({}, {}), screen={}x{}",
                        evt.x, evt.y, self.screen_width, self.screen_height
                    ),
                });
            }
            for pt in &evt.trajectory {
                if pt.x > self.screen_width || pt.y > self.screen_height {
                    return Err(EngineError::ImplausibleArtifact {
                        reason: format!(
                            "trajectory point out of bounds: ({}, {})",
                            pt.x, pt.y
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

/// Generates realistic mouse interaction sequences.
pub struct MouseGenerator;

impl MouseGenerator {
    /// Create a new mouse generator.
    pub fn new() -> Self {
        Self
    }
}

impl Default for MouseGenerator {
    fn default() -> Self {
        Self::new()
    }
}

/// Pick a random mouse event type from the distribution.
fn random_event_type(rng: &mut (impl RngCore + CryptoRng)) -> MouseEventType {
    match Uniform::new_inclusive(0u32, 5).sample(rng) {
        0 => MouseEventType::LeftClick,
        1 => MouseEventType::RightClick,
        2 => MouseEventType::DoubleClick,
        3 => MouseEventType::MiddleClick,
        4 => MouseEventType::Scroll,
        _ => MouseEventType::Hover,
    }
}

/// Generate a quadratic Bezier trajectory between two points with random noise.
///
/// Real mouse paths are never perfectly straight. A control point offset from
/// the midline simulates natural hand tremor and arc.
fn bezier_trajectory(
    start_x: u32,
    start_y: u32,
    end_x: u32,
    end_y: u32,
    duration_ms: u64,
    screen_w: u32,
    screen_h: u32,
    rng: &mut (impl RngCore + CryptoRng),
) -> Vec<TrajectoryPoint> {
    let mut points = Vec::with_capacity(TRAJECTORY_POINTS);

    // Compute a random control point offset perpendicular to the line.
    let mid_x = (start_x as f64 + end_x as f64) / 2.0;
    let mid_y = (start_y as f64 + end_y as f64) / 2.0;
    let offset = Uniform::new(-80.0_f64, 80.0).sample(rng);

    // Perpendicular direction (rotate the direction vector 90 degrees).
    let dx = end_x as f64 - start_x as f64;
    let dy = end_y as f64 - start_y as f64;
    let len = (dx * dx + dy * dy).sqrt().max(1.0);
    let ctrl_x = mid_x + (-dy / len) * offset;
    let ctrl_y = mid_y + (dx / len) * offset;

    for i in 0..TRAJECTORY_POINTS {
        let t = (i + 1) as f64 / (TRAJECTORY_POINTS + 1) as f64;
        let inv = 1.0 - t;

        // Quadratic Bezier: B(t) = (1-t)^2 * P0 + 2*(1-t)*t * C + t^2 * P1
        let bx = inv * inv * start_x as f64
            + 2.0 * inv * t * ctrl_x
            + t * t * end_x as f64;
        let by = inv * inv * start_y as f64
            + 2.0 * inv * t * ctrl_y
            + t * t * end_y as f64;

        let px = (bx.round() as u32).min(screen_w);
        let py = (by.round() as u32).min(screen_h);
        let offset_ms = ((duration_ms as f64) * t) as u64;

        points.push(TrajectoryPoint {
            x: px,
            y: py,
            offset_ms,
        });
    }

    points
}

/// Generate a single mouse event at the given timestamp offset.
fn make_event(
    event_type: MouseEventType,
    current_ms: u64,
    prev_x: u32,
    prev_y: u32,
    screen_w: u32,
    screen_h: u32,
    rng: &mut (impl RngCore + CryptoRng),
) -> MouseEvent {
    let x_dist = Uniform::new(0u32, screen_w);
    let y_dist = Uniform::new(0u32, screen_h);

    let dest_x = x_dist.sample(rng);
    let dest_y = y_dist.sample(rng);

    match event_type {
        MouseEventType::LeftClick => {
            let duration = Uniform::new_inclusive(80u64, 200).sample(rng);
            let trajectory =
                bezier_trajectory(prev_x, prev_y, dest_x, dest_y, duration, screen_w, screen_h, rng);
            MouseEvent {
                event_type,
                x: dest_x,
                y: dest_y,
                button: MouseButton::Left,
                scroll_delta_x: 0,
                scroll_delta_y: 0,
                duration_ms: duration,
                timestamp_ms: current_ms,
                trajectory,
            }
        }
        MouseEventType::RightClick => {
            let duration = Uniform::new_inclusive(80u64, 200).sample(rng);
            let trajectory =
                bezier_trajectory(prev_x, prev_y, dest_x, dest_y, duration, screen_w, screen_h, rng);
            MouseEvent {
                event_type,
                x: dest_x,
                y: dest_y,
                button: MouseButton::Right,
                scroll_delta_x: 0,
                scroll_delta_y: 0,
                duration_ms: duration,
                timestamp_ms: current_ms,
                trajectory,
            }
        }
        MouseEventType::DoubleClick => {
            let single = Uniform::new_inclusive(60u64, 120).sample(rng);
            let gap = Uniform::new_inclusive(50u64, 150).sample(rng);
            let duration = single * 2 + gap;
            let trajectory =
                bezier_trajectory(prev_x, prev_y, dest_x, dest_y, duration, screen_w, screen_h, rng);
            MouseEvent {
                event_type,
                x: dest_x,
                y: dest_y,
                button: MouseButton::Left,
                scroll_delta_x: 0,
                scroll_delta_y: 0,
                duration_ms: duration,
                timestamp_ms: current_ms,
                trajectory,
            }
        }
        MouseEventType::MiddleClick => {
            let duration = Uniform::new_inclusive(80u64, 180).sample(rng);
            let trajectory =
                bezier_trajectory(prev_x, prev_y, dest_x, dest_y, duration, screen_w, screen_h, rng);
            MouseEvent {
                event_type,
                x: dest_x,
                y: dest_y,
                button: MouseButton::Middle,
                scroll_delta_x: 0,
                scroll_delta_y: 0,
                duration_ms: duration,
                timestamp_ms: current_ms,
                trajectory,
            }
        }
        MouseEventType::Scroll => {
            let duration = Uniform::new_inclusive(100u64, 400).sample(rng);
            let delta_y = Uniform::new_inclusive(-10i32, 10).sample(rng);
            let delta_x = Uniform::new_inclusive(-3i32, 3).sample(rng);
            // Cursor stays roughly in place during scroll.
            MouseEvent {
                event_type,
                x: prev_x,
                y: prev_y,
                button: MouseButton::None,
                scroll_delta_x: delta_x,
                scroll_delta_y: delta_y,
                duration_ms: duration,
                timestamp_ms: current_ms,
                trajectory: Vec::new(),
            }
        }
        MouseEventType::Hover => {
            let duration = Uniform::new_inclusive(200u64, 600).sample(rng);
            let trajectory =
                bezier_trajectory(prev_x, prev_y, dest_x, dest_y, duration, screen_w, screen_h, rng);
            MouseEvent {
                event_type,
                x: dest_x,
                y: dest_y,
                button: MouseButton::None,
                scroll_delta_x: 0,
                scroll_delta_y: 0,
                duration_ms: duration,
                timestamp_ms: current_ms,
                trajectory,
            }
        }
    }
}

impl DataGenerator for MouseGenerator {
    fn generate(
        &self,
        _profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        let event_count = Uniform::new_inclusive(5u32, 15).sample(rng);
        let mut events = Vec::with_capacity(event_count as usize);
        let mut current_ms: u64 = 0;
        // Track cursor position for trajectory continuity.
        let mut prev_x = DEFAULT_SCREEN_WIDTH / 2;
        let mut prev_y = DEFAULT_SCREEN_HEIGHT / 2;

        for _ in 0..event_count {
            let event_type = random_event_type(rng);
            let evt = make_event(
                event_type,
                current_ms,
                prev_x,
                prev_y,
                DEFAULT_SCREEN_WIDTH,
                DEFAULT_SCREEN_HEIGHT,
                rng,
            );

            prev_x = evt.x;
            prev_y = evt.y;
            current_ms += evt.duration_ms;
            // Inter-event pause: 50-500ms.
            current_ms += Uniform::new_inclusive(50u64, 500).sample(rng);
            events.push(evt);
        }

        let meta = ArtifactMetadata::new(
            DataCategory::Input,
            context.now,
            context.now,
            events.len() as u64 * 128,
        )?;

        let entry = MouseEntry {
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
    fn test_generate_mouse_events() {
        let g = MouseGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);
        let a = g.generate(&p, &c, &mut r).unwrap();
        a.validate_plausibility().unwrap();
        let b = a.to_bytes().unwrap();
        let e: MouseEntry = serde_json::from_slice(&b).unwrap();
        assert!(!e.events.is_empty());
        assert_eq!(e.screen_width, DEFAULT_SCREEN_WIDTH);
        assert_eq!(e.screen_height, DEFAULT_SCREEN_HEIGHT);
    }

    #[test]
    fn test_500_mouse_sequences_valid() {
        let g = MouseGenerator::new();
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
    fn test_mouse_event_type_variety() {
        let g = MouseGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut seen = std::collections::HashSet::new();
        for s in 0..200 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: MouseEntry = serde_json::from_slice(&b).unwrap();
            for evt in &e.events {
                seen.insert(format!("{:?}", evt.event_type));
            }
        }
        assert!(seen.contains("LeftClick"), "missing LeftClick events");
        assert!(seen.contains("RightClick"), "missing RightClick events");
        assert!(seen.contains("DoubleClick"), "missing DoubleClick events");
        assert!(seen.contains("MiddleClick"), "missing MiddleClick events");
        assert!(seen.contains("Scroll"), "missing Scroll events");
        assert!(seen.contains("Hover"), "missing Hover events");
    }

    #[test]
    fn test_trajectories_non_linear() {
        let g = MouseGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(99);
        let a = g.generate(&p, &c, &mut r).unwrap();
        let b = a.to_bytes().unwrap();
        let e: MouseEntry = serde_json::from_slice(&b).unwrap();

        // Find events with trajectories and verify they have points.
        let with_traj: Vec<_> = e
            .events
            .iter()
            .filter(|ev| !ev.trajectory.is_empty())
            .collect();
        assert!(
            !with_traj.is_empty(),
            "should have events with trajectory points"
        );
        for evt in &with_traj {
            assert_eq!(evt.trajectory.len(), TRAJECTORY_POINTS);
            // Verify trajectory points are within screen bounds.
            for pt in &evt.trajectory {
                assert!(pt.x <= DEFAULT_SCREEN_WIDTH);
                assert!(pt.y <= DEFAULT_SCREEN_HEIGHT);
            }
        }
    }

    #[test]
    fn test_timestamps_monotonic() {
        let g = MouseGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);
        let a = g.generate(&p, &c, &mut r).unwrap();
        let b = a.to_bytes().unwrap();
        let e: MouseEntry = serde_json::from_slice(&b).unwrap();
        for w in e.events.windows(2) {
            assert!(
                w[1].timestamp_ms >= w[0].timestamp_ms,
                "mouse events not monotonically ordered"
            );
        }
    }
}
