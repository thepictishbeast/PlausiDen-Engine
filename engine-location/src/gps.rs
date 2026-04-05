//! GPS trace generation with realistic movement models.
//!
//! Produces GPS trace entries that follow plausible movement patterns.
//! Points form coherent paths using a random-walk-with-momentum model:
//! each point is near the previous one, with speed determining step size
//! and heading providing directional continuity.

use chrono::{DateTime, Duration, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext, ResourceCost,
};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// Location data source type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocationSource {
    /// Satellite GPS fix (high accuracy).
    Gps,
    /// WiFi-based positioning (moderate accuracy).
    WiFi,
    /// Cell tower triangulation (low accuracy).
    Cell,
    /// Fused provider combining multiple sources.
    Fused,
}

/// Movement mode determining speed and behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MovementMode {
    /// Standing still or minor fidgeting (0 m/s).
    Stationary,
    /// Walking pace (1-5 m/s, ~2-11 mph).
    Walking,
    /// Vehicle travel (10-30 m/s, ~22-67 mph).
    Driving,
    /// Air travel (200-300 m/s, ~450-670 mph).
    Flying,
}

/// Continental US geographic bounds (latitude/longitude).
const US_LAT_MIN: f64 = 24.5;
const US_LAT_MAX: f64 = 49.0;
const US_LON_MIN: f64 = -125.0;
const US_LON_MAX: f64 = -66.9;

/// A single GPS trace entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpsEntry {
    /// Artifact metadata.
    pub meta: ArtifactMetadata,
    /// Latitude in decimal degrees (-90 to 90).
    pub lat: f64,
    /// Longitude in decimal degrees (-180 to 180).
    pub lon: f64,
    /// Horizontal accuracy in meters.
    pub accuracy_m: f64,
    /// Altitude above sea level in meters.
    pub altitude_m: f64,
    /// Speed in meters per second.
    pub speed_mps: f64,
    /// Heading in degrees (0-359, 0 = north, 90 = east).
    pub heading_deg: f64,
    /// Location data source.
    pub source: LocationSource,
    /// Timestamp of this fix.
    pub timestamp: DateTime<Utc>,
}

impl Artifact for GpsEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;

        if !(-90.0..=90.0).contains(&self.lat) {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!("latitude {} out of range [-90, 90]", self.lat),
            });
        }

        if !(-180.0..=180.0).contains(&self.lon) {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!("longitude {} out of range [-180, 180]", self.lon),
            });
        }

        if self.accuracy_m <= 0.0 {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!("accuracy must be positive, got {}", self.accuracy_m),
            });
        }

        if self.speed_mps < 0.0 {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!("speed must be non-negative, got {}", self.speed_mps),
            });
        }

        if !(0.0..360.0).contains(&self.heading_deg) {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!("heading {} out of range [0, 360)", self.heading_deg),
            });
        }

        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

/// Generates GPS trace entries with realistic movement patterns.
///
/// Uses a random-walk-with-momentum model: each generated point is near
/// the previous one, with speed determining step size and heading providing
/// directional continuity. Produces stationary clusters interspersed with
/// travel segments.
pub struct GpsGenerator {
    /// Last generated position for continuity.
    last_lat: Option<f64>,
    /// Last generated longitude for continuity.
    last_lon: Option<f64>,
    /// Last heading for momentum.
    last_heading: Option<f64>,
    /// Last timestamp for time progression.
    last_timestamp: Option<DateTime<Utc>>,
    /// Last altitude for terrain continuity.
    last_altitude: Option<f64>,
    /// Current movement mode.
    current_mode: MovementMode,
    /// How many points remain in the current movement segment.
    segment_remaining: u32,
}

impl GpsGenerator {
    /// Create a new GPS generator with no prior state.
    pub fn new() -> Self {
        Self {
            last_lat: None,
            last_lon: None,
            last_heading: None,
            last_timestamp: None,
            last_altitude: None,
            current_mode: MovementMode::Stationary,
            segment_remaining: 0,
        }
    }

    /// Pick a movement mode with realistic distribution.
    ///
    /// Stationary is most common (people spend most of the day in one place),
    /// then driving, then walking, then very rarely flying.
    fn choose_movement_mode(rng: &mut (impl RngCore + CryptoRng)) -> MovementMode {
        let roll = Uniform::new_inclusive(0u32, 99).sample(rng);
        match roll {
            0..=49 => MovementMode::Stationary,
            50..=69 => MovementMode::Walking,
            70..=94 => MovementMode::Driving,
            _ => MovementMode::Flying,
        }
    }

    /// Pick a location source with probability weighted by accuracy tier.
    fn choose_source(rng: &mut (impl RngCore + CryptoRng)) -> LocationSource {
        let sources = [
            LocationSource::Gps,
            LocationSource::WiFi,
            LocationSource::Cell,
            LocationSource::Fused,
        ];
        *sources.choose(rng).unwrap_or(&LocationSource::Gps)
    }

    /// Accuracy range in meters for a given source.
    fn accuracy_for_source(
        source: LocationSource,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> f64 {
        let (lo, hi) = match source {
            LocationSource::Gps => (3.0, 15.0),
            LocationSource::WiFi => (30.0, 100.0),
            LocationSource::Cell => (100.0, 3000.0),
            LocationSource::Fused => (3.0, 50.0),
        };
        Uniform::new_inclusive(lo, hi).sample(rng)
    }

    /// Speed range in m/s for a given movement mode.
    fn speed_for_mode(
        mode: MovementMode,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> f64 {
        let (lo, hi) = match mode {
            MovementMode::Stationary => (0.0, 0.3),
            MovementMode::Walking => (1.0, 5.0),
            MovementMode::Driving => (10.0, 30.0),
            MovementMode::Flying => (200.0, 300.0),
        };
        Uniform::new_inclusive(lo, hi).sample(rng)
    }

    /// Time interval between fixes based on movement mode.
    fn time_step_secs(
        mode: MovementMode,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> i64 {
        match mode {
            // Stationary: infrequent fixes (30s to 5min)
            MovementMode::Stationary => Uniform::new_inclusive(30i64, 300).sample(rng),
            // Walking: moderate frequency (5s to 30s)
            MovementMode::Walking => Uniform::new_inclusive(5i64, 30).sample(rng),
            // Driving: frequent fixes (3s to 15s)
            MovementMode::Driving => Uniform::new_inclusive(3i64, 15).sample(rng),
            // Flying: less frequent (30s to 120s)
            MovementMode::Flying => Uniform::new_inclusive(30i64, 120).sample(rng),
        }
    }

    /// Segment length (number of points) for a given mode.
    fn segment_length(
        mode: MovementMode,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> u32 {
        match mode {
            MovementMode::Stationary => Uniform::new_inclusive(5u32, 30).sample(rng),
            MovementMode::Walking => Uniform::new_inclusive(10u32, 50).sample(rng),
            MovementMode::Driving => Uniform::new_inclusive(20u32, 100).sample(rng),
            MovementMode::Flying => Uniform::new_inclusive(10u32, 40).sample(rng),
        }
    }

    /// Clamp latitude to valid range.
    fn clamp_lat(lat: f64) -> f64 {
        lat.clamp(-90.0, 90.0)
    }

    /// Clamp longitude to valid range, wrapping at boundaries.
    fn clamp_lon(lon: f64) -> f64 {
        let mut l = lon;
        while l > 180.0 {
            l -= 360.0;
        }
        while l < -180.0 {
            l += 360.0;
        }
        l
    }
}

impl Default for GpsGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for GpsGenerator {
    fn generate(
        &self,
        _profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        // SAFETY: We need interior mutability for the movement model state.
        // The trait signature takes &self, so we compute state locally and
        // return it in the artifact. Callers that want path continuity should
        // use generate_trace() directly instead.

        let (lat, lon, heading, altitude, timestamp, mode) =
            if let (Some(prev_lat), Some(prev_lon)) = (self.last_lat, self.last_lon) {
                // Continue from previous position
                let mode = if self.segment_remaining > 0 {
                    self.current_mode
                } else {
                    Self::choose_movement_mode(rng)
                };

                let speed = Self::speed_for_mode(mode, rng);
                let dt_secs = Self::time_step_secs(mode, rng);

                // Heading with momentum: drift from previous heading
                let prev_heading = self.last_heading.unwrap_or(0.0);
                let heading_drift = Uniform::new_inclusive(-30.0f64, 30.0).sample(rng);
                let heading = (prev_heading + heading_drift).rem_euclid(360.0);

                // Convert heading to radians for displacement
                let heading_rad = heading.to_radians();
                let distance_m = speed * dt_secs as f64;

                // Approximate meters to degrees (1 degree lat ~ 111,000m)
                let dlat = (heading_rad.cos() * distance_m) / 111_000.0;
                let dlon = (heading_rad.sin() * distance_m)
                    / (111_000.0 * prev_lat.to_radians().cos().max(0.01));

                let new_lat = Self::clamp_lat(prev_lat + dlat);
                let new_lon = Self::clamp_lon(prev_lon + dlon);

                // Altitude with small drift
                let prev_alt = self.last_altitude.unwrap_or(100.0);
                let alt_drift = Uniform::new_inclusive(-5.0f64, 5.0).sample(rng);
                let altitude = match mode {
                    MovementMode::Flying => {
                        Uniform::new_inclusive(8000.0f64, 12000.0).sample(rng)
                    }
                    _ => (prev_alt + alt_drift).clamp(0.0, 3000.0),
                };

                let prev_ts = self.last_timestamp.unwrap_or(context.now);
                let timestamp = prev_ts + Duration::seconds(dt_secs);

                (new_lat, new_lon, heading, altitude, timestamp, mode)
            } else {
                // First point: start somewhere in continental US
                let lat =
                    Uniform::new_inclusive(US_LAT_MIN, US_LAT_MAX).sample(rng);
                let lon =
                    Uniform::new_inclusive(US_LON_MIN, US_LON_MAX).sample(rng);
                let heading = Uniform::new_inclusive(0.0f64, 359.99).sample(rng);
                let altitude = Uniform::new_inclusive(0.0f64, 500.0).sample(rng);
                let mode = MovementMode::Stationary;
                let timestamp = context.now;

                (lat, lon, heading, altitude, timestamp, mode)
            };

        let source = Self::choose_source(rng);
        let accuracy = Self::accuracy_for_source(source, rng);
        let speed = Self::speed_for_mode(mode, rng);

        let meta = ArtifactMetadata::new(
            DataCategory::Location,
            timestamp,
            timestamp,
            128, // approximate serialized size
        )?;

        let entry = GpsEntry {
            meta,
            lat,
            lon,
            accuracy_m: accuracy,
            altitude_m: altitude,
            speed_mps: speed,
            heading_deg: heading,
            source,
            timestamp,
        };

        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory {
        DataCategory::Location
    }

    fn forensic_weight(&self) -> u32 {
        85
    }

    fn resource_cost(&self) -> ResourceCost {
        ResourceCost {
            cpu_us: 30,
            disk_bytes: 256,
            network_bytes: 0,
        }
    }
}

impl GpsGenerator {
    /// Generate a coherent trace of `count` GPS entries.
    ///
    /// Unlike the `DataGenerator::generate` method, this maintains state
    /// between points so the trace forms a realistic path with stationary
    /// clusters and travel segments.
    pub fn generate_trace(
        &mut self,
        _profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
        count: usize,
    ) -> Result<Vec<GpsEntry>> {
        let mut entries = Vec::with_capacity(count);

        for _ in 0..count {
            // Check if we need a new movement segment
            if self.segment_remaining == 0 {
                self.current_mode = Self::choose_movement_mode(rng);
                self.segment_remaining = Self::segment_length(self.current_mode, rng);
            }
            self.segment_remaining = self.segment_remaining.saturating_sub(1);

            let (lat, lon, heading, altitude, timestamp) =
                if let (Some(prev_lat), Some(prev_lon)) = (self.last_lat, self.last_lon) {
                    let speed = Self::speed_for_mode(self.current_mode, rng);
                    let dt_secs = Self::time_step_secs(self.current_mode, rng);

                    let prev_heading = self.last_heading.unwrap_or(0.0);
                    let heading_drift =
                        Uniform::new_inclusive(-30.0f64, 30.0).sample(rng);
                    let heading = (prev_heading + heading_drift).rem_euclid(360.0);

                    let heading_rad = heading.to_radians();
                    let distance_m = speed * dt_secs as f64;

                    let dlat = (heading_rad.cos() * distance_m) / 111_000.0;
                    let dlon = (heading_rad.sin() * distance_m)
                        / (111_000.0 * prev_lat.to_radians().cos().max(0.01));

                    let new_lat = Self::clamp_lat(prev_lat + dlat);
                    let new_lon = Self::clamp_lon(prev_lon + dlon);

                    let prev_alt = self.last_altitude.unwrap_or(100.0);
                    let alt_drift =
                        Uniform::new_inclusive(-5.0f64, 5.0).sample(rng);
                    let altitude = match self.current_mode {
                        MovementMode::Flying => {
                            Uniform::new_inclusive(8000.0f64, 12000.0).sample(rng)
                        }
                        _ => (prev_alt + alt_drift).clamp(0.0, 3000.0),
                    };

                    let prev_ts = self.last_timestamp.unwrap_or(context.now);
                    let timestamp = prev_ts + Duration::seconds(dt_secs);

                    (new_lat, new_lon, heading, altitude, timestamp)
                } else {
                    let lat = Uniform::new_inclusive(US_LAT_MIN, US_LAT_MAX)
                        .sample(rng);
                    let lon = Uniform::new_inclusive(US_LON_MIN, US_LON_MAX)
                        .sample(rng);
                    let heading =
                        Uniform::new_inclusive(0.0f64, 359.99).sample(rng);
                    let altitude =
                        Uniform::new_inclusive(0.0f64, 500.0).sample(rng);

                    (lat, lon, heading, altitude, context.now)
                };

            let source = Self::choose_source(rng);
            let accuracy = Self::accuracy_for_source(source, rng);
            let speed = Self::speed_for_mode(self.current_mode, rng);

            let meta = ArtifactMetadata::new(
                DataCategory::Location,
                timestamp,
                timestamp,
                128,
            )?;

            let entry = GpsEntry {
                meta,
                lat,
                lon,
                accuracy_m: accuracy,
                altitude_m: altitude,
                speed_mps: speed,
                heading_deg: heading,
                source,
                timestamp,
            };

            entry.validate_plausibility()?;

            // Update state for next point
            self.last_lat = Some(lat);
            self.last_lon = Some(lon);
            self.last_heading = Some(heading);
            self.last_timestamp = Some(timestamp);
            self.last_altitude = Some(altitude);

            entries.push(entry);
        }

        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    fn test_profile() -> UserProfile {
        UserProfile::default()
    }

    #[test]
    fn test_basic_generation() {
        let gps_gen = GpsGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let artifact = gps_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: GpsEntry = serde_json::from_slice(&bytes).unwrap();

        assert!((-90.0..=90.0).contains(&entry.lat));
        assert!((-180.0..=180.0).contains(&entry.lon));
        assert!(entry.accuracy_m > 0.0);
        assert!(entry.speed_mps >= 0.0);
        assert!((0.0..360.0).contains(&entry.heading_deg));
    }

    #[test]
    fn test_coordinates_in_valid_range() {
        let mut gps_gen = GpsGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(99);

        let entries = gps_gen
            .generate_trace(&profile, &ctx, &mut rng, 200)
            .unwrap();

        for (i, entry) in entries.iter().enumerate() {
            assert!(
                (-90.0..=90.0).contains(&entry.lat),
                "entry {i}: latitude {} out of range",
                entry.lat,
            );
            assert!(
                (-180.0..=180.0).contains(&entry.lon),
                "entry {i}: longitude {} out of range",
                entry.lon,
            );
        }
    }

    #[test]
    fn test_accuracy_always_positive() {
        let mut gps_gen = GpsGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(77);

        let entries = gps_gen
            .generate_trace(&profile, &ctx, &mut rng, 500)
            .unwrap();

        for (i, entry) in entries.iter().enumerate() {
            assert!(
                entry.accuracy_m > 0.0,
                "entry {i}: accuracy must be positive, got {}",
                entry.accuracy_m,
            );
        }
    }

    #[test]
    fn test_speed_non_negative() {
        let mut gps_gen = GpsGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(13);

        let entries = gps_gen
            .generate_trace(&profile, &ctx, &mut rng, 500)
            .unwrap();

        for (i, entry) in entries.iter().enumerate() {
            assert!(
                entry.speed_mps >= 0.0,
                "entry {i}: speed must be non-negative, got {}",
                entry.speed_mps,
            );
        }
    }

    #[test]
    fn test_1000_entry_stress() {
        let mut gps_gen = GpsGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let entries = gps_gen
            .generate_trace(&profile, &ctx, &mut rng, 1000)
            .unwrap();

        assert_eq!(entries.len(), 1000);

        for (i, entry) in entries.iter().enumerate() {
            entry.validate_plausibility().unwrap_or_else(|e| {
                panic!("entry {i} failed plausibility: {e}");
            });
        }

        // Verify timestamps are monotonically increasing
        for window in entries.windows(2) {
            assert!(
                window[1].timestamp >= window[0].timestamp,
                "timestamps must be non-decreasing",
            );
        }
    }

    #[test]
    fn test_trace_forms_coherent_path() {
        let mut gps_gen = GpsGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let entries = gps_gen
            .generate_trace(&profile, &ctx, &mut rng, 100)
            .unwrap();

        // Consecutive non-flying points should be relatively close together.
        // Even at 30 m/s for 300s that is 9km ~ 0.08 degrees.
        // Use a generous threshold that catches truly scattered random points.
        let mut consecutive_close = 0u32;
        for window in entries.windows(2) {
            let dlat = (window[1].lat - window[0].lat).abs();
            let dlon = (window[1].lon - window[0].lon).abs();
            // Within ~50 km (~0.5 degrees) is reasonable for all non-flying modes
            if dlat < 0.5 && dlon < 0.5 {
                consecutive_close += 1;
            }
        }
        // The vast majority of consecutive points should be close
        assert!(
            consecutive_close > 70,
            "most consecutive points should be nearby: got {consecutive_close}/99 close pairs",
        );
    }

    #[test]
    fn test_serialization_roundtrip() {
        let gps_gen = GpsGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let artifact = gps_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: GpsEntry = serde_json::from_slice(&bytes).unwrap();

        // Roundtrip back to bytes
        let bytes2 = serde_json::to_vec(&entry).unwrap();
        let entry2: GpsEntry = serde_json::from_slice(&bytes2).unwrap();

        assert!((entry.lat - entry2.lat).abs() < f64::EPSILON);
        assert!((entry.lon - entry2.lon).abs() < f64::EPSILON);
    }
}
