//! GPS trace generation with realistic movement and circadian patterns.
//!
//! Produces GPS trace entries that follow plausible daily routines:
//! home at night, commute in the morning/evening, work during the day.
//! Points start from a seed city center chosen from a pool of 20+
//! major US cities, then evolve via a random-walk-with-momentum model
//! where speed determines step size and heading provides directional
//! continuity.
//!
//! GPS jitter varies by context: outdoor fixes achieve +/-5m accuracy,
//! indoor fixes degrade to +/-20m.

use chrono::{DateTime, Duration, Timelike, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext, ResourceCost,
};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// City seed pool (20+ US cities with approximate center coordinates)
// ---------------------------------------------------------------------------

/// A seed city with center latitude, longitude, and name (for debugging).
struct CityCenter {
    lat: f64,
    lon: f64,
    #[allow(dead_code)]
    name: &'static str,
}

/// Pool of 24 major US city centers for initial seed points.
const CITY_POOL: &[CityCenter] = &[
    CityCenter {
        lat: 40.7128,
        lon: -74.0060,
        name: "New York",
    },
    CityCenter {
        lat: 34.0522,
        lon: -118.2437,
        name: "Los Angeles",
    },
    CityCenter {
        lat: 41.8781,
        lon: -87.6298,
        name: "Chicago",
    },
    CityCenter {
        lat: 29.7604,
        lon: -95.3698,
        name: "Houston",
    },
    CityCenter {
        lat: 33.4484,
        lon: -112.0740,
        name: "Phoenix",
    },
    CityCenter {
        lat: 29.9511,
        lon: -90.0715,
        name: "New Orleans",
    },
    CityCenter {
        lat: 39.7392,
        lon: -104.9903,
        name: "Denver",
    },
    CityCenter {
        lat: 47.6062,
        lon: -122.3321,
        name: "Seattle",
    },
    CityCenter {
        lat: 37.7749,
        lon: -122.4194,
        name: "San Francisco",
    },
    CityCenter {
        lat: 30.2672,
        lon: -97.7431,
        name: "Austin",
    },
    CityCenter {
        lat: 35.2271,
        lon: -80.8431,
        name: "Charlotte",
    },
    CityCenter {
        lat: 42.3601,
        lon: -71.0589,
        name: "Boston",
    },
    CityCenter {
        lat: 38.9072,
        lon: -77.0369,
        name: "Washington DC",
    },
    CityCenter {
        lat: 36.1627,
        lon: -86.7816,
        name: "Nashville",
    },
    CityCenter {
        lat: 39.9612,
        lon: -82.9988,
        name: "Columbus",
    },
    CityCenter {
        lat: 32.7767,
        lon: -96.7970,
        name: "Dallas",
    },
    CityCenter {
        lat: 45.5152,
        lon: -122.6784,
        name: "Portland",
    },
    CityCenter {
        lat: 25.7617,
        lon: -80.1918,
        name: "Miami",
    },
    CityCenter {
        lat: 33.7490,
        lon: -84.3880,
        name: "Atlanta",
    },
    CityCenter {
        lat: 44.9778,
        lon: -93.2650,
        name: "Minneapolis",
    },
    CityCenter {
        lat: 36.1699,
        lon: -115.1398,
        name: "Las Vegas",
    },
    CityCenter {
        lat: 37.3382,
        lon: -121.8863,
        name: "San Jose",
    },
    CityCenter {
        lat: 35.4676,
        lon: -97.5164,
        name: "Oklahoma City",
    },
    CityCenter {
        lat: 43.0389,
        lon: -87.9065,
        name: "Milwaukee",
    },
];

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Location data source type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LocationSource {
    /// Satellite GPS fix (high accuracy outdoors).
    Gps,
    /// WiFi-based positioning (moderate accuracy).
    WiFi,
    /// Cell tower triangulation (low accuracy).
    Cell,
    /// Fused provider combining multiple sources.
    Fused,
}

/// Movement mode determining speed range and behavior.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MovementMode {
    /// Stationary or minor fidgeting (0-0.3 m/s).
    Stationary,
    /// Walking pace (0.83-1.67 m/s, approximately 3-6 km/h).
    Walking,
    /// Vehicle travel (8.33-22.22 m/s, approximately 30-80 km/h).
    Driving,
}

/// A single GPS trace point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpsPoint {
    /// Artifact metadata (id, timestamps, category).
    pub meta: ArtifactMetadata,
    /// Latitude in decimal degrees (-90 to 90).
    pub lat: f64,
    /// Longitude in decimal degrees (-180 to 180).
    pub lon: f64,
    /// Altitude above sea level in meters.
    pub altitude: f64,
    /// Horizontal accuracy in meters.
    pub accuracy: f64,
    /// Speed in meters per second.
    pub speed: f64,
    /// Bearing in degrees (0-359, 0 = north, 90 = east).
    pub bearing: f64,
    /// Timestamp of this fix.
    pub timestamp: DateTime<Utc>,
    /// Location data source.
    pub source: LocationSource,
    /// Current movement mode.
    pub mode: MovementMode,
}

impl Artifact for GpsPoint {
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
        if self.accuracy <= 0.0 {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!("accuracy must be positive, got {}", self.accuracy),
            });
        }
        if self.speed < 0.0 {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!("speed must be non-negative, got {}", self.speed),
            });
        }
        if !(0.0..360.0).contains(&self.bearing) {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!("bearing {} out of range [0, 360)", self.bearing),
            });
        }

        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

// ---------------------------------------------------------------------------
// Circadian phase (determines movement patterns by time of day)
// ---------------------------------------------------------------------------

/// Phase of the daily circadian cycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CircadianPhase {
    /// Sleeping at home (midnight - wake).
    HomeNight,
    /// Morning commute (wake - wake+1h).
    CommuteMorning,
    /// At workplace (wake+1h - ~17:00).
    WorkDay,
    /// Evening commute (~17:00 - ~18:00).
    CommuteEvening,
    /// At home in the evening (~18:00 - sleep).
    HomeEvening,
}

impl CircadianPhase {
    /// Determine phase from hour-of-day and user activity schedule.
    fn from_hour(hour: u32, profile: &UserProfile) -> Self {
        let wake = profile.activity_schedule.wake_hour as u32;
        let sleep = profile.activity_schedule.sleep_hour as u32;
        let commute_morning_end = (wake + 1).min(23);
        let work_end = if sleep > 6 {
            sleep.saturating_sub(5)
        } else {
            17
        };
        let commute_evening_end = (work_end + 1).min(23);

        if hour < wake || hour >= sleep {
            CircadianPhase::HomeNight
        } else if hour < commute_morning_end {
            CircadianPhase::CommuteMorning
        } else if hour < work_end {
            CircadianPhase::WorkDay
        } else if hour < commute_evening_end {
            CircadianPhase::CommuteEvening
        } else {
            CircadianPhase::HomeEvening
        }
    }

    /// Preferred movement mode for this phase.
    fn preferred_mode(self) -> MovementMode {
        match self {
            Self::HomeNight | Self::WorkDay | Self::HomeEvening => MovementMode::Stationary,
            Self::CommuteMorning | Self::CommuteEvening => MovementMode::Driving,
        }
    }
}

// ---------------------------------------------------------------------------
// GPS jitter helpers
// ---------------------------------------------------------------------------

/// Whether the user is likely indoors or outdoors given the circadian phase.
fn is_indoor(phase: CircadianPhase) -> bool {
    matches!(
        phase,
        CircadianPhase::HomeNight | CircadianPhase::WorkDay | CircadianPhase::HomeEvening
    )
}

/// GPS accuracy jitter in meters.
///
/// Outdoor: 3-8 m (clear sky satellite fix).
/// Indoor: 10-25 m (signal attenuation through walls).
fn accuracy_jitter(indoor: bool, rng: &mut (impl RngCore + CryptoRng)) -> f64 {
    if indoor {
        Uniform::new_inclusive(10.0, 25.0).sample(rng)
    } else {
        Uniform::new_inclusive(3.0, 8.0).sample(rng)
    }
}

// ---------------------------------------------------------------------------
// GpsTraceGenerator
// ---------------------------------------------------------------------------

/// Generates GPS trace entries with circadian movement patterns.
///
/// Each generation cycle produces a single [`GpsPoint`]. The generator
/// maintains internal state so consecutive calls form a coherent trace:
///
/// - Starts from a randomly selected city center (pool of 24 US cities).
/// - Movement mode follows the user's activity schedule: stationary at
///   home during night, driving during commute, stationary at work, etc.
/// - GPS jitter is +/-5m outdoors, +/-20m indoors.
/// - Walking: 3-6 km/h, Driving: 30-80 km/h, Stationary: near-zero drift.
pub struct GpsTraceGenerator {
    /// Last generated latitude.
    last_lat: Option<f64>,
    /// Last generated longitude.
    last_lon: Option<f64>,
    /// Last bearing for momentum.
    last_bearing: Option<f64>,
    /// Last timestamp for time progression.
    last_timestamp: Option<DateTime<Utc>>,
    /// Last altitude for terrain continuity.
    last_altitude: Option<f64>,
    /// Current movement mode.
    current_mode: MovementMode,
    /// Points remaining in the current movement segment.
    segment_remaining: u32,
}

impl GpsTraceGenerator {
    /// Create a new GPS trace generator with no prior state.
    pub fn new() -> Self {
        Self {
            last_lat: None,
            last_lon: None,
            last_bearing: None,
            last_timestamp: None,
            last_altitude: None,
            current_mode: MovementMode::Stationary,
            segment_remaining: 0,
        }
    }

    /// Choose movement mode weighted by circadian phase plus randomness.
    ///
    /// The circadian-preferred mode is chosen 70% of the time; the
    /// remaining 30% allows for short walks during work or brief
    /// driving errands at night.
    fn choose_mode(phase: CircadianPhase, rng: &mut (impl RngCore + CryptoRng)) -> MovementMode {
        let roll = Uniform::new_inclusive(0u32, 99).sample(rng);
        let preferred = phase.preferred_mode();

        if roll < 70 {
            preferred
        } else if roll < 85 {
            MovementMode::Walking
        } else {
            match preferred {
                MovementMode::Stationary => MovementMode::Driving,
                MovementMode::Walking => MovementMode::Stationary,
                MovementMode::Driving => MovementMode::Stationary,
            }
        }
    }

    /// Speed in m/s for a given movement mode.
    ///
    /// Walking: 0.83-1.67 m/s (3-6 km/h).
    /// Driving: 8.33-22.22 m/s (30-80 km/h).
    /// Stationary: 0-0.3 m/s (GPS drift).
    fn speed_for_mode(mode: MovementMode, rng: &mut (impl RngCore + CryptoRng)) -> f64 {
        let (lo, hi) = match mode {
            MovementMode::Stationary => (0.0, 0.3),
            MovementMode::Walking => (0.83, 1.67),
            MovementMode::Driving => (8.33, 22.22),
        };
        Uniform::new_inclusive(lo, hi).sample(rng)
    }

    /// Time between fixes in seconds, based on mode.
    fn time_step_secs(mode: MovementMode, rng: &mut (impl RngCore + CryptoRng)) -> i64 {
        match mode {
            MovementMode::Stationary => Uniform::new_inclusive(30i64, 300).sample(rng),
            MovementMode::Walking => Uniform::new_inclusive(5i64, 30).sample(rng),
            MovementMode::Driving => Uniform::new_inclusive(3i64, 15).sample(rng),
        }
    }

    /// Number of points in one movement segment.
    fn segment_length(mode: MovementMode, rng: &mut (impl RngCore + CryptoRng)) -> u32 {
        match mode {
            MovementMode::Stationary => Uniform::new_inclusive(5u32, 30).sample(rng),
            MovementMode::Walking => Uniform::new_inclusive(10u32, 50).sample(rng),
            MovementMode::Driving => Uniform::new_inclusive(20u32, 80).sample(rng),
        }
    }

    /// Choose a location source with weighted probability.
    fn choose_source(rng: &mut (impl RngCore + CryptoRng)) -> LocationSource {
        let roll = Uniform::new_inclusive(0u32, 99).sample(rng);
        match roll {
            0..=49 => LocationSource::Fused,
            50..=79 => LocationSource::Gps,
            80..=94 => LocationSource::WiFi,
            _ => LocationSource::Cell,
        }
    }

    /// Clamp latitude to valid range.
    fn clamp_lat(lat: f64) -> f64 {
        lat.clamp(-90.0, 90.0)
    }

    /// Wrap longitude to [-180, 180].
    fn wrap_lon(lon: f64) -> f64 {
        let mut l = lon;
        while l > 180.0 {
            l -= 360.0;
        }
        while l < -180.0 {
            l += 360.0;
        }
        l
    }

    /// Generate a coherent trace of `count` GPS points.
    ///
    /// Unlike `DataGenerator::generate`, this maintains state between
    /// points so the trace forms a realistic path with circadian patterns.
    pub fn generate_trace(
        &mut self,
        profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
        count: usize,
    ) -> Result<Vec<GpsPoint>> {
        let mut entries = Vec::with_capacity(count);

        for _ in 0..count {
            let ts = self.last_timestamp.unwrap_or(context.now);
            let hour = ts.hour();
            let phase = CircadianPhase::from_hour(hour, profile);

            // Start new segment if needed
            if self.segment_remaining == 0 {
                self.current_mode = Self::choose_mode(phase, rng);
                self.segment_remaining = Self::segment_length(self.current_mode, rng);
            }
            self.segment_remaining = self.segment_remaining.saturating_sub(1);

            let (lat, lon, bearing, altitude, timestamp) =
                if let (Some(prev_lat), Some(prev_lon)) = (self.last_lat, self.last_lon) {
                    let speed = Self::speed_for_mode(self.current_mode, rng);
                    let dt_secs = Self::time_step_secs(self.current_mode, rng);

                    let prev_bearing = self.last_bearing.unwrap_or(0.0);
                    let bearing_drift = Uniform::new_inclusive(-30.0f64, 30.0).sample(rng);
                    let bearing = (prev_bearing + bearing_drift).rem_euclid(360.0);

                    let bearing_rad = bearing.to_radians();
                    let distance_m = speed * dt_secs as f64;

                    let dlat = (bearing_rad.cos() * distance_m) / 111_000.0;
                    let dlon = (bearing_rad.sin() * distance_m)
                        / (111_000.0 * prev_lat.to_radians().cos().max(0.01));

                    let new_lat = Self::clamp_lat(prev_lat + dlat);
                    let new_lon = Self::wrap_lon(prev_lon + dlon);

                    let prev_alt = self.last_altitude.unwrap_or(100.0);
                    let alt_drift = Uniform::new_inclusive(-3.0f64, 3.0).sample(rng);
                    let altitude = (prev_alt + alt_drift).clamp(0.0, 3000.0);

                    let prev_ts = self.last_timestamp.unwrap_or(context.now);
                    let timestamp = prev_ts + Duration::seconds(dt_secs);

                    (new_lat, new_lon, bearing, altitude, timestamp)
                } else {
                    // First point: seed from a random city center
                    let city = CITY_POOL.choose(rng).unwrap_or(&CITY_POOL[0]);
                    // Small offset from exact center (up to ~2 km)
                    let lat_offset = Uniform::new_inclusive(-0.02f64, 0.02).sample(rng);
                    let lon_offset = Uniform::new_inclusive(-0.02f64, 0.02).sample(rng);
                    let lat = Self::clamp_lat(city.lat + lat_offset);
                    let lon = Self::wrap_lon(city.lon + lon_offset);
                    let bearing = Uniform::new_inclusive(0.0f64, 359.99).sample(rng);
                    let altitude = Uniform::new_inclusive(0.0f64, 500.0).sample(rng);

                    (lat, lon, bearing, altitude, context.now)
                };

            let source = Self::choose_source(rng);
            let indoor = is_indoor(phase);
            let accuracy = accuracy_jitter(indoor, rng);
            let speed = Self::speed_for_mode(self.current_mode, rng);

            let meta = ArtifactMetadata::new(DataCategory::Location, timestamp, timestamp, 192)?;

            let entry = GpsPoint {
                meta,
                lat,
                lon,
                altitude,
                accuracy,
                speed,
                bearing,
                timestamp,
                source,
                mode: self.current_mode,
            };

            entry.validate_plausibility()?;

            // Update state for next point
            self.last_lat = Some(lat);
            self.last_lon = Some(lon);
            self.last_bearing = Some(bearing);
            self.last_timestamp = Some(timestamp);
            self.last_altitude = Some(altitude);

            entries.push(entry);
        }

        Ok(entries)
    }
}

impl Default for GpsTraceGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for GpsTraceGenerator {
    fn generate(
        &self,
        profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        // Single-point generation: compute everything from context without
        // relying on internal state (the trait takes &self).
        let hour = context.now.hour();
        let phase = CircadianPhase::from_hour(hour, profile);
        let mode = Self::choose_mode(phase, rng);

        let (lat, lon, bearing, altitude) =
            if let (Some(prev_lat), Some(prev_lon)) = (self.last_lat, self.last_lon) {
                let speed = Self::speed_for_mode(mode, rng);
                let dt_secs = Self::time_step_secs(mode, rng);

                let prev_bearing = self.last_bearing.unwrap_or(0.0);
                let drift = Uniform::new_inclusive(-30.0f64, 30.0).sample(rng);
                let bearing = (prev_bearing + drift).rem_euclid(360.0);
                let bearing_rad = bearing.to_radians();
                let distance_m = speed * dt_secs as f64;

                let dlat = (bearing_rad.cos() * distance_m) / 111_000.0;
                let dlon = (bearing_rad.sin() * distance_m)
                    / (111_000.0 * prev_lat.to_radians().cos().max(0.01));

                let new_lat = Self::clamp_lat(prev_lat + dlat);
                let new_lon = Self::wrap_lon(prev_lon + dlon);

                let prev_alt = self.last_altitude.unwrap_or(100.0);
                let alt_drift = Uniform::new_inclusive(-3.0f64, 3.0).sample(rng);
                let altitude = (prev_alt + alt_drift).clamp(0.0, 3000.0);

                (new_lat, new_lon, bearing, altitude)
            } else {
                let city = CITY_POOL.choose(rng).unwrap_or(&CITY_POOL[0]);
                let lat_off = Uniform::new_inclusive(-0.02f64, 0.02).sample(rng);
                let lon_off = Uniform::new_inclusive(-0.02f64, 0.02).sample(rng);
                let lat = Self::clamp_lat(city.lat + lat_off);
                let lon = Self::wrap_lon(city.lon + lon_off);
                let bearing = Uniform::new_inclusive(0.0f64, 359.99).sample(rng);
                let altitude = Uniform::new_inclusive(0.0f64, 500.0).sample(rng);
                (lat, lon, bearing, altitude)
            };

        let source = Self::choose_source(rng);
        let indoor = is_indoor(phase);
        let accuracy = accuracy_jitter(indoor, rng);
        let speed = Self::speed_for_mode(mode, rng);

        let meta = ArtifactMetadata::new(DataCategory::Location, context.now, context.now, 192)?;

        let entry = GpsPoint {
            meta,
            lat,
            lon,
            altitude,
            accuracy,
            speed,
            bearing,
            timestamp: context.now,
            source,
            mode,
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    fn test_profile() -> UserProfile {
        UserProfile::default()
    }

    #[test]
    fn test_basic_generation_produces_valid_point() {
        let gps = GpsTraceGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let artifact = gps.generate(&profile, &ctx, &mut rng);
        assert!(artifact.is_ok(), "generate must succeed");
        let artifact = artifact.expect("checked above");
        let bytes = artifact.to_bytes().expect("serialization must succeed");
        let point: GpsPoint = serde_json::from_slice(&bytes).expect("deserialize");

        assert!((-90.0..=90.0).contains(&point.lat));
        assert!((-180.0..=180.0).contains(&point.lon));
        assert!(point.accuracy > 0.0);
        assert!(point.speed >= 0.0);
        assert!((0.0..360.0).contains(&point.bearing));
    }

    #[test]
    fn test_seed_point_is_near_a_city_center() {
        let mut gps = GpsTraceGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(123);

        let entries = gps.generate_trace(&profile, &ctx, &mut rng, 1);
        assert!(entries.is_ok());
        let entries = entries.expect("checked above");
        let first = &entries[0];

        // Must be within ~0.03 degrees (~3 km) of at least one city center
        let near_any_city = CITY_POOL
            .iter()
            .any(|c| (first.lat - c.lat).abs() < 0.03 && (first.lon - c.lon).abs() < 0.03);
        assert!(near_any_city, "first point must be near a seed city");
    }

    #[test]
    fn test_circadian_phase_classification() {
        let profile = test_profile(); // wake=7, sleep=23

        assert_eq!(
            CircadianPhase::from_hour(3, &profile),
            CircadianPhase::HomeNight,
        );
        assert_eq!(
            CircadianPhase::from_hour(7, &profile),
            CircadianPhase::CommuteMorning,
        );
        assert_eq!(
            CircadianPhase::from_hour(12, &profile),
            CircadianPhase::WorkDay,
        );
        assert_eq!(
            CircadianPhase::from_hour(18, &profile),
            CircadianPhase::CommuteEvening,
        );
        assert_eq!(
            CircadianPhase::from_hour(20, &profile),
            CircadianPhase::HomeEvening,
        );
    }

    #[test]
    fn test_indoor_accuracy_worse_than_outdoor() {
        let mut rng = seeded_rng(55);

        let mut indoor_total = 0.0;
        let mut outdoor_total = 0.0;
        let n = 200;

        for _ in 0..n {
            indoor_total += accuracy_jitter(true, &mut rng);
            outdoor_total += accuracy_jitter(false, &mut rng);
        }

        let indoor_avg = indoor_total / n as f64;
        let outdoor_avg = outdoor_total / n as f64;

        assert!(
            indoor_avg > outdoor_avg,
            "indoor accuracy ({indoor_avg:.1}m) should be worse than outdoor ({outdoor_avg:.1}m)",
        );
    }

    #[test]
    fn test_walking_speed_range() {
        let mut rng = seeded_rng(66);

        for _ in 0..500 {
            let speed = GpsTraceGenerator::speed_for_mode(MovementMode::Walking, &mut rng);
            // Walking: 3-6 km/h = 0.83-1.67 m/s
            assert!(
                speed >= 0.83 && speed <= 1.67,
                "walking speed {speed} m/s out of range [0.83, 1.67]",
            );
        }
    }

    #[test]
    fn test_driving_speed_range() {
        let mut rng = seeded_rng(77);

        for _ in 0..500 {
            let speed = GpsTraceGenerator::speed_for_mode(MovementMode::Driving, &mut rng);
            // Driving: 30-80 km/h = 8.33-22.22 m/s
            assert!(
                speed >= 8.33 && speed <= 22.22,
                "driving speed {speed} m/s out of range [8.33, 22.22]",
            );
        }
    }

    #[test]
    fn test_trace_1000_points_all_valid() {
        let mut gps = GpsTraceGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let entries = gps.generate_trace(&profile, &ctx, &mut rng, 1000);
        assert!(entries.is_ok());
        let entries = entries.expect("checked above");
        assert_eq!(entries.len(), 1000);

        for (i, entry) in entries.iter().enumerate() {
            if let Err(e) = entry.validate_plausibility() {
                panic!("entry {i} failed plausibility: {e}");
            }
        }
    }

    #[test]
    fn test_timestamps_monotonically_increase() {
        let mut gps = GpsTraceGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let entries = gps
            .generate_trace(&profile, &ctx, &mut rng, 200)
            .expect("trace generation");

        for pair in entries.windows(2) {
            assert!(
                pair[1].timestamp >= pair[0].timestamp,
                "timestamps must be non-decreasing",
            );
        }
    }

    #[test]
    fn test_serialization_roundtrip() {
        let gps = GpsTraceGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let artifact = gps.generate(&profile, &ctx, &mut rng).expect("generate");
        let bytes = artifact.to_bytes().expect("to_bytes");
        let point: GpsPoint = serde_json::from_slice(&bytes).expect("deserialize");

        let bytes2 = serde_json::to_vec(&point).expect("re-serialize");
        let point2: GpsPoint = serde_json::from_slice(&bytes2).expect("re-deserialize");

        assert!((point.lat - point2.lat).abs() < f64::EPSILON);
        assert!((point.lon - point2.lon).abs() < f64::EPSILON);
        assert_eq!(point.mode, point2.mode);
    }

    #[test]
    fn test_trace_coherent_path_consecutive_close() {
        let mut gps = GpsTraceGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let entries = gps
            .generate_trace(&profile, &ctx, &mut rng, 100)
            .expect("trace generation");

        let mut close_pairs = 0u32;
        for pair in entries.windows(2) {
            let dlat = (pair[1].lat - pair[0].lat).abs();
            let dlon = (pair[1].lon - pair[0].lon).abs();
            if dlat < 0.5 && dlon < 0.5 {
                close_pairs += 1;
            }
        }
        assert!(
            close_pairs > 80,
            "most consecutive points should be nearby: got {close_pairs}/99 close pairs",
        );
    }
}
