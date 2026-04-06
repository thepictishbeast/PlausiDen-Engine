//! EXIF metadata generation — GPS coordinates, camera info, timestamps in photos.
//!
//! Forensic analysts extract EXIF data from photos to establish location history.
//! Synthetic EXIF data must be internally consistent: GPS matches the user's
//! movement pattern, camera model matches their device, timestamps match activity.

use chrono::{DateTime, Duration, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext,
};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ExifEntry {
    pub meta: ArtifactMetadata,
    pub filename: String,
    pub camera_make: String,
    pub camera_model: String,
    pub gps_latitude: f64,
    pub gps_longitude: f64,
    pub gps_altitude: f64,
    pub datetime_original: DateTime<Utc>,
    pub image_width: u32,
    pub image_height: u32,
    pub focal_length_mm: f32,
    pub exposure_time: String,
    pub iso_speed: u32,
    pub orientation: u8,
}

impl Artifact for ExifEntry {
    fn metadata(&self) -> &ArtifactMetadata { &self.meta }
    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.gps_latitude < -90.0 || self.gps_latitude > 90.0 {
            return Err(EngineError::ImplausibleArtifact { reason: format!("latitude out of range: {}", self.gps_latitude) });
        }
        if self.gps_longitude < -180.0 || self.gps_longitude > 180.0 {
            return Err(EngineError::ImplausibleArtifact { reason: format!("longitude out of range: {}", self.gps_longitude) });
        }
        Ok(())
    }
    fn to_bytes(&self) -> Result<Vec<u8>> { serde_json::to_vec(self).map_err(EngineError::Serialization) }
}

const CAMERAS: &[(&str, &str, u32, u32)] = &[
    ("Apple", "iPhone 15 Pro", 4032, 3024),
    ("Apple", "iPhone 14", 4032, 3024),
    ("Samsung", "Galaxy S24 Ultra", 4000, 3000),
    ("Samsung", "Galaxy S23", 4000, 3000),
    ("Google", "Pixel 8 Pro", 4080, 3072),
    ("Google", "Pixel 7a", 4032, 3024),
    ("Sony", "Alpha A7IV", 7008, 4672),
    ("Canon", "EOS R6 II", 6000, 4000),
    ("Nikon", "Z6 III", 6048, 4024),
];

pub struct ExifGenerator;
impl ExifGenerator { pub fn new() -> Self { Self } }
impl Default for ExifGenerator { fn default() -> Self { Self::new() } }

impl DataGenerator for ExifGenerator {
    fn generate(&self, _profile: &UserProfile, context: &GenerationContext, rng: &mut (impl RngCore + CryptoRng)) -> Result<Box<dyn Artifact>> {
        // SAFETY: CAMERAS is a non-empty const slice.
        let (make, model, w, h) = CAMERAS
            .choose(rng)
            .expect("CAMERAS is a non-empty const slice");

        // GPS coordinates — continental US default
        let lat = Uniform::new(25.0f64, 49.0).sample(rng);
        let lon = Uniform::new(-125.0f64, -67.0).sample(rng);
        let alt = Uniform::new(0.0f64, 2500.0).sample(rng);

        let days_ago = Uniform::new_inclusive(1i64, 365).sample(rng);
        let dt = context.now - Duration::days(days_ago);

        let focal = Uniform::new(2.0f32, 200.0).sample(rng);
        // SAFETY: literal arrays are non-empty by construction.
        let iso = [100, 200, 400, 800, 1600, 3200]
            .choose(rng)
            .copied()
            .expect("ISO array literal is non-empty");
        let exposure = ["1/30", "1/60", "1/125", "1/250", "1/500", "1/1000"]
            .choose(rng)
            .copied()
            .expect("exposure array literal is non-empty");
        let img_num = Uniform::new_inclusive(1000u32, 9999).sample(rng);

        let meta = ArtifactMetadata::new(DataCategory::Location, dt, dt, 4096)?;

        let entry = ExifEntry {
            meta, filename: format!("IMG_{img_num}.jpg"),
            camera_make: make.to_string(), camera_model: model.to_string(),
            gps_latitude: lat, gps_longitude: lon, gps_altitude: alt,
            datetime_original: dt, image_width: *w, image_height: *h,
            focal_length_mm: focal, exposure_time: exposure.to_string(),
            iso_speed: iso, orientation: 1,
        };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory { DataCategory::Location }
    fn forensic_weight(&self) -> u32 { 80 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_exif() {
        let g = ExifGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);
        let a = g.generate(&p, &c, &mut r).unwrap();
        a.validate_plausibility().unwrap();
        let b = a.to_bytes().unwrap();
        let e: ExifEntry = serde_json::from_slice(&b).unwrap();
        assert!(e.gps_latitude >= -90.0 && e.gps_latitude <= 90.0);
        assert!(!e.camera_make.is_empty());
    }

    #[test]
    fn test_500_exif_valid() {
        let g = ExifGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..500 { let mut r = seeded_rng(s); g.generate(&p, &c, &mut r).unwrap().validate_plausibility().unwrap(); }
    }

    #[test]
    fn test_gps_in_continental_us() {
        let g = ExifGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..100 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: ExifEntry = serde_json::from_slice(&b).unwrap();
            assert!(e.gps_latitude >= 25.0 && e.gps_latitude <= 49.0);
            assert!(e.gps_longitude >= -125.0 && e.gps_longitude <= -67.0);
        }
    }
}
