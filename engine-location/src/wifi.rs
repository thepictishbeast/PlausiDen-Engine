//! WiFi connection history generation with daily movement patterns.
//!
//! Produces WiFi connection log entries that follow plausible daily routines:
//! home networks in the morning/evening, work networks during the day, and
//! public networks (coffee shops, transit) during commute windows.

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

/// Category of WiFi network.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkCategory {
    /// Home network (strong signal, long sessions).
    Home,
    /// Workplace network (moderate signal, business hours).
    Work,
    /// Public hotspot (variable signal, short sessions).
    Public,
}

/// Realistic SSID pools grouped by network category.
const HOME_SSIDS: &[&str] = &[
    "NETGEAR-5G",
    "NETGEAR-2G",
    "Linksys04832",
    "xfinitywifi",
    "ATT-WIFI-5G",
    "MySpectrumWiFi",
    "TP-LINK_Home",
    "ASUS_RT-AX86U",
    "HomeNetwork",
    "FamilyWiFi",
];

const WORK_SSIDS: &[&str] = &[
    "CorpNet",
    "CorpNet-5G",
    "Enterprise-WiFi",
    "CompanyGuest",
    "Office_Secure",
    "ACME-Corp",
    "WorkWPA3",
    "BuildingWiFi-4F",
    "CampusNet",
    "eduroam",
];

const PUBLIC_SSIDS: &[&str] = &[
    "Starbucks WiFi",
    "McDonald's Free WiFi",
    "xfinitywifi",
    "attwifi",
    "Google Starbucks",
    "Airport Free WiFi",
    "Hilton Honors",
    "Library-Public",
    "MetroTransit-WiFi",
    "CoffeeShop_Guest",
];

/// A WiFi connection history entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiEntry {
    /// Artifact metadata.
    pub meta: ArtifactMetadata,
    /// Network name (SSID).
    pub ssid: String,
    /// MAC address of the access point (BSSID).
    pub bssid: String,
    /// Signal strength in dBm (typical range: -30 to -90).
    pub signal_dbm: i32,
    /// Network category (home, work, public).
    pub category: NetworkCategory,
    /// When the connection was established.
    pub connected_at: DateTime<Utc>,
    /// Connection duration in seconds.
    pub duration_secs: u64,
}

impl Artifact for WifiEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;

        if self.ssid.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty SSID".to_string(),
            });
        }

        if self.bssid.len() != 17 {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!(
                    "BSSID must be 17 chars (AA:BB:CC:DD:EE:FF), got {}",
                    self.bssid.len()
                ),
            });
        }

        // Signal strength should be in realistic range
        if !(-100..=0).contains(&self.signal_dbm) {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!(
                    "signal strength {} dBm out of realistic range [-100, 0]",
                    self.signal_dbm
                ),
            });
        }

        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

/// Generates WiFi connection history entries following daily patterns.
///
/// Networks are chosen based on time of day to simulate a realistic
/// home-commute-work-commute-home cycle.
pub struct WifiGenerator {
    /// Persistent "home" SSID for this persona.
    home_ssid: Option<String>,
    /// Persistent "home" BSSID.
    home_bssid: Option<String>,
    /// Persistent "work" SSID for this persona.
    work_ssid: Option<String>,
    /// Persistent "work" BSSID.
    work_bssid: Option<String>,
}

impl WifiGenerator {
    /// Create a new WiFi generator with no persistent networks yet.
    pub fn new() -> Self {
        Self {
            home_ssid: None,
            home_bssid: None,
            work_ssid: None,
            work_bssid: None,
        }
    }

    /// Generate a random MAC address formatted as AA:BB:CC:DD:EE:FF.
    fn random_bssid(rng: &mut (impl RngCore + CryptoRng)) -> String {
        let octets: Vec<String> = (0..6)
            .map(|_| {
                let b = Uniform::new_inclusive(0u8, 255).sample(rng);
                format!("{b:02X}")
            })
            .collect();
        octets.join(":")
    }

    /// Determine network category based on hour of day and activity schedule.
    fn category_for_hour(hour: u32, profile: &UserProfile) -> NetworkCategory {
        let wake = profile.activity_schedule.wake_hour as u32;
        let sleep = profile.activity_schedule.sleep_hour as u32;

        // Commute windows: 1-2 hours after wake, 1-2 hours before typical end-of-work
        let morning_commute_end = wake + 2;
        let work_end = if sleep > 5 { sleep - 5 } else { 17 };
        let evening_commute_end = work_end + 2;

        if hour < wake || hour >= sleep {
            // Sleeping or late night: home
            NetworkCategory::Home
        } else if hour < morning_commute_end {
            // Morning: leaving home, might hit public wifi
            NetworkCategory::Public
        } else if hour < work_end {
            // Working hours
            NetworkCategory::Work
        } else if hour < evening_commute_end {
            // Evening commute
            NetworkCategory::Public
        } else {
            // Evening at home
            NetworkCategory::Home
        }
    }

    /// Signal strength based on network category.
    fn signal_for_category(
        cat: NetworkCategory,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> i32 {
        let (lo, hi) = match cat {
            // Home: strong signal (close to AP)
            NetworkCategory::Home => (-55, -30),
            // Work: moderate signal
            NetworkCategory::Work => (-70, -40),
            // Public: variable, often weaker
            NetworkCategory::Public => (-90, -50),
        };
        Uniform::new_inclusive(lo, hi).sample(rng)
    }

    /// Connection duration based on category.
    fn duration_for_category(
        cat: NetworkCategory,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> u64 {
        let (lo, hi) = match cat {
            // Home: long sessions (1-8 hours)
            NetworkCategory::Home => (3600u64, 28800),
            // Work: medium sessions (2-6 hours)
            NetworkCategory::Work => (7200u64, 21600),
            // Public: short sessions (5 min to 1 hour)
            NetworkCategory::Public => (300u64, 3600),
        };
        Uniform::new_inclusive(lo, hi).sample(rng)
    }

    /// Initialize persistent home/work networks for this persona.
    ///
    /// Call this once before generating entries to ensure consistent
    /// SSID and BSSID values across a generation session.
    pub fn init_persistent_networks(
        &mut self,
        rng: &mut (impl RngCore + CryptoRng),
    ) {
        if self.home_ssid.is_none() {
            self.home_ssid = HOME_SSIDS
                .choose(rng)
                .map(|s| (*s).to_string());
            self.home_bssid = Some(Self::random_bssid(rng));
        }
        if self.work_ssid.is_none() {
            self.work_ssid = WORK_SSIDS
                .choose(rng)
                .map(|s| (*s).to_string());
            self.work_bssid = Some(Self::random_bssid(rng));
        }
    }
}

impl Default for WifiGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for WifiGenerator {
    fn generate(
        &self,
        profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        let hour = context.now.hour();
        let cat = Self::category_for_hour(hour, profile);

        let (ssid, bssid) = match cat {
            NetworkCategory::Home => {
                let ssid = self
                    .home_ssid
                    .clone()
                    .unwrap_or_else(|| {
                        HOME_SSIDS
                            .choose(rng)
                            .map(|s| (*s).to_string())
                            .unwrap_or_else(|| "HomeWiFi".to_string())
                    });
                let bssid = self
                    .home_bssid
                    .clone()
                    .unwrap_or_else(|| Self::random_bssid(rng));
                (ssid, bssid)
            }
            NetworkCategory::Work => {
                let ssid = self
                    .work_ssid
                    .clone()
                    .unwrap_or_else(|| {
                        WORK_SSIDS
                            .choose(rng)
                            .map(|s| (*s).to_string())
                            .unwrap_or_else(|| "OfficeNet".to_string())
                    });
                let bssid = self
                    .work_bssid
                    .clone()
                    .unwrap_or_else(|| Self::random_bssid(rng));
                (ssid, bssid)
            }
            NetworkCategory::Public => {
                let ssid = PUBLIC_SSIDS
                    .choose(rng)
                    .map(|s| (*s).to_string())
                    .unwrap_or_else(|| "FreeWiFi".to_string());
                let bssid = Self::random_bssid(rng);
                (ssid, bssid)
            }
        };

        let signal = Self::signal_for_category(cat, rng);
        let duration = Self::duration_for_category(cat, rng);

        // Connection time: slightly before context.now with jitter
        let jitter_secs = Uniform::new_inclusive(0i64, 600).sample(rng);
        let connected_at = context.now - Duration::seconds(jitter_secs);

        let meta = ArtifactMetadata::new(
            DataCategory::Location,
            connected_at,
            connected_at,
            ssid.len() as u64 + bssid.len() as u64 + 64,
        )?;

        let entry = WifiEntry {
            meta,
            ssid,
            bssid,
            signal_dbm: signal,
            category: cat,
            connected_at,
            duration_secs: duration,
        };

        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory {
        DataCategory::Location
    }

    fn forensic_weight(&self) -> u32 {
        80 // WiFi logs are secondary to GPS but still forensically valuable
    }

    fn resource_cost(&self) -> ResourceCost {
        ResourceCost {
            cpu_us: 20,
            disk_bytes: 192,
            network_bytes: 0,
        }
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
    fn test_basic_wifi_generation() {
        let wifi_gen = WifiGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let artifact = wifi_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: WifiEntry = serde_json::from_slice(&bytes).unwrap();

        assert!(!entry.ssid.is_empty());
        assert_eq!(entry.bssid.len(), 17); // AA:BB:CC:DD:EE:FF
        assert!((-100..=0).contains(&entry.signal_dbm));
        assert!(entry.duration_secs > 0);
    }

    #[test]
    fn test_bssid_format() {
        let wifi_gen = WifiGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(99);

        for _ in 0..100 {
            let artifact = wifi_gen.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: WifiEntry = serde_json::from_slice(&bytes).unwrap();

            // BSSID must be AA:BB:CC:DD:EE:FF format
            let parts: Vec<&str> = entry.bssid.split(':').collect();
            assert_eq!(
                parts.len(),
                6,
                "BSSID must have 6 octets: {}",
                entry.bssid,
            );
            for part in &parts {
                assert_eq!(
                    part.len(),
                    2,
                    "each BSSID octet must be 2 hex chars: {}",
                    entry.bssid,
                );
            }
        }
    }

    #[test]
    fn test_signal_strength_in_range() {
        let wifi_gen = WifiGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(77);

        for i in 0..500 {
            let artifact = wifi_gen.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: WifiEntry = serde_json::from_slice(&bytes).unwrap();

            assert!(
                (-100..=0).contains(&entry.signal_dbm),
                "entry {i}: signal {} dBm out of range",
                entry.signal_dbm,
            );
        }
    }

    #[test]
    fn test_daily_pattern_categories() {
        let profile = test_profile(); // wake=7, sleep=23

        // Late night -> Home
        assert_eq!(
            WifiGenerator::category_for_hour(3, &profile),
            NetworkCategory::Home,
        );

        // Morning commute (7-9) -> Public
        assert_eq!(
            WifiGenerator::category_for_hour(8, &profile),
            NetworkCategory::Public,
        );

        // Work hours (9-18) -> Work
        assert_eq!(
            WifiGenerator::category_for_hour(12, &profile),
            NetworkCategory::Work,
        );

        // Evening commute (18-20) -> Public
        assert_eq!(
            WifiGenerator::category_for_hour(19, &profile),
            NetworkCategory::Public,
        );

        // Evening at home (20-23) -> Home
        assert_eq!(
            WifiGenerator::category_for_hour(21, &profile),
            NetworkCategory::Home,
        );
    }

    #[test]
    fn test_serialization_roundtrip() {
        let wifi_gen = WifiGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let artifact = wifi_gen.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: WifiEntry = serde_json::from_slice(&bytes).unwrap();

        let bytes2 = serde_json::to_vec(&entry).unwrap();
        let entry2: WifiEntry = serde_json::from_slice(&bytes2).unwrap();

        assert_eq!(entry.ssid, entry2.ssid);
        assert_eq!(entry.bssid, entry2.bssid);
        assert_eq!(entry.signal_dbm, entry2.signal_dbm);
    }
}
