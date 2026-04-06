//! WiFi network encounter generation with realistic SSIDs and signal patterns.
//!
//! Produces WiFi sighting records that follow plausible daily routines:
//! home networks morning/evening, corporate networks during work, public
//! hotspots during commute. Signal strength varies over time to simulate
//! entering and leaving range. SSIDs follow common naming patterns:
//! "HOME-XXXX", "CoffeeShop-Guest", "OFFICE_5G", "xfinitywifi", etc.

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
// Network category
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// SSID pools
// ---------------------------------------------------------------------------

/// Home network SSID templates. "XXXX" is replaced with random hex digits.
const HOME_SSID_TEMPLATES: &[&str] = &[
    "HOME-XXXX",
    "NETGEAR-XXXX",
    "NETGEAR-5G",
    "Linksys-XXXX",
    "xfinitywifi",
    "ATT-WIFI-XXXX",
    "MySpectrumWiFi-XXXX",
    "TP-LINK_XXXX",
    "ASUS_XXXX",
    "FamilyWiFi",
    "HomeNetwork",
    "MyWiFi-5G",
];

/// Work network SSIDs.
const WORK_SSIDS: &[&str] = &[
    "CorpNet",
    "CorpNet-5G",
    "Enterprise-WiFi",
    "OFFICE_5G",
    "Office_Secure",
    "ACME-Corp",
    "CompanyGuest",
    "BuildingWiFi-4F",
    "CampusNet",
    "eduroam",
    "WorkWPA3",
];

/// Public hotspot SSIDs.
const PUBLIC_SSIDS: &[&str] = &[
    "Starbucks WiFi",
    "CoffeeShop-Guest",
    "McDonald's Free WiFi",
    "xfinitywifi",
    "attwifi",
    "Google Starbucks",
    "Airport Free WiFi",
    "Hilton Honors",
    "Library-Public",
    "MetroTransit-WiFi",
    "BusStation-Free",
    "Mall-WiFi",
];

/// Common WiFi channels (2.4 GHz and 5 GHz).
const CHANNELS_24GHZ: &[u8] = &[1, 6, 11];
const CHANNELS_5GHZ: &[u8] = &[36, 40, 44, 48, 149, 153, 157, 161];

// ---------------------------------------------------------------------------
// WifiSighting
// ---------------------------------------------------------------------------

/// A single WiFi network sighting record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WifiSighting {
    /// Artifact metadata (id, timestamps, category).
    pub meta: ArtifactMetadata,
    /// Network name (SSID).
    pub ssid: String,
    /// MAC address of the access point (BSSID), format AA:BB:CC:DD:EE:FF.
    pub bssid: String,
    /// Signal strength in dBm (typical: -30 strong to -90 weak).
    pub signal_strength: i32,
    /// WiFi channel number.
    pub channel: u8,
    /// Timestamp of this sighting.
    pub timestamp: DateTime<Utc>,
    /// Whether the device was connected to this network (vs just scanning).
    pub connected: bool,
    /// Network category (home, work, public).
    pub category: NetworkCategory,
}

impl Artifact for WifiSighting {
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
                    "BSSID must be 17 chars (AA:BB:CC:DD:EE:FF), got len {}",
                    self.bssid.len()
                ),
            });
        }

        // Each BSSID octet must be 2 hex chars
        let parts: Vec<&str> = self.bssid.split(':').collect();
        if parts.len() != 6 {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!("BSSID must have 6 octets, got {}", parts.len()),
            });
        }

        if !(-100..=0).contains(&self.signal_strength) {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!(
                    "signal strength {} dBm out of range [-100, 0]",
                    self.signal_strength
                ),
            });
        }

        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

// ---------------------------------------------------------------------------
// WifiGenerator
// ---------------------------------------------------------------------------

/// Generates WiFi network sighting records following daily patterns.
///
/// Maintains persistent home and work SSIDs/BSSIDs across a session so
/// the user consistently connects to the same networks. Signal strength
/// varies to simulate entering and leaving range. Public networks are
/// generated with random BSSIDs each time.
pub struct WifiGenerator {
    /// Persistent home SSID for this persona.
    home_ssid: Option<String>,
    /// Persistent home BSSID.
    home_bssid: Option<String>,
    /// Home network channel.
    home_channel: Option<u8>,
    /// Persistent work SSID for this persona.
    work_ssid: Option<String>,
    /// Persistent work BSSID.
    work_bssid: Option<String>,
    /// Work network channel.
    work_channel: Option<u8>,
    /// Simulated signal approach/departure state for enter/leave effect.
    /// Positive = approaching (signal getting stronger), negative = departing.
    signal_trend: i32,
}

impl WifiGenerator {
    /// Create a new WiFi generator with no persistent networks.
    pub fn new() -> Self {
        Self {
            home_ssid: None,
            home_bssid: None,
            home_channel: None,
            work_ssid: None,
            work_bssid: None,
            work_channel: None,
            signal_trend: 0,
        }
    }

    /// Generate a random MAC address formatted as AA:BB:CC:DD:EE:FF.
    ///
    /// Sets the locally-administered bit (bit 1 of first octet) to mark
    /// this as a synthetic address.
    fn random_bssid(rng: &mut (impl RngCore + CryptoRng)) -> String {
        let octets: Vec<String> = (0..6)
            .map(|i| {
                let mut b = Uniform::new_inclusive(0u8, 255).sample(rng);
                if i == 0 {
                    // Set locally-administered bit, clear multicast bit
                    b = (b | 0x02) & 0xFE;
                }
                format!("{b:02X}")
            })
            .collect();
        octets.join(":")
    }

    /// Expand SSID template by replacing "XXXX" with random hex digits.
    fn expand_ssid_template(
        template: &str,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> String {
        if template.contains("XXXX") {
            let hex: String = (0..4)
                .map(|_| {
                    let nibble = Uniform::new_inclusive(0u8, 15).sample(rng);
                    format!("{nibble:X}")
                })
                .collect();
            template.replace("XXXX", &hex)
        } else {
            template.to_string()
        }
    }

    /// Pick a random channel (mix of 2.4 GHz and 5 GHz).
    fn random_channel(rng: &mut (impl RngCore + CryptoRng)) -> u8 {
        let roll = Uniform::new_inclusive(0u32, 99).sample(rng);
        if roll < 40 {
            // 2.4 GHz
            *CHANNELS_24GHZ
                .choose(rng)
                .unwrap_or(&1)
        } else {
            // 5 GHz
            *CHANNELS_5GHZ
                .choose(rng)
                .unwrap_or(&36)
        }
    }

    /// Determine network category from hour of day and user schedule.
    fn category_for_hour(hour: u32, profile: &UserProfile) -> NetworkCategory {
        let wake = profile.activity_schedule.wake_hour as u32;
        let sleep = profile.activity_schedule.sleep_hour as u32;
        let morning_commute_end = wake + 2;
        let work_end = if sleep > 5 { sleep - 5 } else { 17 };
        let evening_commute_end = work_end + 2;

        if hour < wake || hour >= sleep {
            NetworkCategory::Home
        } else if hour < morning_commute_end {
            NetworkCategory::Public
        } else if hour < work_end {
            NetworkCategory::Work
        } else if hour < evening_commute_end {
            NetworkCategory::Public
        } else {
            NetworkCategory::Home
        }
    }

    /// Signal strength with enter/leave variation.
    ///
    /// Base signal depends on category, then a trend modifier simulates
    /// approaching (stronger) or departing (weaker).
    fn signal_with_trend(
        cat: NetworkCategory,
        trend: i32,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> i32 {
        let (base_lo, base_hi) = match cat {
            NetworkCategory::Home => (-55, -30),
            NetworkCategory::Work => (-70, -40),
            NetworkCategory::Public => (-85, -55),
        };
        let base = Uniform::new_inclusive(base_lo, base_hi).sample(rng);
        // Apply trend: positive = entering range (stronger), negative = leaving
        let adjusted = base + trend;
        adjusted.clamp(-100, -10)
    }

    /// Initialize persistent home/work networks for this persona.
    ///
    /// Ensures consistent SSID, BSSID, and channel across a session.
    pub fn init_persistent_networks(
        &mut self,
        rng: &mut (impl RngCore + CryptoRng),
    ) {
        if self.home_ssid.is_none() {
            let template = HOME_SSID_TEMPLATES
                .choose(rng)
                .copied()
                .unwrap_or("HomeWiFi");
            self.home_ssid = Some(Self::expand_ssid_template(template, rng));
            self.home_bssid = Some(Self::random_bssid(rng));
            self.home_channel = Some(Self::random_channel(rng));
        }
        if self.work_ssid.is_none() {
            self.work_ssid = WORK_SSIDS
                .choose(rng)
                .map(|s| (*s).to_string());
            self.work_bssid = Some(Self::random_bssid(rng));
            self.work_channel = Some(Self::random_channel(rng));
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

        let (ssid, bssid, channel) = match cat {
            NetworkCategory::Home => {
                let ssid = self
                    .home_ssid
                    .clone()
                    .unwrap_or_else(|| {
                        let tmpl = HOME_SSID_TEMPLATES
                            .choose(rng)
                            .copied()
                            .unwrap_or("HomeWiFi");
                        Self::expand_ssid_template(tmpl, rng)
                    });
                let bssid = self
                    .home_bssid
                    .clone()
                    .unwrap_or_else(|| Self::random_bssid(rng));
                let channel = self.home_channel.unwrap_or_else(|| Self::random_channel(rng));
                (ssid, bssid, channel)
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
                let channel = self.work_channel.unwrap_or_else(|| Self::random_channel(rng));
                (ssid, bssid, channel)
            }
            NetworkCategory::Public => {
                let ssid = PUBLIC_SSIDS
                    .choose(rng)
                    .map(|s| (*s).to_string())
                    .unwrap_or_else(|| "FreeWiFi".to_string());
                let bssid = Self::random_bssid(rng);
                let channel = Self::random_channel(rng);
                (ssid, bssid, channel)
            }
        };

        let signal = Self::signal_with_trend(cat, self.signal_trend, rng);

        // Connection probability: home/work usually connected, public sometimes
        let connected = match cat {
            NetworkCategory::Home | NetworkCategory::Work => {
                Uniform::new_inclusive(0u32, 99).sample(rng) < 90
            }
            NetworkCategory::Public => {
                Uniform::new_inclusive(0u32, 99).sample(rng) < 40
            }
        };

        // Timestamp with small jitter
        let jitter_secs = Uniform::new_inclusive(0i64, 300).sample(rng);
        let timestamp = context.now - Duration::seconds(jitter_secs);

        let meta = ArtifactMetadata::new(
            DataCategory::Location,
            timestamp,
            timestamp,
            ssid.len() as u64 + bssid.len() as u64 + 96,
        )?;

        let sighting = WifiSighting {
            meta,
            ssid,
            bssid,
            signal_strength: signal,
            channel,
            timestamp,
            connected,
            category: cat,
        };

        sighting.validate_plausibility()?;
        Ok(Box::new(sighting))
    }

    fn category(&self) -> DataCategory {
        DataCategory::Location
    }

    fn forensic_weight(&self) -> u32 {
        80
    }

    fn resource_cost(&self) -> ResourceCost {
        ResourceCost {
            cpu_us: 20,
            disk_bytes: 192,
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
    fn test_basic_wifi_generation() {
        let wifi = WifiGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let artifact = wifi.generate(&profile, &ctx, &mut rng);
        assert!(artifact.is_ok());
        let artifact = artifact.expect("checked");
        let bytes = artifact.to_bytes().expect("serialize");
        let sighting: WifiSighting = serde_json::from_slice(&bytes).expect("deserialize");

        assert!(!sighting.ssid.is_empty());
        assert_eq!(sighting.bssid.len(), 17);
        assert!((-100..=0).contains(&sighting.signal_strength));
        assert!(sighting.channel > 0);
    }

    #[test]
    fn test_bssid_format_hex_octets() {
        let wifi = WifiGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(99);

        for _ in 0..100 {
            let artifact = wifi.generate(&profile, &ctx, &mut rng).expect("generate");
            let bytes = artifact.to_bytes().expect("to_bytes");
            let sighting: WifiSighting = serde_json::from_slice(&bytes).expect("deser");

            let parts: Vec<&str> = sighting.bssid.split(':').collect();
            assert_eq!(parts.len(), 6, "BSSID must have 6 octets: {}", sighting.bssid);
            for part in &parts {
                assert_eq!(part.len(), 2, "each octet 2 hex chars: {}", sighting.bssid);
                assert!(
                    u8::from_str_radix(part, 16).is_ok(),
                    "octet must be valid hex: {part}",
                );
            }
        }
    }

    #[test]
    fn test_signal_strength_always_in_range() {
        let wifi = WifiGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(77);

        for i in 0..500 {
            let artifact = wifi.generate(&profile, &ctx, &mut rng).expect("generate");
            let bytes = artifact.to_bytes().expect("to_bytes");
            let sighting: WifiSighting = serde_json::from_slice(&bytes).expect("deser");

            assert!(
                (-100..=0).contains(&sighting.signal_strength),
                "entry {i}: signal {} dBm out of range",
                sighting.signal_strength,
            );
        }
    }

    #[test]
    fn test_daily_pattern_categories() {
        let profile = test_profile(); // wake=7, sleep=23

        assert_eq!(
            WifiGenerator::category_for_hour(3, &profile),
            NetworkCategory::Home,
        );
        assert_eq!(
            WifiGenerator::category_for_hour(8, &profile),
            NetworkCategory::Public,
        );
        assert_eq!(
            WifiGenerator::category_for_hour(12, &profile),
            NetworkCategory::Work,
        );
        assert_eq!(
            WifiGenerator::category_for_hour(19, &profile),
            NetworkCategory::Public,
        );
        assert_eq!(
            WifiGenerator::category_for_hour(21, &profile),
            NetworkCategory::Home,
        );
    }

    #[test]
    fn test_ssid_template_expansion() {
        let mut rng = seeded_rng(42);

        let expanded = WifiGenerator::expand_ssid_template("HOME-XXXX", &mut rng);
        assert!(expanded.starts_with("HOME-"));
        assert_eq!(expanded.len(), 9); // "HOME-" + 4 hex chars
        assert!(!expanded.contains("XXXX"));

        // Without XXXX template
        let plain = WifiGenerator::expand_ssid_template("xfinitywifi", &mut rng);
        assert_eq!(plain, "xfinitywifi");
    }

    #[test]
    fn test_persistent_networks_consistent() {
        let mut wifi = WifiGenerator::new();
        let mut rng = seeded_rng(42);

        wifi.init_persistent_networks(&mut rng);

        let home1 = wifi.home_ssid.clone();
        let home_bssid1 = wifi.home_bssid.clone();

        // Re-init should not change already-set values
        wifi.init_persistent_networks(&mut rng);

        assert_eq!(wifi.home_ssid, home1);
        assert_eq!(wifi.home_bssid, home_bssid1);
    }

    #[test]
    fn test_channel_is_valid_wifi_channel() {
        let mut rng = seeded_rng(55);

        let all_valid: Vec<u8> = CHANNELS_24GHZ
            .iter()
            .chain(CHANNELS_5GHZ.iter())
            .copied()
            .collect();

        for _ in 0..200 {
            let ch = WifiGenerator::random_channel(&mut rng);
            assert!(
                all_valid.contains(&ch),
                "channel {ch} is not a valid WiFi channel",
            );
        }
    }

    #[test]
    fn test_serialization_roundtrip() {
        let wifi = WifiGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let artifact = wifi.generate(&profile, &ctx, &mut rng).expect("generate");
        let bytes = artifact.to_bytes().expect("to_bytes");
        let sighting: WifiSighting = serde_json::from_slice(&bytes).expect("deser");

        let bytes2 = serde_json::to_vec(&sighting).expect("re-serialize");
        let sighting2: WifiSighting = serde_json::from_slice(&bytes2).expect("re-deser");

        assert_eq!(sighting.ssid, sighting2.ssid);
        assert_eq!(sighting.bssid, sighting2.bssid);
        assert_eq!(sighting.signal_strength, sighting2.signal_strength);
        assert_eq!(sighting.channel, sighting2.channel);
        assert_eq!(sighting.connected, sighting2.connected);
    }

    #[test]
    fn test_connected_field_varies() {
        let wifi = WifiGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(88);

        let mut saw_connected = false;
        let mut saw_not_connected = false;

        for _ in 0..200 {
            let artifact = wifi.generate(&profile, &ctx, &mut rng).expect("generate");
            let bytes = artifact.to_bytes().expect("to_bytes");
            let sighting: WifiSighting = serde_json::from_slice(&bytes).expect("deser");

            if sighting.connected {
                saw_connected = true;
            } else {
                saw_not_connected = true;
            }

            if saw_connected && saw_not_connected {
                break;
            }
        }

        assert!(
            saw_connected && saw_not_connected,
            "should see both connected=true and connected=false",
        );
    }
}
