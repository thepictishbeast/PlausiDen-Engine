//! User behavioral profiles for generating plausible data.
//!
//! A [`UserProfile`] captures demographic, behavioral, and device characteristics
//! that shape what synthetic data looks like. A journalist's browsing history
//! looks different from a teenager's. Profiles ensure generated artifacts match
//! the persona's expected patterns.

use serde::{Deserialize, Serialize};

/// Controls how aggressively data is generated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RiskLevel {
    /// Background noise — blends in, minimal resource usage.
    Low,
    /// Noticeable volume — covers most forensic targets.
    Medium,
    /// Aggressive generation — targets all data categories.
    High,
    /// Flood all channels — high resource usage, for imminent threat scenarios.
    Maximum,
}

impl RiskLevel {
    /// Multiplier applied to base generation rates.
    pub fn rate_multiplier(&self) -> f64 {
        match self {
            Self::Low => 0.25,
            Self::Medium => 1.0,
            Self::High => 3.0,
            Self::Maximum => 10.0,
        }
    }
}

impl Default for RiskLevel {
    fn default() -> Self {
        Self::Medium
    }
}

/// Broad demographic category affecting data patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DemographicProfile {
    /// Age range (affects content preferences, platforms used).
    pub age_range: (u8, u8),
    /// Primary language code (e.g., "en", "es", "zh").
    pub language: String,
    /// Country code (ISO 3166-1 alpha-2).
    pub country: String,
    /// Occupation category (affects browsing/app patterns).
    pub occupation: OccupationCategory,
}

impl Default for DemographicProfile {
    fn default() -> Self {
        Self {
            age_range: (25, 45),
            language: "en".to_string(),
            country: "US".to_string(),
            occupation: OccupationCategory::General,
        }
    }
}

/// Occupation categories that influence data generation patterns.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum OccupationCategory {
    General,
    Student,
    Academic,
    Journalist,
    LegalProfessional,
    TechWorker,
    HealthcareWorker,
    TradesWorker,
    Retired,
}

/// Device characteristics affecting what data can be generated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceProfile {
    /// Operating system family.
    pub os: OsFamily,
    /// Available browsers on this device.
    pub browsers: Vec<BrowserType>,
    /// Whether the device has GPS capability.
    pub has_gps: bool,
    /// Whether the device has cellular connectivity.
    pub has_cellular: bool,
    /// Available storage in bytes.
    pub available_storage_bytes: u64,
}

impl Default for DeviceProfile {
    fn default() -> Self {
        Self {
            os: OsFamily::Linux,
            browsers: vec![BrowserType::Firefox, BrowserType::Chrome],
            has_gps: false,
            has_cellular: false,
            available_storage_bytes: 10 * 1024 * 1024 * 1024, // 10 GiB
        }
    }
}

/// Operating system families.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsFamily {
    Linux,
    MacOS,
    Windows,
    Android,
    IOS,
}

/// Browser types for history/cookie generation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BrowserType {
    Firefox,
    Chrome,
    Safari,
    Edge,
    Brave,
}

/// When the user is typically active.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActivitySchedule {
    /// Hour of day when activity typically starts (0-23).
    pub wake_hour: u8,
    /// Hour of day when activity typically ends (0-23).
    pub sleep_hour: u8,
    /// Days of week with higher activity (0=Mon, 6=Sun).
    pub active_days: Vec<u8>,
    /// Timezone offset from UTC in hours.
    pub timezone_offset_hours: i8,
}

impl Default for ActivitySchedule {
    fn default() -> Self {
        Self {
            wake_hour: 7,
            sleep_hour: 23,
            active_days: vec![0, 1, 2, 3, 4, 5, 6],
            timezone_offset_hours: -5, // EST
        }
    }
}

/// Locale settings for localized data generation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Locale {
    /// Language tag (e.g., "en-US").
    pub language_tag: String,
    /// Date format preference.
    pub date_format: String,
    /// Currency code (e.g., "USD").
    pub currency: String,
}

impl Default for Locale {
    fn default() -> Self {
        Self {
            language_tag: "en-US".to_string(),
            date_format: "MM/DD/YYYY".to_string(),
            currency: "USD".to_string(),
        }
    }
}

/// Interest categories that drive browsing and activity patterns.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum InterestCategory {
    News,
    Technology,
    Sports,
    Entertainment,
    Shopping,
    Social,
    Academic,
    Finance,
    Health,
    Travel,
    Food,
    Gaming,
    Music,
    Government,
    Legal,
    Weather,
    Reference,
    Documentation,
}

/// Complete user behavioral profile for generating plausible data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserProfile {
    /// Demographic category (affects browsing patterns, app usage).
    pub demographic: DemographicProfile,
    /// Device type and capabilities.
    pub device: DeviceProfile,
    /// Typical usage hours.
    pub activity_schedule: ActivitySchedule,
    /// Language and locale.
    pub locale: Locale,
    /// Browsing interests (categories, not specific URLs).
    pub interests: Vec<InterestCategory>,
    /// Risk level — higher risk = more aggressive generation.
    pub risk_level: RiskLevel,
}

impl Default for UserProfile {
    fn default() -> Self {
        Self {
            demographic: DemographicProfile::default(),
            device: DeviceProfile::default(),
            activity_schedule: ActivitySchedule::default(),
            locale: Locale::default(),
            interests: vec![
                InterestCategory::News,
                InterestCategory::Technology,
                InterestCategory::Entertainment,
                InterestCategory::Shopping,
            ],
            risk_level: RiskLevel::default(),
        }
    }
}

/// Builder for constructing [`UserProfile`] instances.
pub struct UserProfileBuilder {
    profile: UserProfile,
}

impl UserProfileBuilder {
    /// Start building a new profile with defaults.
    pub fn new() -> Self {
        Self {
            profile: UserProfile::default(),
        }
    }

    /// Set the demographic profile.
    pub fn demographic(mut self, demographic: DemographicProfile) -> Self {
        self.profile.demographic = demographic;
        self
    }

    /// Set the device profile.
    pub fn device(mut self, device: DeviceProfile) -> Self {
        self.profile.device = device;
        self
    }

    /// Set the activity schedule.
    pub fn activity_schedule(mut self, schedule: ActivitySchedule) -> Self {
        self.profile.activity_schedule = schedule;
        self
    }

    /// Set the locale.
    pub fn locale(mut self, locale: Locale) -> Self {
        self.profile.locale = locale;
        self
    }

    /// Set the interest categories.
    pub fn interests(mut self, interests: Vec<InterestCategory>) -> Self {
        self.profile.interests = interests;
        self
    }

    /// Set the risk level.
    pub fn risk_level(mut self, level: RiskLevel) -> Self {
        self.profile.risk_level = level;
        self
    }

    /// Build the profile.
    pub fn build(self) -> UserProfile {
        self.profile
    }
}

impl Default for UserProfileBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // --- Property-based tests ---

    use proptest::prelude::*;

    fn arb_risk_level() -> impl Strategy<Value = RiskLevel> {
        prop_oneof![
            Just(RiskLevel::Low),
            Just(RiskLevel::Medium),
            Just(RiskLevel::High),
            Just(RiskLevel::Maximum),
        ]
    }

    fn arb_occupation() -> impl Strategy<Value = OccupationCategory> {
        prop_oneof![
            Just(OccupationCategory::General),
            Just(OccupationCategory::Student),
            Just(OccupationCategory::Academic),
            Just(OccupationCategory::Journalist),
            Just(OccupationCategory::LegalProfessional),
            Just(OccupationCategory::TechWorker),
            Just(OccupationCategory::HealthcareWorker),
            Just(OccupationCategory::TradesWorker),
            Just(OccupationCategory::Retired),
        ]
    }

    fn arb_os_family() -> impl Strategy<Value = OsFamily> {
        prop_oneof![
            Just(OsFamily::Linux),
            Just(OsFamily::MacOS),
            Just(OsFamily::Windows),
            Just(OsFamily::Android),
            Just(OsFamily::IOS),
        ]
    }

    fn arb_browser() -> impl Strategy<Value = BrowserType> {
        prop_oneof![
            Just(BrowserType::Firefox),
            Just(BrowserType::Chrome),
            Just(BrowserType::Safari),
            Just(BrowserType::Edge),
            Just(BrowserType::Brave),
        ]
    }

    fn arb_interest() -> impl Strategy<Value = InterestCategory> {
        prop_oneof![
            Just(InterestCategory::News),
            Just(InterestCategory::Technology),
            Just(InterestCategory::Sports),
            Just(InterestCategory::Entertainment),
            Just(InterestCategory::Shopping),
            Just(InterestCategory::Social),
            Just(InterestCategory::Academic),
            Just(InterestCategory::Finance),
            Just(InterestCategory::Health),
            Just(InterestCategory::Travel),
            Just(InterestCategory::Food),
            Just(InterestCategory::Gaming),
            Just(InterestCategory::Music),
            Just(InterestCategory::Government),
            Just(InterestCategory::Legal),
            Just(InterestCategory::Weather),
            Just(InterestCategory::Reference),
            Just(InterestCategory::Documentation),
        ]
    }

    fn arb_demographic() -> impl Strategy<Value = DemographicProfile> {
        (
            (1u8..100, 1u8..100),
            "[a-z]{2}",
            "[A-Z]{2}",
            arb_occupation(),
        )
            .prop_map(
                |(age_range, language, country, occupation)| DemographicProfile {
                    age_range,
                    language,
                    country,
                    occupation,
                },
            )
    }

    fn arb_device() -> impl Strategy<Value = DeviceProfile> {
        (
            arb_os_family(),
            prop::collection::vec(arb_browser(), 1..4),
            any::<bool>(),
            any::<bool>(),
        )
            .prop_map(|(os, browsers, has_gps, has_cellular)| DeviceProfile {
                os,
                browsers,
                has_gps,
                has_cellular,
                available_storage_bytes: 10 * 1024 * 1024 * 1024,
            })
    }

    fn arb_activity() -> impl Strategy<Value = ActivitySchedule> {
        (
            0u8..24,
            0u8..24,
            prop::collection::vec(0u8..7, 1..8),
            -12i8..=12,
        )
            .prop_map(|(wake, sleep, active_days, tz_offset)| ActivitySchedule {
                wake_hour: wake,
                sleep_hour: sleep,
                active_days,
                timezone_offset_hours: tz_offset,
            })
    }

    fn arb_user_profile() -> impl Strategy<Value = UserProfile> {
        (
            arb_demographic(),
            arb_device(),
            arb_activity(),
            prop::collection::vec(arb_interest(), 0..6),
            arb_risk_level(),
        )
            .prop_map(
                |(demographic, device, activity_schedule, interests, risk_level)| UserProfile {
                    demographic,
                    device,
                    activity_schedule,
                    locale: Locale::default(),
                    interests,
                    risk_level,
                },
            )
    }

    proptest! {
        #[test]
        fn prop_user_profile_serde_roundtrip(profile in arb_user_profile()) {
            let json = serde_json::to_string(&profile).expect("serialize");
            let roundtripped: UserProfile = serde_json::from_str(&json).expect("deserialize");

            // Verify key fields survived the roundtrip
            prop_assert_eq!(&profile.demographic.language, &roundtripped.demographic.language);
            prop_assert_eq!(&profile.demographic.country, &roundtripped.demographic.country);
            prop_assert_eq!(profile.demographic.age_range, roundtripped.demographic.age_range);
            prop_assert_eq!(profile.risk_level, roundtripped.risk_level);
            prop_assert_eq!(profile.interests.len(), roundtripped.interests.len());
            prop_assert_eq!(profile.device.browsers.len(), roundtripped.device.browsers.len());
            prop_assert_eq!(profile.activity_schedule.wake_hour, roundtripped.activity_schedule.wake_hour);
            prop_assert_eq!(profile.activity_schedule.sleep_hour, roundtripped.activity_schedule.sleep_hour);
        }
    }

    #[test]
    fn test_risk_level_rate_multiplier_strictly_ordered() {
        let low = RiskLevel::Low.rate_multiplier();
        let medium = RiskLevel::Medium.rate_multiplier();
        let high = RiskLevel::High.rate_multiplier();
        let maximum = RiskLevel::Maximum.rate_multiplier();

        assert!(low < medium, "Low ({low}) must be < Medium ({medium})");
        assert!(medium < high, "Medium ({medium}) must be < High ({high})");
        assert!(
            high < maximum,
            "High ({high}) must be < Maximum ({maximum})"
        );
    }

    #[test]
    fn test_empty_interests_is_valid_profile() {
        let profile = UserProfileBuilder::new().interests(vec![]).build();
        assert!(profile.interests.is_empty());
        // Should still serialize cleanly
        let json = serde_json::to_string(&profile).unwrap();
        let rt: UserProfile = serde_json::from_str(&json).unwrap();
        assert!(rt.interests.is_empty());
    }

    #[test]
    fn test_extreme_risk_level_maximum() {
        let profile = UserProfileBuilder::new()
            .risk_level(RiskLevel::Maximum)
            .build();
        assert_eq!(profile.risk_level, RiskLevel::Maximum);
        assert_eq!(profile.risk_level.rate_multiplier(), 10.0);
    }

    #[test]
    fn test_builder_defaults_match_direct_default() {
        let built = UserProfileBuilder::new().build();
        let direct = UserProfile::default();

        assert_eq!(built.risk_level, direct.risk_level);
        assert_eq!(built.interests.len(), direct.interests.len());
        assert_eq!(built.demographic.language, direct.demographic.language);
    }
}
