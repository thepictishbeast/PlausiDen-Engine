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
