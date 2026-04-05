//! Form autofill data generation -- names, addresses, emails, phone numbers, credit cards.
//!
//! Generates saved form autofill entries that browsers remember across sessions.
//! Each entry represents a field-value pair associated with a specific form URL,
//! mimicking the way browsers like Chrome and Firefox store autofill suggestions.

use crate::url_corpus;
use chrono::{DateTime, Duration, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext, ResourceCost,
};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use serde::Serialize;

/// A single browser autofill entry representing a saved form field.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct AutofillEntry {
    /// Artifact metadata.
    pub meta: ArtifactMetadata,
    /// HTML form field name (e.g., "first_name", "email", "cc-number").
    pub field_name: String,
    /// The saved value for this field.
    pub field_value: String,
    /// URL of the form where this value was saved.
    pub form_url: String,
    /// Number of times this autofill entry has been used.
    pub usage_count: u32,
    /// When this entry was first saved.
    pub created_at: DateTime<Utc>,
    /// When this entry was last used to fill a form.
    pub last_used: DateTime<Utc>,
}

impl Artifact for AutofillEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;

        if self.field_name.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty field name".to_string(),
            });
        }

        if self.field_value.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty field value".to_string(),
            });
        }

        if self.form_url.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty form URL".to_string(),
            });
        }

        if self.usage_count == 0 {
            return Err(EngineError::ImplausibleArtifact {
                reason: "usage count is zero".to_string(),
            });
        }

        if self.last_used < self.created_at {
            return Err(EngineError::ImplausibleArtifact {
                reason: "last_used before created_at".to_string(),
            });
        }

        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

/// Common first names for autofill generation.
const FIRST_NAMES: &[&str] = &[
    "James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda",
    "David", "Elizabeth", "William", "Barbara", "Richard", "Susan", "Joseph", "Jessica",
    "Thomas", "Sarah", "Christopher", "Karen", "Daniel", "Lisa", "Matthew", "Nancy",
    "Anthony", "Betty", "Mark", "Margaret", "Donald", "Sandra", "Steven", "Ashley",
];

/// Common last names for autofill generation.
const LAST_NAMES: &[&str] = &[
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
    "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
    "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker",
];

/// US street names for address generation.
const STREET_NAMES: &[&str] = &[
    "Main St", "Oak Ave", "Maple Dr", "Cedar Ln", "Elm St", "Park Ave",
    "Washington Blvd", "Pine St", "Lake Rd", "Hill Dr", "Church St",
    "Broad St", "Walnut St", "Chestnut Ave", "Spring St", "Highland Ave",
    "Meadow Ln", "Forest Dr", "River Rd", "Sunset Blvd",
];

/// US cities with state abbreviation and zip code prefix.
const US_LOCATIONS: &[(&str, &str, &str)] = &[
    ("New York", "NY", "100"),
    ("Los Angeles", "CA", "900"),
    ("Chicago", "IL", "606"),
    ("Houston", "TX", "770"),
    ("Phoenix", "AZ", "850"),
    ("Philadelphia", "PA", "191"),
    ("San Antonio", "TX", "782"),
    ("San Diego", "CA", "921"),
    ("Dallas", "TX", "752"),
    ("Austin", "TX", "787"),
    ("Portland", "OR", "972"),
    ("Denver", "CO", "802"),
    ("Seattle", "WA", "981"),
    ("Boston", "MA", "021"),
    ("Nashville", "TN", "372"),
    ("Atlanta", "GA", "303"),
    ("Miami", "FL", "331"),
    ("Minneapolis", "MN", "554"),
];

/// Test credit card numbers (Luhn-valid test numbers from payment processors).
const TEST_CARD_NUMBERS: &[&str] = &[
    "4111111111111111", // Visa test
    "4012888888881881", // Visa test
    "5555555555554444", // Mastercard test
    "5105105105105100", // Mastercard test
    "378282246310005",  // Amex test
    "371449635398431",  // Amex test
    "6011111111111117", // Discover test
    "6011000990139424", // Discover test
];

/// Email domains for address generation.
const EMAIL_DOMAINS: &[&str] = &[
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
    "protonmail.com", "aol.com", "mail.com",
];

/// Autofill field types with their HTML field name and a tag for generation logic.
#[derive(Debug, Clone, Copy)]
enum FieldType {
    FirstName,
    LastName,
    Email,
    Phone,
    StreetAddress,
    City,
    State,
    ZipCode,
    CreditCard,
}

/// All field types in a weighted distribution for realistic frequency.
const FIELD_TYPES: &[(FieldType, u32)] = &[
    (FieldType::FirstName, 15),
    (FieldType::LastName, 15),
    (FieldType::Email, 20),
    (FieldType::Phone, 10),
    (FieldType::StreetAddress, 10),
    (FieldType::City, 8),
    (FieldType::State, 7),
    (FieldType::ZipCode, 8),
    (FieldType::CreditCard, 7),
];

/// Returns the HTML field name browsers typically use for each field type.
fn field_name_for_type(ft: FieldType) -> &'static str {
    match ft {
        FieldType::FirstName => "first_name",
        FieldType::LastName => "last_name",
        FieldType::Email => "email",
        FieldType::Phone => "phone",
        FieldType::StreetAddress => "address",
        FieldType::City => "city",
        FieldType::State => "state",
        FieldType::ZipCode => "zip",
        FieldType::CreditCard => "cc-number",
    }
}

/// Generates browser autofill entries -- saved form data.
pub struct AutofillGenerator;

impl AutofillGenerator {
    /// Create a new autofill generator.
    pub fn new() -> Self {
        Self
    }

    /// Pick a weighted-random field type.
    fn choose_field_type(rng: &mut (impl RngCore + CryptoRng)) -> FieldType {
        let total_weight: u32 = FIELD_TYPES.iter().map(|(_, w)| w).sum();
        let roll = Uniform::new(0u32, total_weight).sample(rng);
        let mut cumulative = 0u32;
        for (ft, weight) in FIELD_TYPES {
            cumulative += weight;
            if roll < cumulative {
                return *ft;
            }
        }
        // Fallback (should not be reached)
        FieldType::Email
    }

    /// Generate a plausible value for the given field type.
    fn generate_field_value(
        ft: FieldType,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> String {
        match ft {
            FieldType::FirstName => {
                FIRST_NAMES
                    .choose(rng)
                    .unwrap_or(&"John")
                    .to_string()
            }
            FieldType::LastName => {
                LAST_NAMES
                    .choose(rng)
                    .unwrap_or(&"Smith")
                    .to_string()
            }
            FieldType::Email => {
                let first = FIRST_NAMES
                    .choose(rng)
                    .unwrap_or(&"user")
                    .to_lowercase();
                let last = LAST_NAMES
                    .choose(rng)
                    .unwrap_or(&"name")
                    .to_lowercase();
                let domain = EMAIL_DOMAINS.choose(rng).unwrap_or(&"gmail.com");
                let suffix = Uniform::new_inclusive(0u32, 99).sample(rng);
                if suffix > 60 {
                    format!("{first}.{last}@{domain}")
                } else {
                    format!("{first}.{last}{suffix}@{domain}")
                }
            }
            FieldType::Phone => {
                let area = Uniform::new_inclusive(201u32, 989).sample(rng);
                let exchange = Uniform::new_inclusive(200u32, 999).sample(rng);
                let subscriber = Uniform::new_inclusive(1000u32, 9999).sample(rng);
                format!("({area}) {exchange}-{subscriber}")
            }
            FieldType::StreetAddress => {
                let number = Uniform::new_inclusive(100u32, 9999).sample(rng);
                let street = STREET_NAMES.choose(rng).unwrap_or(&"Main St");
                format!("{number} {street}")
            }
            FieldType::City => {
                let (city, _, _) = US_LOCATIONS.choose(rng).unwrap_or(&("New York", "NY", "100"));
                city.to_string()
            }
            FieldType::State => {
                let (_, state, _) = US_LOCATIONS.choose(rng).unwrap_or(&("New York", "NY", "100"));
                state.to_string()
            }
            FieldType::ZipCode => {
                let (_, _, prefix) =
                    US_LOCATIONS.choose(rng).unwrap_or(&("New York", "NY", "100"));
                let suffix = Uniform::new_inclusive(10u32, 99).sample(rng);
                format!("{prefix}{suffix}")
            }
            FieldType::CreditCard => {
                TEST_CARD_NUMBERS
                    .choose(rng)
                    .unwrap_or(&"4111111111111111")
                    .to_string()
            }
        }
    }

    /// Pick a plausible form URL from the user's interests.
    fn choose_form_url(
        profile: &UserProfile,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<String> {
        let category = profile
            .interests
            .choose(rng)
            .unwrap_or(&engine_core::profile::InterestCategory::Shopping);

        let urls = url_corpus::urls_for_category(category);
        let base_url = urls
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("no URLs for category".to_string()))?;

        // Autofill typically targets form pages
        let form_paths = [
            "/checkout", "/login", "/register", "/signup", "/account",
            "/contact", "/order", "/payment", "/profile", "/settings",
        ];
        let path = form_paths.choose(rng).unwrap_or(&"/login");
        Ok(format!("{base_url}{path}"))
    }
}

impl Default for AutofillGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for AutofillGenerator {
    fn generate(
        &self,
        profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        let field_type = Self::choose_field_type(rng);
        let field_name = field_name_for_type(field_type).to_string();
        let field_value = Self::generate_field_value(field_type, rng);
        let form_url = Self::choose_form_url(profile, rng)?;

        // Autofill entries are created some time in the past
        let age_secs = Uniform::new_inclusive(60i64, 86400 * 90).sample(rng);
        let created_at = context.now - Duration::seconds(age_secs);

        // Last used between created_at and now
        let used_offset = Uniform::new_inclusive(0i64, age_secs).sample(rng);
        let last_used = created_at + Duration::seconds(used_offset);

        // Usage count: correlated with age -- older entries used more
        let days_old = (age_secs / 86400).max(1);
        let usage_count = Uniform::new_inclusive(1u32, (days_old as u32).max(1).min(50))
            .sample(rng);

        let size_estimate = (field_name.len() + field_value.len() + form_url.len()) as u64 + 128;

        let meta = ArtifactMetadata::new(
            DataCategory::BrowserActivity,
            created_at,
            last_used,
            size_estimate,
        )?;

        let entry = AutofillEntry {
            meta,
            field_name,
            field_value,
            form_url,
            usage_count,
            created_at,
            last_used,
        };

        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory {
        DataCategory::BrowserActivity
    }

    fn forensic_weight(&self) -> u32 {
        75 // Autofill data reveals personal details and form submission patterns
    }

    fn resource_cost(&self) -> ResourceCost {
        ResourceCost {
            cpu_us: 30,
            disk_bytes: 256,
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
    fn test_autofill_entry_has_valid_fields() {
        let gtor = AutofillGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let artifact = gtor.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: AutofillEntry = serde_json::from_slice(&bytes).unwrap();

        assert!(!entry.field_name.is_empty(), "field_name must not be empty");
        assert!(!entry.field_value.is_empty(), "field_value must not be empty");
        assert!(
            entry.form_url.starts_with("http"),
            "form_url must start with http: {}",
            entry.form_url,
        );
        assert!(entry.usage_count >= 1, "usage_count must be at least 1");
    }

    #[test]
    fn test_autofill_timestamps_are_plausible() {
        let gtor = AutofillGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(99);

        let artifact = gtor.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: AutofillEntry = serde_json::from_slice(&bytes).unwrap();

        assert!(
            entry.last_used >= entry.created_at,
            "last_used ({}) must be >= created_at ({})",
            entry.last_used,
            entry.created_at,
        );
        assert!(
            entry.created_at <= Utc::now() + Duration::seconds(1),
            "created_at should be in the past or very near present",
        );
    }

    #[test]
    fn test_autofill_serialization_roundtrip() {
        let gtor = AutofillGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(7);

        let artifact = gtor.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: AutofillEntry = serde_json::from_slice(&bytes).unwrap();

        // Re-serialize and compare
        let bytes2 = serde_json::to_vec(&entry).unwrap();
        let entry2: AutofillEntry = serde_json::from_slice(&bytes2).unwrap();

        assert_eq!(entry.field_name, entry2.field_name);
        assert_eq!(entry.field_value, entry2.field_value);
        assert_eq!(entry.form_url, entry2.form_url);
        assert_eq!(entry.usage_count, entry2.usage_count);
    }

    #[test]
    fn test_all_field_types_generated() {
        let gtor = AutofillGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();

        let mut seen_fields = std::collections::HashSet::new();
        for seed in 0..500u64 {
            let mut rng = seeded_rng(seed);
            let artifact = gtor.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: AutofillEntry = serde_json::from_slice(&bytes).unwrap();
            seen_fields.insert(entry.field_name.clone());
        }

        let expected = [
            "first_name", "last_name", "email", "phone", "address",
            "city", "state", "zip", "cc-number",
        ];
        for field in &expected {
            assert!(
                seen_fields.contains(*field),
                "field type '{field}' was never generated in 500 entries",
            );
        }
    }

    #[test]
    fn test_500_entries_all_valid() {
        let gtor = AutofillGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();

        for seed in 0..500u64 {
            let mut rng = seeded_rng(seed);
            let artifact = gtor.generate(&profile, &ctx, &mut rng).unwrap();
            artifact.validate_plausibility().unwrap_or_else(|e| {
                panic!("autofill entry {seed} failed plausibility: {e}");
            });
            let bytes = artifact.to_bytes().unwrap();
            let entry: AutofillEntry = serde_json::from_slice(&bytes).unwrap();

            assert!(!entry.field_name.is_empty(), "seed {seed}: empty field_name");
            assert!(!entry.field_value.is_empty(), "seed {seed}: empty field_value");
            assert!(
                entry.form_url.starts_with("http"),
                "seed {seed}: form_url does not start with http: {}",
                entry.form_url,
            );
            assert!(entry.usage_count >= 1, "seed {seed}: zero usage_count");
            assert!(
                entry.last_used >= entry.created_at,
                "seed {seed}: last_used before created_at",
            );
        }
    }

    #[test]
    fn test_credit_card_numbers_are_test_only() {
        let gtor = AutofillGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();

        let test_cards: std::collections::HashSet<&str> =
            TEST_CARD_NUMBERS.iter().copied().collect();

        for seed in 0..500u64 {
            let mut rng = seeded_rng(seed);
            let artifact = gtor.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: AutofillEntry = serde_json::from_slice(&bytes).unwrap();

            if entry.field_name == "cc-number" {
                assert!(
                    test_cards.contains(entry.field_value.as_str()),
                    "seed {seed}: credit card '{}' is not a known test number",
                    entry.field_value,
                );
            }
        }
    }
}
