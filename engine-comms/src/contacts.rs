//! Contact list generation with realistic names, phones, emails, and categories.
//!
//! Produces contact entries that mirror organic address books: a mix of family,
//! friends, work colleagues, and acquaintances with plausible creation dates
//! spread across months and years rather than clustered in a single session.

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

// ---- Name pools (English) ----

const FIRST_NAMES: &[&str] = &[
    "James", "Mary", "Robert", "Patricia", "John", "Jennifer", "Michael", "Linda",
    "David", "Elizabeth", "William", "Barbara", "Richard", "Susan", "Joseph", "Jessica",
    "Thomas", "Sarah", "Charles", "Karen", "Christopher", "Lisa", "Daniel", "Nancy",
    "Matthew", "Betty", "Anthony", "Margaret", "Mark", "Sandra", "Donald", "Ashley",
    "Steven", "Dorothy", "Andrew", "Kimberly", "Paul", "Emily", "Joshua", "Donna",
    "Kenneth", "Michelle", "Kevin", "Carol", "Brian", "Amanda", "George", "Melissa",
    "Timothy", "Deborah", "Ronald", "Stephanie", "Edward", "Rebecca", "Jason", "Sharon",
    "Jeffrey", "Laura", "Ryan", "Cynthia", "Jacob", "Kathleen", "Gary", "Amy",
    "Nicholas", "Angela", "Eric", "Shirley", "Jonathan", "Anna", "Stephen", "Brenda",
    "Larry", "Pamela", "Justin", "Emma", "Scott", "Nicole", "Brandon", "Helen",
    "Benjamin", "Samantha", "Samuel", "Katherine", "Raymond", "Christine", "Gregory", "Debra",
    "Frank", "Rachel", "Alexander", "Carolyn", "Patrick", "Janet", "Jack", "Catherine",
];

const LAST_NAMES: &[&str] = &[
    "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis",
    "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez", "Wilson", "Anderson",
    "Thomas", "Taylor", "Moore", "Jackson", "Martin", "Lee", "Perez", "Thompson",
    "White", "Harris", "Sanchez", "Clark", "Ramirez", "Lewis", "Robinson", "Walker",
    "Young", "Allen", "King", "Wright", "Scott", "Torres", "Nguyen", "Hill",
    "Flores", "Green", "Adams", "Nelson", "Baker", "Hall", "Rivera", "Campbell",
    "Mitchell", "Carter", "Roberts", "Gomez", "Phillips", "Evans", "Turner", "Diaz",
    "Parker", "Cruz", "Edwards", "Collins", "Reyes", "Stewart", "Morris", "Morales",
    "Murphy", "Cook", "Rogers", "Gutierrez", "Ortiz", "Morgan", "Cooper", "Peterson",
    "Bailey", "Reed", "Kelly", "Howard", "Ramos", "Kim", "Cox", "Ward",
    "Richardson", "Watson", "Brooks", "Chavez", "Wood", "James", "Bennett", "Gray",
    "Mendoza", "Ruiz", "Hughes", "Price", "Alvarez", "Castillo", "Sanders", "Patel",
];

const COMPANY_NAMES: &[&str] = &[
    "Apex Solutions", "Pinnacle Systems", "Meridian Group", "Summit Technologies",
    "Horizon Partners", "Vanguard Consulting", "Atlas Industries", "Beacon Health",
    "Catalyst Financial", "Crestview Associates", "Frontier Energy", "Keystone Media",
    "Lakeview Properties", "Nexus Engineering", "Oakridge Dynamics", "Pacific Trade Co",
    "Quantum Analytics", "Redwood Capital", "Silverline Logistics", "Trident Manufacturing",
    "Urban Design Lab", "Valley Medical Center", "Westfield Insurance", "Zenith Marketing",
    "Clearwater Tech", "Granite Construction", "Harbor Shipping", "Iron Bridge LLC",
    "Jade Software", "Maple Leaf Services", "Northern Trust Corp", "Olive Branch Legal",
];

const EMAIL_DOMAINS: &[&str] = &[
    "gmail.com", "yahoo.com", "outlook.com", "hotmail.com", "icloud.com",
    "protonmail.com", "aol.com", "mail.com", "zoho.com", "fastmail.com",
];

/// Relationship category for a contact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContactCategory {
    /// Family member.
    Family,
    /// Friend.
    Friend,
    /// Work colleague or professional contact.
    Work,
    /// Casual or infrequent contact.
    Acquaintance,
}

/// A single contact entry in an address book.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactEntry {
    /// Artifact metadata (timestamps, category, size).
    pub meta: ArtifactMetadata,
    /// Full display name.
    pub name: String,
    /// Phone number in locale-appropriate format.
    pub phone: String,
    /// Email address (derived from name).
    pub email: String,
    /// Company or organization (primarily for Work contacts).
    pub company: Option<String>,
    /// Relationship category.
    pub category: ContactCategory,
    /// When this contact was first saved.
    pub created_at: DateTime<Utc>,
    /// When the user last communicated with this contact.
    pub last_contacted: DateTime<Utc>,
    /// Total number of communications with this contact.
    pub contact_count: u32,
}

impl Artifact for ContactEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;

        if self.name.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "contact name is empty".to_string(),
            });
        }

        if !self.email.contains('@') {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!("email missing '@': {}", self.email),
            });
        }

        if self.phone.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "phone number is empty".to_string(),
            });
        }

        if self.last_contacted < self.created_at {
            return Err(EngineError::ImplausibleArtifact {
                reason: "last_contacted before created_at".to_string(),
            });
        }

        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

/// Generates realistic contact list entries.
pub struct ContactGenerator;

impl ContactGenerator {
    /// Create a new contact generator.
    pub fn new() -> Self {
        Self
    }

    /// Generate a US-format phone number: (xxx) xxx-xxxx.
    fn generate_phone(rng: &mut (impl RngCore + CryptoRng)) -> String {
        let area = Uniform::new_inclusive(200u16, 999).sample(rng);
        let prefix = Uniform::new_inclusive(200u16, 999).sample(rng);
        let line = Uniform::new_inclusive(0u16, 9999).sample(rng);
        format!("({area}) {prefix}-{line:04}")
    }

    /// Generate an email address from a first and last name.
    fn generate_email(
        first: &str,
        last: &str,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> String {
        let domain = EMAIL_DOMAINS
            .choose(rng)
            .unwrap_or(&"gmail.com");
        let first_lower = first.to_lowercase();
        let last_lower = last.to_lowercase();

        let style = Uniform::new_inclusive(0u32, 4).sample(rng);
        match style {
            0 => format!("{first_lower}.{last_lower}@{domain}"),
            1 => format!("{first_lower}{last_lower}@{domain}"),
            2 => {
                let digits = Uniform::new_inclusive(1u32, 99).sample(rng);
                format!("{first_lower}.{last_lower}{digits}@{domain}")
            }
            3 => {
                let digits = Uniform::new_inclusive(70u32, 99).sample(rng);
                format!("{first_lower}{digits}@{domain}")
            }
            _ => {
                let first_initial = &first_lower[..1];
                format!("{first_initial}{last_lower}@{domain}")
            }
        }
    }

    /// Choose a contact category with realistic distribution.
    fn choose_category(rng: &mut (impl RngCore + CryptoRng)) -> ContactCategory {
        let roll = Uniform::new_inclusive(0u32, 99).sample(rng);
        match roll {
            0..=14 => ContactCategory::Family,
            15..=39 => ContactCategory::Friend,
            40..=69 => ContactCategory::Work,
            _ => ContactCategory::Acquaintance,
        }
    }
}

impl Default for ContactGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for ContactGenerator {
    fn generate(
        &self,
        _profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        let first = FIRST_NAMES
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("empty first name pool".to_string()))?;
        let last = LAST_NAMES
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("empty last name pool".to_string()))?;
        let name = format!("{first} {last}");

        let phone = Self::generate_phone(rng);
        let email = Self::generate_email(first, last, rng);

        let category = Self::choose_category(rng);
        let company = if category == ContactCategory::Work {
            Some(
                COMPANY_NAMES
                    .choose(rng)
                    .unwrap_or(&"Acme Corp")
                    .to_string(),
            )
        } else {
            // ~10% chance a non-work contact also has a company listed
            if Uniform::new_inclusive(0u32, 9).sample(rng) == 0 {
                Some(
                    COMPANY_NAMES
                        .choose(rng)
                        .unwrap_or(&"Acme Corp")
                        .to_string(),
                )
            } else {
                None
            }
        };

        // Spread creation dates: 1 day to 3 years before context.now
        let max_age_days = 3 * 365;
        let age_days = Uniform::new_inclusive(1i64, max_age_days).sample(rng);
        let created_at = context.now - Duration::days(age_days);

        // last_contacted: between created_at and context.now
        let contact_window_secs = (context.now - created_at).num_seconds().max(1);
        let last_contacted_offset = Uniform::new_inclusive(0i64, contact_window_secs).sample(rng);
        let last_contacted = created_at + Duration::seconds(last_contacted_offset);

        // contact_count scales with age and category
        let base_count = match category {
            ContactCategory::Family => Uniform::new_inclusive(20u32, 500).sample(rng),
            ContactCategory::Friend => Uniform::new_inclusive(10u32, 300).sample(rng),
            ContactCategory::Work => Uniform::new_inclusive(5u32, 200).sample(rng),
            ContactCategory::Acquaintance => Uniform::new_inclusive(1u32, 30).sample(rng),
        };
        let contact_count = base_count;

        let size_estimate = name.len() as u64
            + phone.len() as u64
            + email.len() as u64
            + company.as_ref().map_or(0, |c| c.len()) as u64
            + 128;

        let meta = ArtifactMetadata::new(
            DataCategory::Communications,
            created_at,
            last_contacted,
            size_estimate,
        )?;

        let entry = ContactEntry {
            meta,
            name,
            phone,
            email,
            company,
            category,
            created_at,
            last_contacted,
            contact_count,
        };

        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory {
        DataCategory::Communications
    }

    fn forensic_weight(&self) -> u32 {
        90 // Communications are heavily relied upon in forensic analysis
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
    fn test_basic_contact_generation() {
        let cgen = ContactGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let artifact = cgen.generate(&profile, &ctx, &mut rng).unwrap();
        artifact.validate_plausibility().unwrap();

        let bytes = artifact.to_bytes().unwrap();
        let entry: ContactEntry = serde_json::from_slice(&bytes).unwrap();

        assert!(!entry.name.is_empty());
        assert!(entry.email.contains('@'));
        assert!(!entry.phone.is_empty());
        assert!(entry.contact_count >= 1);
        assert!(entry.created_at <= entry.last_contacted);
    }

    #[test]
    fn test_500_entries_stress() {
        let cgen = ContactGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(7);

        for i in 0..500u64 {
            let artifact = cgen.generate(&profile, &ctx, &mut rng).unwrap();
            artifact.validate_plausibility().unwrap_or_else(|e| {
                panic!("entry {i} failed plausibility: {e}");
            });
            let bytes = artifact.to_bytes().unwrap();
            let entry: ContactEntry = serde_json::from_slice(&bytes).unwrap();
            assert!(!entry.name.is_empty(), "entry {i}: empty name");
            assert!(entry.email.contains('@'), "entry {i}: email missing @");
        }
    }

    #[test]
    fn test_names_are_nonempty() {
        let cgen = ContactGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(100);

        for _ in 0..100 {
            let artifact = cgen.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: ContactEntry = serde_json::from_slice(&bytes).unwrap();
            assert!(!entry.name.is_empty(), "name must never be empty");
            // Name should contain a space (first + last)
            assert!(entry.name.contains(' '), "name should have first and last: {}", entry.name);
        }
    }

    #[test]
    fn test_phone_format_validation() {
        let cgen = ContactGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(55);

        let phone_re_pattern = |phone: &str| -> bool {
            // (xxx) xxx-xxxx
            let bytes = phone.as_bytes();
            if bytes.len() != 14 {
                return false;
            }
            bytes[0] == b'('
                && bytes[1..4].iter().all(|b| b.is_ascii_digit())
                && bytes[4] == b')'
                && bytes[5] == b' '
                && bytes[6..9].iter().all(|b| b.is_ascii_digit())
                && bytes[9] == b'-'
                && bytes[10..14].iter().all(|b| b.is_ascii_digit())
        };

        for i in 0..200 {
            let artifact = cgen.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: ContactEntry = serde_json::from_slice(&bytes).unwrap();
            assert!(
                phone_re_pattern(&entry.phone),
                "entry {i}: phone '{}' does not match (xxx) xxx-xxxx",
                entry.phone
            );
        }
    }

    #[test]
    fn test_email_contains_at() {
        let cgen = ContactGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(33);

        for i in 0..200 {
            let artifact = cgen.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: ContactEntry = serde_json::from_slice(&bytes).unwrap();
            assert!(
                entry.email.contains('@'),
                "entry {i}: email '{}' missing '@'",
                entry.email
            );
            // Should also have a domain part after @
            let parts: Vec<&str> = entry.email.split('@').collect();
            assert_eq!(parts.len(), 2, "entry {i}: email should have exactly one '@'");
            assert!(!parts[0].is_empty(), "entry {i}: email local part is empty");
            assert!(parts[1].contains('.'), "entry {i}: email domain missing '.'");
        }
    }

    #[test]
    fn test_category_distribution() {
        let cgen = ContactGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let mut family = 0u32;
        let mut friend = 0u32;
        let mut work = 0u32;
        let mut acquaintance = 0u32;

        for _ in 0..1000 {
            let artifact = cgen.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: ContactEntry = serde_json::from_slice(&bytes).unwrap();
            match entry.category {
                ContactCategory::Family => family += 1,
                ContactCategory::Friend => friend += 1,
                ContactCategory::Work => work += 1,
                ContactCategory::Acquaintance => acquaintance += 1,
            }
        }

        // All categories should be represented
        assert!(family > 0, "should have family contacts");
        assert!(friend > 0, "should have friend contacts");
        assert!(work > 0, "should have work contacts");
        assert!(acquaintance > 0, "should have acquaintance contacts");

        // Work should be the most common (30%), Acquaintance (30%), Friend (25%), Family (15%)
        assert!(work > 200, "work contacts should be substantial: got {work}");
        assert!(family < friend, "family ({family}) should be less common than friends ({friend})");
    }

    #[test]
    fn test_creation_dates_spread_over_time() {
        let cgen = ContactGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let mut min_age_days = 0i64;
        let mut max_age_days = 0i64;

        for _ in 0..200 {
            let artifact = cgen.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: ContactEntry = serde_json::from_slice(&bytes).unwrap();

            let age = (ctx.now - entry.created_at).num_days();
            if age > max_age_days {
                max_age_days = age;
            }
            if min_age_days == 0 || age < min_age_days {
                min_age_days = age;
            }
        }

        // Dates should span at least a year's range
        let spread = max_age_days - min_age_days;
        assert!(
            spread > 300,
            "creation dates should span many months, got spread of {spread} days"
        );
    }
}
