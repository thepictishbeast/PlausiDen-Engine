//! localStorage/IndexedDB entry generation for visited sites.
//!
//! Generates key-value pairs that websites store in the browser's localStorage.
//! Forensic tools extract localStorage to identify user activity, preferences,
//! session tokens, and analytics identifiers tied to specific origins.

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

/// A single localStorage entry stored by a website.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct LocalStorageEntry {
    /// Artifact metadata.
    pub meta: ArtifactMetadata,
    /// Origin domain that stored this entry (e.g., `https://www.example.com`).
    pub origin: String,
    /// localStorage key.
    pub key: String,
    /// localStorage value.
    pub value: String,
    /// When this entry was first written.
    pub created_at: DateTime<Utc>,
    /// Approximate size in bytes (key.len() + value.len()).
    pub size_bytes: u64,
}

impl Artifact for LocalStorageEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;

        if self.origin.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty origin".to_string(),
            });
        }

        if self.key.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty key".to_string(),
            });
        }

        // Values can be empty strings in real localStorage, but never in our generator
        if self.value.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty value".to_string(),
            });
        }

        if self.size_bytes == 0 {
            return Err(EngineError::ImplausibleArtifact {
                reason: "size_bytes is zero".to_string(),
            });
        }

        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

/// Categories of localStorage data that websites commonly store.
#[derive(Debug, Clone, Copy)]
enum StorageKind {
    /// Session/auth tokens (random hex strings).
    SessionToken,
    /// User preference settings (theme, language).
    UserPreference,
    /// Analytics tracking IDs (_ga, _gid format).
    AnalyticsId,
    /// Cookie consent / GDPR flags.
    CookieConsent,
    /// Shopping cart or wishlist data.
    CartData,
}

/// Weighted distribution of storage kinds -- session tokens and preferences dominate.
const STORAGE_KINDS: &[(StorageKind, u32)] = &[
    (StorageKind::SessionToken, 25),
    (StorageKind::UserPreference, 25),
    (StorageKind::AnalyticsId, 20),
    (StorageKind::CookieConsent, 15),
    (StorageKind::CartData, 15),
];

/// Theme values for user preferences.
const THEMES: &[&str] = &["dark", "light", "auto", "system"];

/// Language codes for user preferences.
const LANGUAGES: &[&str] = &["en", "en-US", "es", "fr", "de", "pt", "ja", "zh", "ko"];

/// Common product names for cart/wishlist data.
const PRODUCT_NAMES: &[&str] = &[
    "Wireless Headphones",
    "USB-C Cable",
    "Laptop Stand",
    "Mechanical Keyboard",
    "Mouse Pad",
    "Monitor Light Bar",
    "Webcam HD",
    "Phone Case",
    "Screen Protector",
    "Desk Organizer",
    "Travel Mug",
    "Notebook",
    "Backpack",
    "Water Bottle",
    "Bluetooth Speaker",
];

/// Generates localStorage key-value pairs for websites.
pub struct LocalStorageGenerator;

impl LocalStorageGenerator {
    /// Create a new localStorage generator.
    pub fn new() -> Self {
        Self
    }

    /// Pick a weighted-random storage kind.
    fn choose_storage_kind(rng: &mut (impl RngCore + CryptoRng)) -> StorageKind {
        let total_weight: u32 = STORAGE_KINDS.iter().map(|(_, w)| w).sum();
        let roll = Uniform::new(0u32, total_weight).sample(rng);
        let mut cumulative = 0u32;
        for (kind, weight) in STORAGE_KINDS {
            cumulative += weight;
            if roll < cumulative {
                return *kind;
            }
        }
        StorageKind::SessionToken
    }

    /// Generate a random hex string of the given byte length.
    fn random_hex(byte_len: usize, rng: &mut (impl RngCore + CryptoRng)) -> String {
        let mut bytes = vec![0u8; byte_len];
        rng.fill_bytes(&mut bytes);
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Generate a key-value pair for the given storage kind.
    fn generate_kv(kind: StorageKind, rng: &mut (impl RngCore + CryptoRng)) -> (String, String) {
        match kind {
            StorageKind::SessionToken => {
                let keys = [
                    "token",
                    "session_token",
                    "auth_token",
                    "access_token",
                    "jwt",
                    "sid",
                ];
                let key = keys.choose(rng).unwrap_or(&"token");
                let value = Self::random_hex(32, rng);
                (key.to_string(), value)
            }
            StorageKind::UserPreference => {
                let roll = Uniform::new_inclusive(0u32, 3).sample(rng);
                match roll {
                    0 => {
                        let theme = THEMES.choose(rng).unwrap_or(&"dark");
                        ("theme".to_string(), theme.to_string())
                    }
                    1 => {
                        let lang = LANGUAGES.choose(rng).unwrap_or(&"en");
                        ("language".to_string(), lang.to_string())
                    }
                    2 => {
                        let val = if Uniform::new_inclusive(0u32, 1).sample(rng) == 0 {
                            "true"
                        } else {
                            "false"
                        };
                        ("notifications_enabled".to_string(), val.to_string())
                    }
                    _ => {
                        let font_sizes = ["small", "medium", "large"];
                        let size = font_sizes.choose(rng).unwrap_or(&"medium");
                        ("font_size".to_string(), size.to_string())
                    }
                }
            }
            StorageKind::AnalyticsId => {
                let roll = Uniform::new_inclusive(0u32, 2).sample(rng);
                match roll {
                    0 => {
                        // Google Analytics _ga format: GA1.2.<random>.<timestamp>
                        let rand_part =
                            Uniform::new_inclusive(100_000_000u64, 9_999_999_999u64).sample(rng);
                        let ts_part =
                            Uniform::new_inclusive(1_600_000_000u64, 1_750_000_000u64).sample(rng);
                        ("_ga".to_string(), format!("GA1.2.{rand_part}.{ts_part}"))
                    }
                    1 => {
                        // Google Analytics _gid
                        let rand_part =
                            Uniform::new_inclusive(100_000_000u64, 9_999_999_999u64).sample(rng);
                        let ts_part =
                            Uniform::new_inclusive(1_600_000_000u64, 1_750_000_000u64).sample(rng);
                        ("_gid".to_string(), format!("GA1.2.{rand_part}.{ts_part}"))
                    }
                    _ => {
                        // Generic analytics client ID
                        let client_id = Self::random_hex(16, rng);
                        ("_analytics_id".to_string(), client_id)
                    }
                }
            }
            StorageKind::CookieConsent => {
                let roll = Uniform::new_inclusive(0u32, 2).sample(rng);
                match roll {
                    0 => (
                        "cookie_consent".to_string(),
                        r#"{"necessary":true,"analytics":true,"marketing":false}"#.to_string(),
                    ),
                    1 => ("gdpr_consent".to_string(), "accepted".to_string()),
                    _ => {
                        let ts =
                            Uniform::new_inclusive(1_700_000_000u64, 1_750_000_000u64).sample(rng);
                        ("consent_timestamp".to_string(), ts.to_string())
                    }
                }
            }
            StorageKind::CartData => {
                let roll = Uniform::new_inclusive(0u32, 1).sample(rng);
                match roll {
                    0 => {
                        // Cart with 1-3 items
                        let item_count = Uniform::new_inclusive(1usize, 3).sample(rng);
                        let mut items = Vec::with_capacity(item_count);
                        for _ in 0..item_count {
                            let name = PRODUCT_NAMES.choose(rng).unwrap_or(&"Item");
                            let price_cents = Uniform::new_inclusive(499u32, 19999).sample(rng);
                            let qty = Uniform::new_inclusive(1u32, 3).sample(rng);
                            items.push(format!(
                                r#"{{"name":"{}","price":{},"qty":{}}}"#,
                                name,
                                price_cents as f64 / 100.0,
                                qty,
                            ));
                        }
                        let value = format!("[{}]", items.join(","));
                        ("cart_items".to_string(), value)
                    }
                    _ => {
                        // Wishlist with product IDs
                        let count = Uniform::new_inclusive(1usize, 5).sample(rng);
                        let mut ids = Vec::with_capacity(count);
                        for _ in 0..count {
                            let id = Uniform::new_inclusive(10000u32, 99999).sample(rng);
                            ids.push(id.to_string());
                        }
                        let value = format!("[{}]", ids.join(","));
                        ("wishlist_ids".to_string(), value)
                    }
                }
            }
        }
    }
}

impl Default for LocalStorageGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for LocalStorageGenerator {
    fn generate(
        &self,
        profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        // Pick an origin from user's interests
        let category = profile
            .interests
            .choose(rng)
            .unwrap_or(&engine_core::profile::InterestCategory::Shopping);

        let urls = url_corpus::urls_for_category(category);
        let base_url = urls
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("no URLs for category".to_string()))?;

        // localStorage origin is scheme + host (no path)
        let origin = base_url.split('/').take(3).collect::<Vec<_>>().join("/");

        let kind = Self::choose_storage_kind(rng);
        let (key, value) = Self::generate_kv(kind, rng);

        // Created some time in the past
        let age_secs = Uniform::new_inclusive(60i64, 86400 * 60).sample(rng);
        let created_at = context.now - Duration::seconds(age_secs);

        let size_bytes = (key.len() + value.len()) as u64;

        let meta = ArtifactMetadata::new(
            DataCategory::BrowserActivity,
            created_at,
            created_at,
            size_bytes + 64,
        )?;

        let entry = LocalStorageEntry {
            meta,
            origin,
            key,
            value,
            created_at,
            size_bytes,
        };

        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory {
        DataCategory::BrowserActivity
    }

    fn forensic_weight(&self) -> u32 {
        60 // localStorage reveals site-specific user state and tracking
    }

    fn resource_cost(&self) -> ResourceCost {
        ResourceCost {
            cpu_us: 25,
            disk_bytes: 512,
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
    fn test_localstorage_entry_has_valid_fields() {
        let gtor = LocalStorageGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let artifact = gtor.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: LocalStorageEntry = serde_json::from_slice(&bytes).unwrap();

        assert!(
            entry.origin.starts_with("http"),
            "origin must start with http: {}",
            entry.origin,
        );
        assert!(!entry.key.is_empty(), "key must not be empty");
        assert!(!entry.value.is_empty(), "value must not be empty");
        assert!(entry.size_bytes > 0, "size_bytes must be > 0");
    }

    #[test]
    fn test_localstorage_origin_has_no_path() {
        let gtor = LocalStorageGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();

        for seed in 0..100u64 {
            let mut rng = seeded_rng(seed);
            let artifact = gtor.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: LocalStorageEntry = serde_json::from_slice(&bytes).unwrap();

            // Origin should be scheme://host with no trailing path
            let parts: Vec<&str> = entry.origin.split('/').collect();
            assert!(
                parts.len() <= 3,
                "seed {seed}: origin should not contain path: {}",
                entry.origin,
            );
        }
    }

    #[test]
    fn test_localstorage_serialization_roundtrip() {
        let gtor = LocalStorageGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(7);

        let artifact = gtor.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: LocalStorageEntry = serde_json::from_slice(&bytes).unwrap();

        let bytes2 = serde_json::to_vec(&entry).unwrap();
        let entry2: LocalStorageEntry = serde_json::from_slice(&bytes2).unwrap();

        assert_eq!(entry.origin, entry2.origin);
        assert_eq!(entry.key, entry2.key);
        assert_eq!(entry.value, entry2.value);
        assert_eq!(entry.size_bytes, entry2.size_bytes);
    }

    #[test]
    fn test_all_storage_kinds_generated() {
        let gtor = LocalStorageGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();

        let mut seen_keys = std::collections::HashSet::new();
        for seed in 0..500u64 {
            let mut rng = seeded_rng(seed);
            let artifact = gtor.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: LocalStorageEntry = serde_json::from_slice(&bytes).unwrap();
            seen_keys.insert(entry.key.clone());
        }

        // Check that at least one key from each storage kind appeared
        let expected_keys = [
            // SessionToken keys
            vec![
                "token",
                "session_token",
                "auth_token",
                "access_token",
                "jwt",
                "sid",
            ],
            // UserPreference keys
            vec!["theme", "language", "notifications_enabled", "font_size"],
            // AnalyticsId keys
            vec!["_ga", "_gid", "_analytics_id"],
            // CookieConsent keys
            vec!["cookie_consent", "gdpr_consent", "consent_timestamp"],
            // CartData keys
            vec!["cart_items", "wishlist_ids"],
        ];

        for group in &expected_keys {
            let group_found = group.iter().any(|k| seen_keys.contains(*k));
            assert!(
                group_found,
                "no keys from group {:?} were generated in 500 entries (saw: {:?})",
                group, seen_keys,
            );
        }
    }

    #[test]
    fn test_500_entries_all_valid() {
        let gtor = LocalStorageGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();

        for seed in 0..500u64 {
            let mut rng = seeded_rng(seed);
            let artifact = gtor.generate(&profile, &ctx, &mut rng).unwrap();
            artifact.validate_plausibility().unwrap_or_else(|e| {
                panic!("localStorage entry {seed} failed plausibility: {e}");
            });
            let bytes = artifact.to_bytes().unwrap();
            let entry: LocalStorageEntry = serde_json::from_slice(&bytes).unwrap();

            assert!(!entry.origin.is_empty(), "seed {seed}: empty origin");
            assert!(!entry.key.is_empty(), "seed {seed}: empty key");
            assert!(!entry.value.is_empty(), "seed {seed}: empty value");
            assert!(entry.size_bytes > 0, "seed {seed}: zero size_bytes");
            assert!(
                entry.origin.starts_with("http"),
                "seed {seed}: origin does not start with http: {}",
                entry.origin,
            );
        }
    }

    #[test]
    fn test_size_bytes_matches_content() {
        let gtor = LocalStorageGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();

        for seed in 0..100u64 {
            let mut rng = seeded_rng(seed);
            let artifact = gtor.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: LocalStorageEntry = serde_json::from_slice(&bytes).unwrap();

            let expected_size = (entry.key.len() + entry.value.len()) as u64;
            assert_eq!(
                entry.size_bytes, expected_size,
                "seed {seed}: size_bytes ({}) should equal key+value length ({})",
                entry.size_bytes, expected_size,
            );
        }
    }

    #[test]
    fn test_analytics_ids_have_correct_format() {
        let gtor = LocalStorageGenerator::new();
        let profile = test_profile();
        let ctx = GenerationContext::new();

        for seed in 0..500u64 {
            let mut rng = seeded_rng(seed);
            let artifact = gtor.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let entry: LocalStorageEntry = serde_json::from_slice(&bytes).unwrap();

            if entry.key == "_ga" || entry.key == "_gid" {
                assert!(
                    entry.value.starts_with("GA1.2."),
                    "seed {seed}: {}: value should start with GA1.2.: {}",
                    entry.key,
                    entry.value,
                );
            }
        }
    }
}
