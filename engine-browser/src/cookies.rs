//! Cookie generation matching visited domains.
//!
//! Generates browser cookies that correspond to visited domains. Forensic analysts
//! cross-reference cookies with history — orphaned cookies (cookies without
//! corresponding history entries) are a red flag.

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

/// SameSite cookie attribute.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub enum SameSite {
    Strict,
    Lax,
    None,
}

/// A single browser cookie.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct CookieEntry {
    /// Artifact metadata.
    pub meta: ArtifactMetadata,
    /// Cookie domain (e.g., ".example.com").
    pub domain: String,
    /// Cookie path.
    pub path: String,
    /// Cookie name.
    pub name: String,
    /// Cookie value.
    pub value: String,
    /// When the cookie was created.
    pub created_at: DateTime<Utc>,
    /// When the cookie expires.
    pub expires_at: DateTime<Utc>,
    /// Whether the cookie is secure (HTTPS only).
    pub secure: bool,
    /// Whether the cookie is HTTP-only.
    pub http_only: bool,
    /// SameSite attribute.
    pub same_site: SameSite,
}

impl Artifact for CookieEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;

        if self.domain.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty cookie domain".to_string(),
            });
        }

        // Expiry should be after creation
        if self.expires_at < self.created_at {
            return Err(EngineError::ImplausibleArtifact {
                reason: "cookie expires before creation".to_string(),
            });
        }

        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

/// Common cookie names used by real websites.
const COMMON_COOKIES: &[(&str, &str)] = &[
    ("_ga", "GA1.2."),
    ("_gid", "GA1.2."),
    ("_gat", "1"),
    ("NID", ""),
    ("CONSENT", "YES+"),
    ("JSESSIONID", ""),
    ("PHPSESSID", ""),
    ("csrftoken", ""),
    ("sessionid", ""),
    ("__cfduid", ""),
    ("_fbp", "fb.1."),
    ("_gcl_au", "1.1."),
    ("lang", "en"),
    ("theme", "light"),
    ("prefs", ""),
    ("visited", "true"),
];

/// Generates realistic browser cookies matching visited domains.
pub struct CookieGenerator;

impl CookieGenerator {
    pub fn new() -> Self {
        Self
    }

    /// Generate a plausible cookie value.
    fn generate_value(name: &str, rng: &mut (impl RngCore + CryptoRng)) -> String {
        // Find prefix from common cookies
        let prefix = COMMON_COOKIES
            .iter()
            .find(|(n, _)| *n == name)
            .map(|(_, p)| *p)
            .unwrap_or("");

        let random_part: u64 = Uniform::new_inclusive(100_000_000u64, 9_999_999_999u64).sample(rng);

        format!("{prefix}{random_part}")
    }

    /// Extract domain from a URL for cookie domain field.
    fn domain_from_url(url: &str) -> String {
        let stripped = url
            .strip_prefix("https://")
            .or_else(|| url.strip_prefix("http://"))
            .unwrap_or(url);

        let host = stripped.split('/').next().unwrap_or(stripped);
        let host = host.strip_prefix("www.").unwrap_or(host);

        format!(".{host}")
    }

    /// Choose a realistic cookie expiry duration.
    fn expiry_duration(rng: &mut (impl RngCore + CryptoRng)) -> Duration {
        let choice = Uniform::new_inclusive(0u32, 9).sample(rng);
        match choice {
            0..=2 => Duration::hours(1),  // Session-like: 1 hour
            3..=4 => Duration::days(1),   // Daily
            5..=6 => Duration::days(30),  // Monthly
            7..=8 => Duration::days(365), // Annual
            _ => Duration::days(365 * 2), // Long-lived (2 years, max per spec)
        }
    }
}

impl Default for CookieGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for CookieGenerator {
    fn generate(
        &self,
        profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        // Pick a domain from the user's interests
        let category = profile
            .interests
            .choose(rng)
            .unwrap_or(&engine_core::profile::InterestCategory::News);

        let urls = url_corpus::urls_for_category(category);
        let base_url = urls
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("no URLs for category".to_string()))?;

        let domain = Self::domain_from_url(base_url);

        // Pick a cookie name
        let (name, _) = COMMON_COOKIES.choose(rng).unwrap_or(&("session", ""));

        let value = Self::generate_value(name, rng);

        let jitter = Uniform::new_inclusive(0i64, 3600).sample(rng);
        let created_at = context.now - Duration::seconds(jitter);
        let expires_at = created_at + Self::expiry_duration(rng);

        let secure = Uniform::new_inclusive(0u32, 9).sample(rng) > 2; // 70% HTTPS
        let http_only = Uniform::new_inclusive(0u32, 9).sample(rng) > 4; // 50%

        let same_site = match Uniform::new_inclusive(0u32, 2).sample(rng) {
            0 => SameSite::Strict,
            1 => SameSite::Lax,
            _ => SameSite::None,
        };

        let meta = ArtifactMetadata::new(
            DataCategory::BrowserActivity,
            created_at,
            created_at,
            (name.len() + value.len() + domain.len()) as u64 + 64,
        )?;

        let cookie = CookieEntry {
            meta,
            domain,
            path: "/".to_string(),
            name: name.to_string(),
            value,
            created_at,
            expires_at,
            secure,
            http_only,
            same_site,
        };

        cookie.validate_plausibility()?;
        Ok(Box::new(cookie))
    }

    fn category(&self) -> DataCategory {
        DataCategory::BrowserActivity
    }

    fn forensic_weight(&self) -> u32 {
        85 // Cookies are cross-referenced with history
    }

    fn resource_cost(&self) -> ResourceCost {
        ResourceCost {
            cpu_us: 20,
            disk_bytes: 256,
            network_bytes: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_cookies_match_visited_domains() {
        let generator = CookieGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let cookie: CookieEntry = serde_json::from_slice(&bytes).unwrap();

        // Cookie domain should start with a dot
        assert!(
            cookie.domain.starts_with('.'),
            "cookie domain should start with '.'"
        );
        // Domain should correspond to a real domain from our corpus
        assert!(
            cookie.domain.len() > 1,
            "cookie domain should not be just a dot"
        );
    }

    /// Forensic-plausibility regression: cookies' domains must come
    /// from the URL corpus (the same pool history visits draw from).
    /// Without this property, cookies for never-visited domains
    /// would surface — a forensic flag for a session where the
    /// browser holds cookies from sites the history doesn't show.
    ///
    /// The cookie domain field is `.example.com`-shaped (leading
    /// dot); we strip it for matching against the corpus's
    /// scheme-and-host URL form.
    #[test]
    fn test_cookie_domains_anchor_in_url_corpus() {
        use crate::url_corpus;
        use engine_core::profile::InterestCategory;

        let generator = CookieGenerator::new();
        let mut profile = UserProfile::default();
        // Pin to one interest so the test is deterministic about
        // the candidate corpus pool.
        profile.interests = vec![InterestCategory::Technology];
        let ctx = GenerationContext::new();
        let corpus_urls: Vec<&str> =
            url_corpus::urls_for_category(&InterestCategory::Technology).iter().copied().collect();

        for s in 0..200 {
            let mut rng = seeded_rng(s);
            let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let cookie: CookieEntry = serde_json::from_slice(&bytes).unwrap();
            let bare = cookie.domain.trim_start_matches('.');
            let covered = corpus_urls
                .iter()
                .any(|url| url_corpus::download_covered_by(bare, url));
            assert!(
                covered,
                "cookie domain {:?} not anchored to any Technology-corpus URL",
                cookie.domain,
            );
        }
    }

    #[test]
    fn test_cookie_expiry_after_creation() {
        let generator = CookieGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();

        for seed in 0..20 {
            let mut rng = seeded_rng(seed);
            let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let cookie: CookieEntry = serde_json::from_slice(&bytes).unwrap();

            assert!(
                cookie.expires_at >= cookie.created_at,
                "cookie must not expire before creation"
            );
        }
    }

    #[test]
    fn test_cookie_name_from_real_corpus() {
        let known_names: std::collections::HashSet<&str> =
            COMMON_COOKIES.iter().map(|(n, _)| *n).collect();

        let generator = CookieGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();

        for seed in 0..200u64 {
            let mut rng = seeded_rng(seed);
            let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let cookie: CookieEntry = serde_json::from_slice(&bytes).unwrap();

            assert!(
                known_names.contains(cookie.name.as_str()),
                "cookie name '{}' (seed {seed}) not found in COMMON_COOKIES corpus",
                cookie.name,
            );
        }
    }

    #[test]
    fn test_100_cookies_all_valid() {
        let generator = CookieGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();

        for seed in 0..100u64 {
            let mut rng = seeded_rng(seed);
            let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
            artifact.validate_plausibility().unwrap_or_else(|e| {
                panic!("cookie {seed} failed plausibility: {e}");
            });
            let bytes = artifact.to_bytes().unwrap();
            let cookie: CookieEntry = serde_json::from_slice(&bytes).unwrap();

            assert!(!cookie.domain.is_empty(), "seed {seed}: empty domain");
            assert!(
                cookie.domain.starts_with('.'),
                "seed {seed}: domain should start with dot: {}",
                cookie.domain,
            );
            assert!(!cookie.name.is_empty(), "seed {seed}: empty name");
            assert!(!cookie.value.is_empty(), "seed {seed}: empty value");
            assert!(
                cookie.expires_at >= cookie.created_at,
                "seed {seed}: expires before created"
            );
        }
    }

    #[test]
    fn test_https_cookies_dominant() {
        let generator = CookieGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut secure_count = 0u32;

        for seed in 0..500u64 {
            let mut rng = seeded_rng(seed);
            let artifact = generator.generate(&profile, &ctx, &mut rng).unwrap();
            let bytes = artifact.to_bytes().unwrap();
            let cookie: CookieEntry = serde_json::from_slice(&bytes).unwrap();

            if cookie.secure {
                secure_count += 1;
            }
        }

        let pct = (secure_count as f64 / 500.0) * 100.0;
        assert!(
            pct > 60.0,
            "secure cookies should dominate (>60%): got {pct:.1}% ({secure_count}/500)"
        );
    }
}
