//! DNS query log generation -- realistic lookup patterns.
//!
//! Real DNS traffic follows predictable patterns: browsers look up domains
//! before HTTP connections, OS resolvers cache aggressively, and certain
//! domains are queried repeatedly (CDNs, analytics, auth providers).
//! Query clusters correlate with page loads, and DNS prefetch adds
//! speculative lookups that precede user navigation.

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

// ---------------------------------------------------------------------------
// Query type enum
// ---------------------------------------------------------------------------

/// DNS record types commonly observed in resolver logs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, serde::Deserialize)]
pub enum DnsQueryType {
    /// IPv4 address record.
    A,
    /// IPv6 address record.
    AAAA,
    /// Mail exchange record.
    MX,
    /// Canonical name (alias) record.
    CNAME,
    /// Text record (SPF, DKIM, verification).
    TXT,
}

impl DnsQueryType {
    /// Human-readable label matching resolver log format.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::A => "A",
            Self::AAAA => "AAAA",
            Self::MX => "MX",
            Self::CNAME => "CNAME",
            Self::TXT => "TXT",
        }
    }
}

impl std::fmt::Display for DnsQueryType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

// ---------------------------------------------------------------------------
// DNS query artifact
// ---------------------------------------------------------------------------

/// A generated DNS query log entry.
///
/// Models a single resolver lookup as it would appear in system DNS logs,
/// passive DNS captures, or forensic packet analysis.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct DnsQuery {
    /// Artifact metadata (timestamps, category, size).
    pub meta: ArtifactMetadata,
    /// Domain name queried (e.g., "www.google.com").
    pub domain: String,
    /// Record type requested.
    pub query_type: DnsQueryType,
    /// Response IP address (populated for A/AAAA records).
    pub response_ip: Option<String>,
    /// Time-to-live of the response in seconds.
    pub ttl: u32,
    /// Timestamp of the query.
    pub timestamp: DateTime<Utc>,
    /// Round-trip latency in milliseconds.
    pub latency_ms: u32,
}

impl Artifact for DnsQuery {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.domain.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty DNS domain".into(),
            });
        }
        if self.latency_ms > 5000 {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!("DNS latency {}ms exceeds 5s plausibility limit", self.latency_ms),
            });
        }
        if self.ttl == 0 {
            return Err(EngineError::ImplausibleArtifact {
                reason: "DNS TTL of zero is implausible for a successful response".into(),
            });
        }
        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

// ---------------------------------------------------------------------------
// Realistic domain pools
// ---------------------------------------------------------------------------

/// CDN infrastructure domains -- appear in virtually all browsing sessions.
const CDN_DOMAINS: &[&str] = &[
    "cdn.jsdelivr.net",
    "cdnjs.cloudflare.com",
    "ajax.googleapis.com",
    "fonts.googleapis.com",
    "fonts.gstatic.com",
    "static.cloudflareinsights.com",
    "unpkg.com",
    "cdn.ampproject.org",
    "cdn.shopify.com",
    "d1.awsstatic.com",
    "assets.adobedtm.com",
    "cdn.optimizely.com",
];

/// Ad network and tracking domains -- ubiquitous background traffic.
const AD_NETWORK_DOMAINS: &[&str] = &[
    "www.google-analytics.com",
    "analytics.google.com",
    "stats.g.doubleclick.net",
    "pixel.facebook.com",
    "bat.bing.com",
    "sb.scorecardresearch.com",
    "px.ads.linkedin.com",
    "ads.twitter.com",
    "www.googletagmanager.com",
    "connect.facebook.net",
    "pagead2.googlesyndication.com",
    "securepubads.g.doubleclick.net",
];

/// Social media domains.
const SOCIAL_MEDIA_DOMAINS: &[&str] = &[
    "www.facebook.com",
    "www.instagram.com",
    "www.twitter.com",
    "www.linkedin.com",
    "www.reddit.com",
    "www.tiktok.com",
    "www.pinterest.com",
    "www.snapchat.com",
    "discord.com",
    "www.twitch.tv",
];

/// Search engine domains.
const SEARCH_ENGINE_DOMAINS: &[&str] = &[
    "www.google.com",
    "www.bing.com",
    "duckduckgo.com",
    "search.yahoo.com",
    "www.ecosia.org",
    "www.startpage.com",
];

/// News and media sites.
const NEWS_DOMAINS: &[&str] = &[
    "www.nytimes.com",
    "www.bbc.com",
    "www.cnn.com",
    "www.reuters.com",
    "www.theguardian.com",
    "news.ycombinator.com",
    "www.washingtonpost.com",
    "www.aljazeera.com",
    "arstechnica.com",
    "www.wired.com",
];

/// General browsing -- high-traffic sites across categories.
const GENERAL_BROWSING_DOMAINS: &[&str] = &[
    "www.youtube.com",
    "www.wikipedia.org",
    "www.amazon.com",
    "www.github.com",
    "www.stackoverflow.com",
    "www.netflix.com",
    "mail.google.com",
    "outlook.live.com",
    "web.whatsapp.com",
    "www.ebay.com",
    "www.apple.com",
    "www.microsoft.com",
    "www.spotify.com",
    "www.dropbox.com",
    "docs.google.com",
];

/// Infrastructure domains (NTP, OCSP, connectivity checks).
const INFRASTRUCTURE_DOMAINS: &[&str] = &[
    "dns.google",
    "one.one.one.one",
    "cloudflare-dns.com",
    "ocsp.digicert.com",
    "ocsp.pki.goog",
    "crl.microsoft.com",
    "ctldl.windowsupdate.com",
    "safebrowsing.googleapis.com",
    "connectivity-check.ubuntu.com",
    "detectportal.firefox.com",
    "ntp.ubuntu.com",
    "time.google.com",
];

/// DNS prefetch domains -- browsers speculatively resolve these.
const PREFETCH_DOMAINS: &[&str] = &[
    "fonts.googleapis.com",
    "www.googletagmanager.com",
    "connect.facebook.net",
    "cdn.jsdelivr.net",
    "www.google-analytics.com",
    "static.cloudflareinsights.com",
    "api.github.com",
    "accounts.google.com",
];

/// Categories of domain pools with their relative selection weights.
#[derive(Debug, Clone, Copy)]
enum DomainCategory {
    Cdn,
    AdNetwork,
    SocialMedia,
    SearchEngine,
    News,
    GeneralBrowsing,
    Infrastructure,
    Prefetch,
}

/// Select a domain from the pools, weighted by real traffic patterns.
///
/// Returns `None` only if all pools are empty (impossible with const data).
fn select_domain(rng: &mut (impl RngCore + CryptoRng)) -> Option<(&'static str, DomainCategory)> {
    let roll = Uniform::new_inclusive(0u32, 99).sample(rng);
    let (pool, category): (&[&str], DomainCategory) = match roll {
        0..=24 => (GENERAL_BROWSING_DOMAINS, DomainCategory::GeneralBrowsing),
        25..=39 => (CDN_DOMAINS, DomainCategory::Cdn),
        40..=54 => (AD_NETWORK_DOMAINS, DomainCategory::AdNetwork),
        55..=64 => (SOCIAL_MEDIA_DOMAINS, DomainCategory::SocialMedia),
        65..=74 => (SEARCH_ENGINE_DOMAINS, DomainCategory::SearchEngine),
        75..=84 => (NEWS_DOMAINS, DomainCategory::News),
        85..=92 => (INFRASTRUCTURE_DOMAINS, DomainCategory::Infrastructure),
        _ => (PREFETCH_DOMAINS, DomainCategory::Prefetch),
    };
    pool.choose(rng).map(|d| (*d, category))
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

/// Generates realistic DNS query log artifacts.
///
/// Produces lookup entries matching real browsing patterns: clustered queries
/// around page loads, DNS prefetch, infrastructure background queries, and
/// cache-aware latency values.
pub struct DnsQueryGenerator;

impl DnsQueryGenerator {
    /// Create a new DNS query generator.
    pub fn new() -> Self {
        Self
    }

    /// Select a DNS query type using weighted distribution matching real traffic.
    ///
    /// A records dominate (~65%), AAAA growing (~15%), CNAME (~10%),
    /// MX and TXT are rare (~5% each).
    fn pick_query_type(rng: &mut (impl RngCore + CryptoRng)) -> DnsQueryType {
        let roll = Uniform::new_inclusive(0u32, 99).sample(rng);
        match roll {
            0..=64 => DnsQueryType::A,
            65..=79 => DnsQueryType::AAAA,
            80..=89 => DnsQueryType::CNAME,
            90..=94 => DnsQueryType::MX,
            _ => DnsQueryType::TXT,
        }
    }

    /// Generate a plausible response IP for A or AAAA records.
    fn make_response_ip(
        query_type: DnsQueryType,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Option<String> {
        match query_type {
            DnsQueryType::A => {
                Some(format!(
                    "{}.{}.{}.{}",
                    Uniform::new_inclusive(1u8, 223).sample(rng),
                    Uniform::new_inclusive(0u8, 255).sample(rng),
                    Uniform::new_inclusive(0u8, 255).sample(rng),
                    Uniform::new_inclusive(1u8, 254).sample(rng),
                ))
            }
            DnsQueryType::AAAA => {
                let segments: Vec<String> = (0..8)
                    .map(|_| {
                        format!(
                            "{:x}",
                            Uniform::new_inclusive(0u16, 0xffff).sample(rng)
                        )
                    })
                    .collect();
                Some(segments.join(":"))
            }
            _ => None,
        }
    }

    /// Compute TTL based on domain category.
    ///
    /// Infrastructure and CDN domains have long TTLs (hours to days).
    /// Browsing and social media domains have shorter TTLs (minutes to hours).
    fn compute_ttl(
        category: DomainCategory,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> u32 {
        match category {
            DomainCategory::Infrastructure => {
                Uniform::new_inclusive(3600u32, 86400).sample(rng)
            }
            DomainCategory::Cdn => {
                Uniform::new_inclusive(1800u32, 86400).sample(rng)
            }
            DomainCategory::AdNetwork | DomainCategory::Prefetch => {
                Uniform::new_inclusive(60u32, 3600).sample(rng)
            }
            DomainCategory::SearchEngine
            | DomainCategory::SocialMedia
            | DomainCategory::News
            | DomainCategory::GeneralBrowsing => {
                Uniform::new_inclusive(30u32, 7200).sample(rng)
            }
        }
    }

    /// Compute query latency.
    ///
    /// Simulates cache behavior: ~60% of queries hit the local resolver cache
    /// (0-3ms), while cache misses require recursive resolution (5-200ms).
    /// Prefetch queries are almost always cached.
    fn compute_latency(
        category: DomainCategory,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> u32 {
        let cache_hit_threshold = match category {
            DomainCategory::Prefetch => 85,
            DomainCategory::Infrastructure | DomainCategory::Cdn => 70,
            _ => 55,
        };
        let roll = Uniform::new_inclusive(0u32, 99).sample(rng);
        if roll < cache_hit_threshold {
            // Cache hit: very fast
            Uniform::new_inclusive(0u32, 3).sample(rng)
        } else {
            // Cache miss: recursive resolution
            Uniform::new_inclusive(5u32, 200).sample(rng)
        }
    }
}

impl Default for DnsQueryGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for DnsQueryGenerator {
    fn generate(
        &self,
        _profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        let (domain, category) = select_domain(rng).ok_or_else(|| EngineError::InvalidContext(
            "empty domain pool (should be unreachable)".into(),
        ))?;

        let query_type = Self::pick_query_type(rng);
        let response_ip = Self::make_response_ip(query_type, rng);
        let ttl = Self::compute_ttl(category, rng);
        let latency_ms = Self::compute_latency(category, rng);

        // Jitter the timestamp to simulate queries spread over recent time.
        // Browsing clusters span 0-60s; background infra queries span wider.
        let jitter_range = match category {
            DomainCategory::Infrastructure => 600i64,
            DomainCategory::Prefetch => 30,
            _ => 300,
        };
        let jitter = Uniform::new_inclusive(0i64, jitter_range).sample(rng);
        let timestamp = context.now - Duration::seconds(jitter);

        let estimated_size = (domain.len() + 96) as u64;
        let meta = ArtifactMetadata::new(
            DataCategory::Network,
            timestamp,
            timestamp,
            estimated_size,
        )?;

        let entry = DnsQuery {
            meta,
            domain: domain.to_string(),
            query_type,
            response_ip,
            ttl,
            timestamp,
            latency_ms,
        };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory {
        DataCategory::Network
    }

    fn forensic_weight(&self) -> u32 {
        70
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_dns_query_roundtrip() {
        let generator = DnsQueryGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let artifact = generator.generate(&profile, &ctx, &mut rng).expect("generation failed");
        artifact.validate_plausibility().expect("plausibility check failed");

        let bytes = artifact.to_bytes().expect("serialization failed");
        let entry: DnsQuery = serde_json::from_slice(&bytes).expect("deserialization failed");
        assert!(!entry.domain.is_empty(), "domain must not be empty");
        assert!(entry.ttl > 0, "TTL must be positive");
        assert!(entry.latency_ms <= 5000, "latency must be plausible");
    }

    #[test]
    fn test_1000_dns_queries_all_valid() {
        let generator = DnsQueryGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();

        for seed in 0u64..1000 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .unwrap_or_else(|e| panic!("seed {seed} failed generation: {e}"));
            artifact
                .validate_plausibility()
                .unwrap_or_else(|e| panic!("seed {seed} failed plausibility: {e}"));
        }
    }

    #[test]
    fn test_query_type_distribution() {
        let generator = DnsQueryGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let n = 5000u64;
        let mut a_count = 0u64;
        let mut aaaa_count = 0u64;
        let mut cname_count = 0u64;
        let mut mx_count = 0u64;
        let mut txt_count = 0u64;

        for seed in 0..n {
            let mut rng = seeded_rng(seed);
            let artifact = generator.generate(&profile, &ctx, &mut rng).expect("gen");
            let bytes = artifact.to_bytes().expect("bytes");
            let entry: DnsQuery = serde_json::from_slice(&bytes).expect("deser");
            match entry.query_type {
                DnsQueryType::A => a_count += 1,
                DnsQueryType::AAAA => aaaa_count += 1,
                DnsQueryType::CNAME => cname_count += 1,
                DnsQueryType::MX => mx_count += 1,
                DnsQueryType::TXT => txt_count += 1,
            }
        }

        let pct = |c: u64| (c as f64 / n as f64) * 100.0;
        assert!(
            pct(a_count) > 45.0 && pct(a_count) < 85.0,
            "A records should be ~65%, got {:.1}%",
            pct(a_count)
        );
        assert!(
            pct(aaaa_count) > 5.0 && pct(aaaa_count) < 30.0,
            "AAAA records should be ~15%, got {:.1}%",
            pct(aaaa_count)
        );
        assert!(cname_count > 0, "should produce some CNAME records");
        assert!(mx_count > 0, "should produce some MX records");
        assert!(txt_count > 0, "should produce some TXT records");
    }

    #[test]
    fn test_a_records_have_response_ip() {
        let generator = DnsQueryGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut found_a = false;

        for seed in 0u64..500 {
            let mut rng = seeded_rng(seed);
            let artifact = generator.generate(&profile, &ctx, &mut rng).expect("gen");
            let bytes = artifact.to_bytes().expect("bytes");
            let entry: DnsQuery = serde_json::from_slice(&bytes).expect("deser");
            if entry.query_type == DnsQueryType::A {
                assert!(
                    entry.response_ip.is_some(),
                    "A records must have a response IP"
                );
                found_a = true;
            }
        }
        assert!(found_a, "should generate at least one A record in 500 queries");
    }

    #[test]
    fn test_domain_pool_coverage() {
        let generator = DnsQueryGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut found_cdn = false;
        let mut found_social = false;
        let mut found_search = false;
        let mut found_news = false;
        let mut found_infra = false;

        for seed in 0u64..2000 {
            let mut rng = seeded_rng(seed);
            let artifact = generator.generate(&profile, &ctx, &mut rng).expect("gen");
            let bytes = artifact.to_bytes().expect("bytes");
            let entry: DnsQuery = serde_json::from_slice(&bytes).expect("deser");
            let d = entry.domain.as_str();

            if CDN_DOMAINS.contains(&d) {
                found_cdn = true;
            }
            if SOCIAL_MEDIA_DOMAINS.contains(&d) {
                found_social = true;
            }
            if SEARCH_ENGINE_DOMAINS.contains(&d) {
                found_search = true;
            }
            if NEWS_DOMAINS.contains(&d) {
                found_news = true;
            }
            if INFRASTRUCTURE_DOMAINS.contains(&d) {
                found_infra = true;
            }
        }

        assert!(found_cdn, "should include CDN domains");
        assert!(found_social, "should include social media domains");
        assert!(found_search, "should include search engine domains");
        assert!(found_news, "should include news domains");
        assert!(found_infra, "should include infrastructure domains");
    }

    #[test]
    fn test_latency_cache_behavior() {
        let generator = DnsQueryGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut fast_count = 0u64;
        let total = 1000u64;

        for seed in 0..total {
            let mut rng = seeded_rng(seed);
            let artifact = generator.generate(&profile, &ctx, &mut rng).expect("gen");
            let bytes = artifact.to_bytes().expect("bytes");
            let entry: DnsQuery = serde_json::from_slice(&bytes).expect("deser");
            if entry.latency_ms <= 3 {
                fast_count += 1;
            }
        }

        let pct = (fast_count as f64 / total as f64) * 100.0;
        assert!(
            pct > 30.0,
            "at least 30% of queries should be fast (cache hits), got {pct:.1}%"
        );
    }
}
