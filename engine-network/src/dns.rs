//! DNS query generation — realistic lookup patterns.
//!
//! Real DNS traffic follows predictable patterns: browsers look up domains
//! before HTTP connections, OS resolvers cache aggressively, and certain
//! domains are queried repeatedly (CDNs, analytics, auth providers).

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

/// A generated DNS query entry.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct DnsEntry {
    pub meta: ArtifactMetadata,
    /// Domain queried.
    pub domain: String,
    /// Record type (A, AAAA, CNAME, MX, TXT, etc.).
    pub record_type: String,
    /// Response IP (for A/AAAA records).
    pub response_ip: Option<String>,
    /// TTL in seconds.
    pub ttl: u32,
    /// Query timestamp.
    pub query_time: DateTime<Utc>,
    /// Response time in milliseconds.
    pub response_ms: u32,
    /// Whether this was a cache hit.
    pub cached: bool,
}

impl Artifact for DnsEntry {
    fn metadata(&self) -> &ArtifactMetadata { &self.meta }
    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.domain.is_empty() {
            return Err(EngineError::ImplausibleArtifact { reason: "empty DNS domain".into() });
        }
        if self.response_ms > 5000 {
            return Err(EngineError::ImplausibleArtifact { reason: "DNS response >5s".into() });
        }
        Ok(())
    }
    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

/// Common domains that appear in DNS logs of any internet user.
const INFRASTRUCTURE_DOMAINS: &[&str] = &[
    "dns.google", "one.one.one.one", "cloudflare-dns.com",
    "ocsp.digicert.com", "ocsp.pki.goog", "crl.microsoft.com",
    "ctldl.windowsupdate.com", "safebrowsing.googleapis.com",
    "connectivity-check.ubuntu.com", "detectportal.firefox.com",
    "ntp.ubuntu.com", "time.google.com",
];

const CDN_DOMAINS: &[&str] = &[
    "cdn.jsdelivr.net", "cdnjs.cloudflare.com", "ajax.googleapis.com",
    "fonts.googleapis.com", "fonts.gstatic.com", "static.cloudflareinsights.com",
    "unpkg.com", "cdn.ampproject.org",
];

const ANALYTICS_DOMAINS: &[&str] = &[
    "www.google-analytics.com", "analytics.google.com",
    "stats.g.doubleclick.net", "pixel.facebook.com",
    "bat.bing.com", "sb.scorecardresearch.com",
];

fn browsing_domains() -> Vec<&'static str> {
    vec![
        "www.google.com", "www.youtube.com", "www.reddit.com",
        "www.wikipedia.org", "www.amazon.com", "www.github.com",
        "www.stackoverflow.com", "news.ycombinator.com",
        "www.nytimes.com", "www.bbc.com", "www.cnn.com",
        "www.twitter.com", "www.facebook.com", "www.instagram.com",
        "www.linkedin.com", "www.netflix.com", "www.twitch.tv",
        "mail.google.com", "outlook.live.com", "web.whatsapp.com",
    ]
}

/// Generates realistic DNS query artifacts.
pub struct DnsGenerator;

impl DnsGenerator {
    pub fn new() -> Self { Self }
}
impl Default for DnsGenerator { fn default() -> Self { Self::new() } }

impl DataGenerator for DnsGenerator {
    fn generate(&self, _profile: &UserProfile, context: &GenerationContext, rng: &mut (impl RngCore + CryptoRng)) -> Result<Box<dyn Artifact>> {
        // Mix of infrastructure, CDN, analytics, and browsing domains
        let roll = Uniform::new_inclusive(0u32, 99).sample(rng);
        let browsing = browsing_domains();
        let domain: &str = if roll < 15 {
            INFRASTRUCTURE_DOMAINS.choose(rng).unwrap()
        } else if roll < 25 {
            CDN_DOMAINS.choose(rng).unwrap()
        } else if roll < 35 {
            ANALYTICS_DOMAINS.choose(rng).unwrap()
        } else {
            browsing.choose(rng).unwrap()
        };

        // Record type — mostly A, some AAAA, occasional CNAME/MX
        let record_type = match Uniform::new_inclusive(0u32, 9).sample(rng) {
            0..=6 => "A",
            7 => "AAAA",
            8 => "CNAME",
            _ => "MX",
        };

        // Response IP (for A records)
        let response_ip = if record_type == "A" {
            Some(format!("{}.{}.{}.{}",
                Uniform::new_inclusive(1u8, 254).sample(rng),
                Uniform::new_inclusive(0u8, 255).sample(rng),
                Uniform::new_inclusive(0u8, 255).sample(rng),
                Uniform::new_inclusive(1u8, 254).sample(rng),
            ))
        } else {
            None
        };

        // TTL — varies by domain type
        let ttl = match roll {
            0..=14 => Uniform::new_inclusive(300u32, 86400).sample(rng), // infra: 5min-1day
            15..=24 => Uniform::new_inclusive(3600u32, 86400).sample(rng), // CDN: 1hr-1day
            _ => Uniform::new_inclusive(60u32, 3600).sample(rng), // browsing: 1min-1hr
        };

        // Response time — cached queries are fast, uncached are slower
        let cached = Uniform::new_inclusive(0u32, 4).sample(rng) < 3; // 60% cache hit
        let response_ms = if cached {
            Uniform::new_inclusive(0u32, 5).sample(rng)
        } else {
            Uniform::new_inclusive(5u32, 200).sample(rng)
        };

        let jitter = Uniform::new_inclusive(0i64, 300).sample(rng);
        let query_time = context.now - Duration::seconds(jitter);

        let meta = ArtifactMetadata::new(
            DataCategory::Network, query_time, query_time,
            (domain.len() + 64) as u64,
        )?;

        let entry = DnsEntry {
            meta, domain: domain.to_string(), record_type: record_type.to_string(),
            response_ip, ttl, query_time, response_ms, cached,
        };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory { DataCategory::Network }
    fn forensic_weight(&self) -> u32 { 70 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_dns_entry() {
        let g = DnsGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);
        let a = g.generate(&p, &c, &mut r).unwrap();
        a.validate_plausibility().unwrap();
        let b = a.to_bytes().unwrap();
        let e: DnsEntry = serde_json::from_slice(&b).unwrap();
        assert!(!e.domain.is_empty());
    }

    #[test]
    fn test_1000_dns_entries_valid() {
        let g = DnsGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..1000 {
            let mut r = seeded_rng(s);
            g.generate(&p, &c, &mut r).unwrap().validate_plausibility().unwrap();
        }
    }

    #[test]
    fn test_dns_includes_infrastructure() {
        let g = DnsGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut found_infra = false;
        for s in 0..500 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: DnsEntry = serde_json::from_slice(&b).unwrap();
            if INFRASTRUCTURE_DOMAINS.contains(&e.domain.as_str()) {
                found_infra = true;
                break;
            }
        }
        assert!(found_infra, "should include infrastructure DNS queries");
    }

    #[test]
    fn test_dns_cache_hits_exist() {
        let g = DnsGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut cached_count = 0;
        for s in 0..100 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: DnsEntry = serde_json::from_slice(&b).unwrap();
            if e.cached { cached_count += 1; }
        }
        assert!(cached_count > 30, "should have >30% cache hits, got {cached_count}%");
    }
}
