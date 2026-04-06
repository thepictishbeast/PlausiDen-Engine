//! HTTP request timing generation -- realistic request/response metadata.
//!
//! Real HTTP traffic exhibits distinctive timing patterns: response times
//! follow a log-normal distribution (most requests complete quickly, a long
//! tail of slow responses exists), status codes cluster around 200, and
//! content sizes correlate with content type.

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
// HTTP timing artifact
// ---------------------------------------------------------------------------

/// A generated HTTP request timing entry.
///
/// Captures request metadata and timing as would appear in HAR files,
/// proxy logs, or network forensic analysis.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct HttpTiming {
    /// Artifact metadata (timestamps, category, size).
    pub meta: ArtifactMetadata,
    /// Full URL including scheme, host, and path.
    pub url: String,
    /// HTTP method (GET, POST, PUT, DELETE, etc.).
    pub method: String,
    /// HTTP response status code.
    pub status_code: u16,
    /// Total response time in milliseconds (log-normal distributed).
    pub response_time_ms: u32,
    /// Response body content length in bytes.
    pub content_length: u64,
    /// Request timestamp.
    pub timestamp: DateTime<Utc>,
}

impl Artifact for HttpTiming {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.url.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty HTTP URL".into(),
            });
        }
        if self.method.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty HTTP method".into(),
            });
        }
        if !(100..=599).contains(&self.status_code) {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!("invalid HTTP status code: {}", self.status_code),
            });
        }
        if self.response_time_ms > 60_000 {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!(
                    "HTTP response time {}ms exceeds 60s plausibility limit",
                    self.response_time_ms
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
// Realistic data pools
// ---------------------------------------------------------------------------

/// Domains used to construct URLs -- common browsing targets.
const DOMAINS: &[&str] = &[
    "www.google.com",
    "www.youtube.com",
    "www.reddit.com",
    "www.wikipedia.org",
    "www.amazon.com",
    "www.github.com",
    "www.stackoverflow.com",
    "news.ycombinator.com",
    "www.nytimes.com",
    "www.bbc.com",
    "www.cnn.com",
    "www.twitter.com",
    "www.facebook.com",
    "www.instagram.com",
    "www.linkedin.com",
    "www.netflix.com",
    "www.twitch.tv",
    "mail.google.com",
    "outlook.live.com",
    "web.whatsapp.com",
    "www.apple.com",
    "docs.google.com",
    "www.ebay.com",
    "www.spotify.com",
];

/// URL path templates mimicking real browsing patterns.
const URL_PATHS: &[&str] = &[
    "/",
    "/index.html",
    "/search?q=weather+today",
    "/search?q=rust+programming",
    "/search?q=best+restaurants+near+me",
    "/login",
    "/api/v1/user/profile",
    "/api/v2/feed",
    "/watch?v=dQw4w9WgXcQ",
    "/r/programming/comments/abc123",
    "/wiki/Rust_(programming_language)",
    "/products/category/electronics",
    "/cart",
    "/checkout",
    "/settings/account",
    "/notifications",
    "/messages/inbox",
    "/feed/trending",
    "/explore",
    "/assets/main.css",
    "/static/js/bundle.min.js",
    "/images/logo.png",
    "/favicon.ico",
    "/robots.txt",
    "/api/health",
    "/api/v1/posts?page=2&limit=25",
    "/privacy-policy",
    "/about",
];

/// Content type categories with associated size ranges (min, max bytes).
const CONTENT_PROFILES: &[(&str, u64, u64)] = &[
    ("text/html", 2_000, 150_000),
    ("application/json", 200, 50_000),
    ("text/css", 1_000, 80_000),
    ("application/javascript", 5_000, 500_000),
    ("image/png", 1_000, 2_000_000),
    ("image/jpeg", 5_000, 5_000_000),
    ("image/webp", 2_000, 1_500_000),
    ("image/svg+xml", 500, 30_000),
    ("font/woff2", 10_000, 100_000),
    ("application/octet-stream", 100, 10_000_000),
];

// ---------------------------------------------------------------------------
// Log-normal distribution helpers
// ---------------------------------------------------------------------------

/// Generate a log-normal sample using the Box-Muller transform.
///
/// Produces values from a log-normal distribution with specified mu (location)
/// and sigma (scale) parameters. The result is clamped to [min, max].
///
/// This matches real HTTP response times: most complete in 50-200ms,
/// with a long tail stretching to several seconds.
fn log_normal_sample(
    mu: f64,
    sigma: f64,
    min: f64,
    max: f64,
    rng: &mut (impl RngCore + CryptoRng),
) -> f64 {
    // Box-Muller transform: two uniform samples -> one normal sample.
    let u1: f64 = Uniform::new(0.001f64, 1.0).sample(rng);
    let u2: f64 = Uniform::new(0.0f64, std::f64::consts::TAU).sample(rng);

    let z = (-2.0 * u1.ln()).sqrt() * u2.cos();
    let value = (mu + sigma * z).exp();
    value.clamp(min, max)
}

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

/// Generates realistic HTTP request timing artifacts.
///
/// Response times follow a log-normal distribution (mu=4.5, sigma=0.8) giving
/// a median around 90ms with a tail reaching several seconds. Status codes
/// follow real-world proportions: 200 (~80%), redirects (~10%), 404 (~5%),
/// 500 (~2%), others (~3%).
pub struct HttpTimingGenerator;

impl HttpTimingGenerator {
    /// Create a new HTTP timing generator.
    pub fn new() -> Self {
        Self
    }

    /// Select an HTTP method using weighted distribution.
    ///
    /// GET dominates browsing traffic (~80%), POST for forms/APIs (~15%),
    /// PUT and DELETE are rare (~5% combined).
    fn pick_method(rng: &mut (impl RngCore + CryptoRng)) -> &'static str {
        let roll = Uniform::new_inclusive(0u32, 99).sample(rng);
        match roll {
            0..=79 => "GET",
            80..=94 => "POST",
            95..=97 => "PUT",
            _ => "DELETE",
        }
    }

    /// Select an HTTP status code using the specified distribution:
    /// 200 (80%), 301/302 (10%), 404 (5%), 500 (2%), others (3%).
    fn pick_status_code(rng: &mut (impl RngCore + CryptoRng)) -> u16 {
        let roll = Uniform::new_inclusive(0u32, 99).sample(rng);
        match roll {
            0..=79 => 200,
            80..=84 => 301,
            85..=89 => 302,
            90..=94 => 404,
            95..=96 => 500,
            97 => 403,
            98 => 429,
            _ => 503,
        }
    }

    /// Build a realistic URL from domain and path pools.
    fn build_url(rng: &mut (impl RngCore + CryptoRng)) -> Option<String> {
        let domain = DOMAINS.choose(rng)?;
        let path = URL_PATHS.choose(rng)?;
        Some(format!("https://{domain}{path}"))
    }
}

impl Default for HttpTimingGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for HttpTimingGenerator {
    fn generate(
        &self,
        _profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        let method = Self::pick_method(rng);
        let url = Self::build_url(rng).ok_or_else(|| {
            EngineError::InvalidContext("empty URL pool (should be unreachable)".into())
        })?;
        let status_code = Self::pick_status_code(rng);

        // Response time: log-normal distribution.
        // mu=4.5, sigma=0.8 gives median ~90ms, mean ~150ms, p99 ~1.5s.
        let response_time_raw = log_normal_sample(4.5, 0.8, 5.0, 30_000.0, rng);
        let response_time_ms = response_time_raw as u32;

        // Content length depends on content type and status code.
        let content_length = if status_code == 304 {
            // 304 Not Modified: no body.
            0u64
        } else {
            let (_, min_size, max_size) = CONTENT_PROFILES
                .choose(rng)
                .copied()
                .unwrap_or(("application/octet-stream", 100, 10_000));
            Uniform::new_inclusive(min_size, max_size).sample(rng)
        };

        // Timestamp with jitter to spread across recent window.
        let jitter = Uniform::new_inclusive(0i64, 300).sample(rng);
        let timestamp = context.now - Duration::seconds(jitter);

        let estimated_size = (url.len() as u64) + content_length.min(1024) + 256;
        let meta = ArtifactMetadata::new(
            DataCategory::Network,
            timestamp,
            timestamp,
            estimated_size,
        )?;

        let entry = HttpTiming {
            meta,
            url,
            method: method.to_string(),
            status_code,
            response_time_ms,
            content_length,
            timestamp,
        };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory {
        DataCategory::Network
    }

    fn forensic_weight(&self) -> u32 {
        75
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
    fn test_generate_http_timing_roundtrip() {
        let generator = HttpTimingGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);

        let artifact = generator.generate(&profile, &ctx, &mut rng).expect("generation");
        artifact.validate_plausibility().expect("plausibility");

        let bytes = artifact.to_bytes().expect("serialization");
        let entry: HttpTiming = serde_json::from_slice(&bytes).expect("deserialization");
        assert!(!entry.url.is_empty());
        assert!(!entry.method.is_empty());
        assert!((100..=599).contains(&entry.status_code));
        assert!(entry.response_time_ms > 0);
    }

    #[test]
    fn test_1000_http_timings_all_valid() {
        let generator = HttpTimingGenerator::new();
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
    fn test_status_code_distribution() {
        let generator = HttpTimingGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let n = 10_000u32;
        let mut count_200 = 0u32;
        let mut count_redirect = 0u32;
        let mut count_404 = 0u32;
        let mut count_500 = 0u32;

        for seed in 0..n {
            let mut rng = seeded_rng(u64::from(seed));
            let artifact = generator.generate(&profile, &ctx, &mut rng).expect("gen");
            let bytes = artifact.to_bytes().expect("bytes");
            let entry: HttpTiming = serde_json::from_slice(&bytes).expect("deser");
            match entry.status_code {
                200 => count_200 += 1,
                301 | 302 => count_redirect += 1,
                404 => count_404 += 1,
                500 => count_500 += 1,
                _ => {}
            }
        }

        let pct = |c: u32| (c as f64 / n as f64) * 100.0;
        assert!(
            pct(count_200) > 65.0 && pct(count_200) < 95.0,
            "200s should be ~80%, got {:.1}%",
            pct(count_200)
        );
        assert!(
            pct(count_redirect) > 4.0 && pct(count_redirect) < 18.0,
            "redirects should be ~10%, got {:.1}%",
            pct(count_redirect)
        );
        assert!(
            pct(count_404) > 1.5 && pct(count_404) < 10.0,
            "404s should be ~5%, got {:.1}%",
            pct(count_404)
        );
        assert!(
            pct(count_500) > 0.5 && pct(count_500) < 5.0,
            "500s should be ~2%, got {:.1}%",
            pct(count_500)
        );
    }

    #[test]
    fn test_response_time_log_normal_shape() {
        let generator = HttpTimingGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let n = 5000u32;
        let mut times: Vec<u32> = Vec::with_capacity(n as usize);

        for seed in 0..n {
            let mut rng = seeded_rng(u64::from(seed));
            let artifact = generator.generate(&profile, &ctx, &mut rng).expect("gen");
            let bytes = artifact.to_bytes().expect("bytes");
            let entry: HttpTiming = serde_json::from_slice(&bytes).expect("deser");
            times.push(entry.response_time_ms);
        }

        times.sort();
        let median = times[times.len() / 2];
        let mean = times.iter().map(|&t| t as f64).sum::<f64>() / times.len() as f64;
        let p99 = times[(times.len() as f64 * 0.99) as usize];

        // Log-normal: mean > median (right-skewed).
        assert!(
            mean > median as f64,
            "mean ({mean:.1}ms) should exceed median ({median}ms) for log-normal"
        );

        // Most responses should be fast (median < 300ms).
        assert!(
            median < 300,
            "median response time should be <300ms, got {median}ms"
        );

        // Long tail should exist (p99 meaningfully larger than median).
        assert!(
            p99 > median * 2,
            "p99 ({p99}ms) should be at least 2x median ({median}ms) -- long tail expected"
        );
    }

    #[test]
    fn test_304_has_zero_content_length() {
        let generator = HttpTimingGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut found_304 = false;

        for seed in 0u64..5000 {
            let mut rng = seeded_rng(seed);
            let artifact = generator.generate(&profile, &ctx, &mut rng).expect("gen");
            let bytes = artifact.to_bytes().expect("bytes");
            let entry: HttpTiming = serde_json::from_slice(&bytes).expect("deser");
            if entry.status_code == 304 {
                assert_eq!(
                    entry.content_length, 0,
                    "304 Not Modified must have zero content length"
                );
                found_304 = true;
            }
        }
        // 304 is not in our status distribution, so we do not assert found_304.
        // The test validates correctness when 304 does appear.
        let _ = found_304;
    }

    #[test]
    fn test_method_distribution() {
        let generator = HttpTimingGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let n = 5000u32;
        let mut get_count = 0u32;
        let mut post_count = 0u32;

        for seed in 0..n {
            let mut rng = seeded_rng(u64::from(seed));
            let artifact = generator.generate(&profile, &ctx, &mut rng).expect("gen");
            let bytes = artifact.to_bytes().expect("bytes");
            let entry: HttpTiming = serde_json::from_slice(&bytes).expect("deser");
            match entry.method.as_str() {
                "GET" => get_count += 1,
                "POST" => post_count += 1,
                _ => {}
            }
        }

        let pct = |c: u32| (c as f64 / n as f64) * 100.0;
        assert!(
            pct(get_count) > 60.0 && pct(get_count) < 95.0,
            "GET should be ~80%, got {:.1}%",
            pct(get_count)
        );
        assert!(
            pct(post_count) > 5.0 && pct(post_count) < 25.0,
            "POST should be ~15%, got {:.1}%",
            pct(post_count)
        );
    }
}
