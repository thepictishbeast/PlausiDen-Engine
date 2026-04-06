//! HTTP traffic generation — realistic request/response metadata.
//!
//! Real HTTP traffic follows predictable patterns: browsers issue mostly GET
//! requests, status codes cluster around 200, and timing values reflect the
//! multi-phase nature of connection setup (DNS, TCP, TLS, TTFB, transfer).

use std::collections::HashMap;

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

/// Timing breakdown for an HTTP request lifecycle.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct HttpTiming {
    /// DNS lookup time in milliseconds.
    pub dns_lookup_ms: u32,
    /// TCP connection time in milliseconds.
    pub tcp_connect_ms: u32,
    /// TLS handshake time in milliseconds (0 for plain HTTP).
    pub tls_handshake_ms: u32,
    /// Time to first byte in milliseconds.
    pub ttfb_ms: u32,
    /// Content transfer time in milliseconds.
    pub content_transfer_ms: u32,
}

impl HttpTiming {
    /// Total request duration in milliseconds.
    pub fn total_ms(&self) -> u32 {
        self.dns_lookup_ms
            + self.tcp_connect_ms
            + self.tls_handshake_ms
            + self.ttfb_ms
            + self.content_transfer_ms
    }
}

/// A generated HTTP request/response entry.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct HttpEntry {
    /// Artifact metadata.
    pub meta: ArtifactMetadata,
    /// HTTP method (GET, POST, PUT, DELETE).
    pub method: String,
    /// Full URL including scheme and path.
    pub url: String,
    /// HTTP response status code.
    pub status_code: u16,
    /// Request headers.
    pub request_headers: HashMap<String, String>,
    /// Response headers.
    pub response_headers: HashMap<String, String>,
    /// Timing breakdown for the request.
    pub timing: HttpTiming,
    /// Response body size in bytes.
    pub body_size_bytes: u64,
    /// Request timestamp.
    pub timestamp: DateTime<Utc>,
}

impl Artifact for HttpEntry {
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
        if self.timing.total_ms() > 60_000 {
            return Err(EngineError::ImplausibleArtifact {
                reason: "HTTP request total timing >60s".into(),
            });
        }
        if !(100..=599).contains(&self.status_code) {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!("invalid HTTP status code: {}", self.status_code),
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

/// User-Agent strings spanning common browsers and platforms.
const USER_AGENTS: &[&str] = &[
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_3_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:123.0) Gecko/20100101 Firefox/123.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_3_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.6261.64 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 Edg/122.0.2365.66",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.3; rv:123.0) Gecko/20100101 Firefox/123.0",
];

const ACCEPT_HEADERS: &[&str] = &[
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "application/json, text/plain, */*",
    "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
    "*/*",
];

const ACCEPT_LANGUAGES: &[&str] = &[
    "en-US,en;q=0.9",
    "en-GB,en;q=0.9",
    "en-US,en;q=0.9,de;q=0.8",
    "en-US,en;q=0.9,fr;q=0.8",
    "en-US,en;q=0.9,es;q=0.8",
    "de-DE,de;q=0.9,en-US;q=0.8,en;q=0.7",
    "fr-FR,fr;q=0.9,en-US;q=0.8,en;q=0.7",
];

/// Domains used to construct URLs — common browsing targets.
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
    "/sitemap.xml",
    "/api/health",
    "/api/v1/posts?page=2&limit=25",
    "/privacy-policy",
    "/terms-of-service",
    "/about",
];

/// Referer domains that commonly appear in Referer headers.
const REFERER_DOMAINS: &[&str] = &[
    "https://www.google.com/",
    "https://www.google.com/search?q=example",
    "https://www.reddit.com/",
    "https://news.ycombinator.com/",
    "https://www.facebook.com/",
    "https://t.co/redirect",
    "https://www.linkedin.com/feed/",
];

/// Content types returned for different kinds of responses.
const CONTENT_TYPES: &[(&str, u64, u64)] = &[
    ("text/html; charset=utf-8", 2_000, 150_000),
    ("application/json; charset=utf-8", 200, 50_000),
    ("text/css; charset=utf-8", 1_000, 80_000),
    ("application/javascript; charset=utf-8", 5_000, 500_000),
    ("image/png", 1_000, 2_000_000),
    ("image/jpeg", 5_000, 5_000_000),
    ("image/webp", 2_000, 1_500_000),
    ("image/svg+xml", 500, 30_000),
    ("font/woff2", 10_000, 100_000),
    ("application/octet-stream", 100, 10_000_000),
];

const CACHE_CONTROL_VALUES: &[&str] = &[
    "no-cache",
    "no-store",
    "max-age=0",
    "max-age=300",
    "max-age=3600",
    "max-age=86400",
    "max-age=31536000, immutable",
    "public, max-age=3600",
    "private, max-age=0, no-cache",
    "public, max-age=604800",
];

// ---------------------------------------------------------------------------
// Generator
// ---------------------------------------------------------------------------

/// Generates realistic HTTP request/response artifacts.
pub struct HttpGenerator;

impl HttpGenerator {
    /// Create a new HTTP traffic generator.
    pub fn new() -> Self {
        Self
    }

    /// Pick an HTTP method using weighted distribution.
    fn pick_method(rng: &mut (impl RngCore + CryptoRng)) -> &'static str {
        let roll = Uniform::new_inclusive(0u32, 99).sample(rng);
        match roll {
            0..=79 => "GET",
            80..=94 => "POST",
            95..=97 => "PUT",
            _ => "DELETE",
        }
    }

    /// Pick an HTTP status code using weighted distribution.
    fn pick_status_code(rng: &mut (impl RngCore + CryptoRng)) -> u16 {
        let roll = Uniform::new_inclusive(0u32, 99).sample(rng);
        match roll {
            0..=69 => 200,
            70..=74 => 301,
            75..=79 => 302,
            80..=89 => 304,
            90..=94 => 404,
            95..=96 => 500,
            // Remaining 3% — assorted realistic codes
            97 => 403,
            98 => 503,
            _ => 429,
        }
    }

    /// Build a realistic URL from domain + path pools.
    fn build_url(rng: &mut (impl RngCore + CryptoRng)) -> String {
        // SAFETY: DOMAINS and URL_PATHS are non-empty const slices.
        let domain = DOMAINS
            .choose(rng)
            .copied()
            .expect("DOMAINS is a non-empty const slice");
        let path = URL_PATHS
            .choose(rng)
            .copied()
            .expect("URL_PATHS is a non-empty const slice");
        format!("https://{domain}{path}")
    }

    /// Build request headers.
    fn build_request_headers(rng: &mut (impl RngCore + CryptoRng)) -> HashMap<String, String> {
        let mut h = HashMap::new();
        // SAFETY: every const pool below is non-empty by construction.
        h.insert(
            "User-Agent".into(),
            USER_AGENTS
                .choose(rng)
                .copied()
                .expect("USER_AGENTS is non-empty")
                .into(),
        );
        h.insert(
            "Accept".into(),
            ACCEPT_HEADERS
                .choose(rng)
                .copied()
                .expect("ACCEPT_HEADERS is non-empty")
                .into(),
        );
        h.insert(
            "Accept-Language".into(),
            ACCEPT_LANGUAGES
                .choose(rng)
                .copied()
                .expect("ACCEPT_LANGUAGES is non-empty")
                .into(),
        );
        h.insert("Accept-Encoding".into(), "gzip, deflate, br".into());
        h.insert("Connection".into(), "keep-alive".into());

        // Referer — present ~60% of the time
        if Uniform::new_inclusive(0u32, 9).sample(rng) < 6 {
            h.insert(
                "Referer".into(),
                REFERER_DOMAINS
                    .choose(rng)
                    .copied()
                    .expect("REFERER_DOMAINS is non-empty")
                    .into(),
            );
        }

        // Cookie — present ~70% of the time
        if Uniform::new_inclusive(0u32, 9).sample(rng) < 7 {
            let cookie_len = Uniform::new_inclusive(16usize, 128).sample(rng);
            let cookie_val: String = (0..cookie_len)
                .map(|_| {
                    let idx = Uniform::new_inclusive(0u32, 61).sample(rng) as u8;
                    match idx {
                        0..=25 => (b'a' + idx) as char,
                        26..=51 => (b'A' + idx - 26) as char,
                        _ => (b'0' + idx - 52) as char,
                    }
                })
                .collect();
            h.insert("Cookie".into(), format!("session_id={cookie_val}"));
        }

        h
    }

    /// Build response headers matching the chosen status code and content type.
    fn build_response_headers(
        content_type: &str,
        body_size: u64,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> HashMap<String, String> {
        let mut h = HashMap::new();
        h.insert("Content-Type".into(), content_type.into());
        h.insert("Content-Length".into(), body_size.to_string());
        h.insert(
            "Cache-Control".into(),
            CACHE_CONTROL_VALUES
                .choose(rng)
                .copied()
                .expect("CACHE_CONTROL_VALUES is non-empty")
                .into(),
        );
        h.insert("Server".into(), "cloudflare".into());

        // Set-Cookie — present ~40% of the time
        if Uniform::new_inclusive(0u32, 9).sample(rng) < 4 {
            let cookie_names = ["_ga", "_gid", "csrf_token", "pref", "lang"];
            // SAFETY: literal array is non-empty.
            let name = cookie_names
                .choose(rng)
                .copied()
                .expect("cookie_names array literal is non-empty");
            let val_len = Uniform::new_inclusive(8usize, 32).sample(rng);
            let val: String = (0..val_len)
                .map(|_| {
                    let idx = Uniform::new_inclusive(0u32, 35).sample(rng) as u8;
                    match idx {
                        0..=25 => (b'a' + idx) as char,
                        _ => (b'0' + idx - 26) as char,
                    }
                })
                .collect();
            h.insert(
                "Set-Cookie".into(),
                format!("{name}={val}; Path=/; HttpOnly; Secure"),
            );
        }

        h
    }

    /// Generate realistic timing values for an HTTPS request.
    fn build_timing(body_size: u64, rng: &mut (impl RngCore + CryptoRng)) -> HttpTiming {
        // DNS — often cached (0-2ms), sometimes a real lookup (5-100ms)
        let dns_lookup_ms = if Uniform::new_inclusive(0u32, 4).sample(rng) < 3 {
            Uniform::new_inclusive(0u32, 2).sample(rng)
        } else {
            Uniform::new_inclusive(5u32, 100).sample(rng)
        };

        // TCP connect — typically 5-50ms
        let tcp_connect_ms = Uniform::new_inclusive(5u32, 50).sample(rng);

        // TLS handshake — 10-80ms for TLS 1.3
        let tls_handshake_ms = Uniform::new_inclusive(10u32, 80).sample(rng);

        // TTFB — server processing, 20-500ms for typical sites
        let ttfb_ms = Uniform::new_inclusive(20u32, 500).sample(rng);

        // Content transfer — proportional to body size, minimum 1ms
        let transfer_base = (body_size / 100_000) as u32; // ~100KB/ms baseline
        let content_transfer_ms =
            transfer_base + Uniform::new_inclusive(1u32, 50).sample(rng);

        HttpTiming {
            dns_lookup_ms,
            tcp_connect_ms,
            tls_handshake_ms,
            ttfb_ms,
            content_transfer_ms,
        }
    }
}

impl Default for HttpGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for HttpGenerator {
    fn generate(
        &self,
        _profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        let method = Self::pick_method(rng);
        let url = Self::build_url(rng);
        let status_code = Self::pick_status_code(rng);

        // Pick content type and matching body size.
        // SAFETY: CONTENT_TYPES is non-empty by construction.
        let (content_type, min_size, max_size) = CONTENT_TYPES
            .choose(rng)
            .expect("CONTENT_TYPES is a non-empty const slice");
        let body_size_bytes = Uniform::new_inclusive(*min_size, *max_size).sample(rng);

        // For 304 Not Modified, body is empty
        let body_size_bytes = if status_code == 304 { 0 } else { body_size_bytes };

        let request_headers = Self::build_request_headers(rng);
        let response_headers =
            Self::build_response_headers(content_type, body_size_bytes, rng);
        let timing = Self::build_timing(body_size_bytes, rng);

        let jitter = Uniform::new_inclusive(0i64, 300).sample(rng);
        let timestamp = context.now - Duration::seconds(jitter);

        let estimated_size = (url.len() as u64) + body_size_bytes + 512; // headers overhead
        let meta = ArtifactMetadata::new(
            DataCategory::Network,
            timestamp,
            timestamp,
            estimated_size,
        )?;

        let entry = HttpEntry {
            meta,
            method: method.to_string(),
            url,
            status_code,
            request_headers,
            response_headers,
            timing,
            body_size_bytes,
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

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_http_entry() {
        let g = HttpGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);
        let a = g.generate(&p, &c, &mut r).unwrap();
        a.validate_plausibility().unwrap();
        let b = a.to_bytes().unwrap();
        let e: HttpEntry = serde_json::from_slice(&b).unwrap();
        assert!(!e.url.is_empty());
        assert!(!e.method.is_empty());
        assert!((100..=599).contains(&e.status_code));
        assert!(e.request_headers.contains_key("User-Agent"));
        assert!(e.response_headers.contains_key("Content-Type"));
    }

    #[test]
    fn test_1000_http_entries_valid() {
        let g = HttpGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..1000 {
            let mut r = seeded_rng(s);
            g.generate(&p, &c, &mut r)
                .unwrap()
                .validate_plausibility()
                .unwrap();
        }
    }

    #[test]
    fn test_status_code_distribution() {
        let g = HttpGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let n = 10_000u32;
        let mut count_200 = 0u32;
        let mut count_redirect = 0u32;
        let mut count_304 = 0u32;
        let mut count_404 = 0u32;
        let mut count_500 = 0u32;

        for s in 0..n {
            let mut r = seeded_rng(u64::from(s));
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: HttpEntry = serde_json::from_slice(&b).unwrap();
            match e.status_code {
                200 => count_200 += 1,
                301 | 302 => count_redirect += 1,
                304 => count_304 += 1,
                404 => count_404 += 1,
                500 => count_500 += 1,
                _ => {}
            }
        }

        // Allow generous margins (±50% of target) for statistical variation
        let pct = |c: u32| (c as f64 / n as f64) * 100.0;
        assert!(
            pct(count_200) > 50.0 && pct(count_200) < 90.0,
            "200s should be ~70%, got {:.1}%",
            pct(count_200)
        );
        assert!(
            pct(count_redirect) > 3.0 && pct(count_redirect) < 20.0,
            "redirects should be ~10%, got {:.1}%",
            pct(count_redirect)
        );
        assert!(
            pct(count_304) > 3.0 && pct(count_304) < 20.0,
            "304s should be ~10%, got {:.1}%",
            pct(count_304)
        );
        assert!(
            pct(count_404) > 1.0 && pct(count_404) < 12.0,
            "404s should be ~5%, got {:.1}%",
            pct(count_404)
        );
        assert!(
            pct(count_500) > 0.5 && pct(count_500) < 6.0,
            "500s should be ~2%, got {:.1}%",
            pct(count_500)
        );
    }

    #[test]
    fn test_timing_values_positive() {
        let g = HttpGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..500 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: HttpEntry = serde_json::from_slice(&b).unwrap();
            // TCP, TLS, TTFB, and transfer should all be > 0
            assert!(e.timing.tcp_connect_ms > 0, "tcp_connect_ms should be positive");
            assert!(e.timing.tls_handshake_ms > 0, "tls_handshake_ms should be positive");
            assert!(e.timing.ttfb_ms > 0, "ttfb_ms should be positive");
            assert!(e.timing.content_transfer_ms > 0, "content_transfer_ms should be positive");
            assert!(e.timing.total_ms() > 0, "total timing should be positive");
            assert!(
                e.timing.total_ms() <= 60_000,
                "total timing should be under 60s, got {}ms",
                e.timing.total_ms()
            );
        }
    }

    #[test]
    fn test_method_distribution() {
        let g = HttpGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let n = 5_000u32;
        let mut get_count = 0u32;
        let mut post_count = 0u32;

        for s in 0..n {
            let mut r = seeded_rng(u64::from(s));
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: HttpEntry = serde_json::from_slice(&b).unwrap();
            match e.method.as_str() {
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
            pct(post_count) > 5.0 && pct(post_count) < 30.0,
            "POST should be ~15%, got {:.1}%",
            pct(post_count)
        );
    }

    #[test]
    fn test_304_has_zero_body_size() {
        let g = HttpGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut found_304 = false;
        for s in 0..5000 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: HttpEntry = serde_json::from_slice(&b).unwrap();
            if e.status_code == 304 {
                assert_eq!(e.body_size_bytes, 0, "304 responses should have zero body");
                found_304 = true;
            }
        }
        assert!(found_304, "should generate at least one 304 in 5000 entries");
    }
}
