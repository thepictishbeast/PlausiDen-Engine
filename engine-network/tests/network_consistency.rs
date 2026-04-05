//! Cross-artifact consistency tests for HTTP, TLS, and DNS generators.
//!
//! Forensic analysts cross-reference network artifacts: every HTTP request
//! implies a prior DNS lookup; every HTTPS connection implies a TLS handshake;
//! timing phases must obey physical ordering. Any inconsistency between
//! generators is a synthetic data tell.

use std::collections::HashSet;

use chrono::Utc;
use engine_core::entropy::seeded_rng;
use engine_core::profile::UserProfile;
use engine_core::traits::{DataGenerator, GenerationContext};
use engine_network::dns::{DnsEntry, DnsGenerator};
use engine_network::http::{HttpEntry, HttpGenerator};
use engine_network::tls::{
    TlsEntry, TlsGenerator, KNOWN_JA3_CHROME_120, KNOWN_JA3_CURL_WGET,
    KNOWN_JA3_FIREFOX_121, KNOWN_JA3_SAFARI_17,
};

// ============================================================================
// Shared helpers
// ============================================================================

fn shared_profile() -> UserProfile {
    UserProfile::default()
}

fn shared_context() -> GenerationContext {
    GenerationContext::new()
}

/// Extract the host from a full URL, stripping scheme and path.
fn host_from_url(url: &str) -> String {
    let stripped = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    stripped
        .split('/')
        .next()
        .unwrap_or(stripped)
        .to_lowercase()
}

/// Generate N DNS entries.
fn make_dns(
    n: usize,
    profile: &UserProfile,
    ctx: &GenerationContext,
    seed: u64,
) -> Vec<DnsEntry> {
    let dns_gen = DnsGenerator::new();
    let mut rng = seeded_rng(seed);
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let artifact = dns_gen.generate(profile, ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: DnsEntry = serde_json::from_slice(&bytes).unwrap();
        entries.push(entry);
    }
    entries
}

/// Generate N HTTP entries.
fn make_http(
    n: usize,
    profile: &UserProfile,
    ctx: &GenerationContext,
    seed: u64,
) -> Vec<HttpEntry> {
    let http_gen = HttpGenerator::new();
    let mut rng = seeded_rng(seed);
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let artifact = http_gen.generate(profile, ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: HttpEntry = serde_json::from_slice(&bytes).unwrap();
        entries.push(entry);
    }
    entries
}

/// Generate N TLS entries.
fn make_tls(
    n: usize,
    profile: &UserProfile,
    ctx: &GenerationContext,
    seed: u64,
) -> Vec<TlsEntry> {
    let tls_gen = TlsGenerator::new();
    let mut rng = seeded_rng(seed);
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let artifact = tls_gen.generate(profile, ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: TlsEntry = serde_json::from_slice(&bytes).unwrap();
        entries.push(entry);
    }
    entries
}

// ============================================================================
// Test 1: HTTP requests should have corresponding DNS lookups for their domains
// ============================================================================
//
// Every HTTP request implies a prior DNS resolution for its domain. Both
// generators draw from overlapping domain pools, so the set of HTTP
// request domains should substantially overlap with the DNS domain pool.

#[test]
fn test_http_domains_have_dns_lookups() {
    let profile = shared_profile();
    let ctx = shared_context();

    let http_entries = make_http(200, &profile, &ctx, 42);
    let dns_entries = make_dns(500, &profile, &ctx, 42);

    // Collect all DNS domains (with and without www. prefix)
    let dns_domains: HashSet<String> = dns_entries
        .iter()
        .flat_map(|e| {
            let d = e.domain.to_lowercase();
            let stripped = d.strip_prefix("www.").unwrap_or(&d).to_string();
            vec![d, stripped]
        })
        .collect();

    // Check how many HTTP request hosts have a matching DNS lookup
    let http_hosts: HashSet<String> = http_entries
        .iter()
        .map(|e| host_from_url(&e.url))
        .collect();

    let mut matched = 0u32;
    for host in &http_hosts {
        let bare = host.strip_prefix("www.").unwrap_or(host);
        let has_dns = dns_domains.contains(host)
            || dns_domains.contains(bare)
            || dns_domains.iter().any(|d| d.contains(bare) || bare.contains(d.as_str()));
        if has_dns {
            matched += 1;
        }
    }

    let coverage_pct = if http_hosts.is_empty() {
        0.0
    } else {
        (matched as f64 / http_hosts.len() as f64) * 100.0
    };

    // HTTP uses DOMAINS (20 entries) and DNS uses browsing_domains() (same 20)
    // plus infrastructure/CDN/analytics. Overlap should be significant.
    assert!(
        coverage_pct > 40.0,
        "HTTP domains should have DNS coverage >40%: got {coverage_pct:.1}% \
         ({matched}/{} HTTP hosts, {} DNS domains)",
        http_hosts.len(),
        dns_domains.len(),
    );
}

// ============================================================================
// Test 2: HTTPS requests should have corresponding TLS handshakes
// ============================================================================
//
// Every HTTPS URL implies a TLS handshake to that server. The TLS
// generator's SNI domain pool should overlap with HTTP's domain pool.

#[test]
fn test_https_requests_have_tls_handshakes() {
    let profile = shared_profile();
    let ctx = shared_context();

    let http_entries = make_http(200, &profile, &ctx, 77);
    let tls_entries = make_tls(300, &profile, &ctx, 77);

    // All HTTP entries use https:// scheme (verified by build_url)
    for entry in &http_entries {
        assert!(
            entry.url.starts_with("https://"),
            "HTTP generator should produce HTTPS URLs: {}",
            entry.url,
        );
    }

    // Collect TLS SNI domains
    let tls_domains: HashSet<String> = tls_entries
        .iter()
        .map(|e| e.server_name.to_lowercase())
        .collect();

    // Check overlap between HTTPS request hosts and TLS SNI domains
    let https_hosts: HashSet<String> = http_entries
        .iter()
        .map(|e| host_from_url(&e.url))
        .collect();

    let mut matched = 0u32;
    for host in &https_hosts {
        if tls_domains.contains(host) {
            matched += 1;
        }
    }

    let coverage_pct = if https_hosts.is_empty() {
        0.0
    } else {
        (matched as f64 / https_hosts.len() as f64) * 100.0
    };

    // HTTP DOMAINS and TLS SNI_DOMAINS share the same 20 browsing domains.
    // TLS also includes CDN/API/auth domains (6 extra). Coverage should be high.
    assert!(
        coverage_pct > 50.0,
        "HTTPS hosts should have TLS handshake coverage >50%: got {coverage_pct:.1}% \
         ({matched}/{} HTTPS hosts, {} TLS SNI domains)",
        https_hosts.len(),
        tls_domains.len(),
    );
}

// ============================================================================
// Test 3: TLS JA3 hashes should match known browser profiles (not random)
// ============================================================================
//
// Every JA3 hash the TLS generator produces must be one of the four
// known browser profiles. A random or unknown JA3 hash would immediately
// flag the traffic as synthetic in forensic analysis.

#[test]
fn test_tls_ja3_matches_known_profiles() {
    let profile = shared_profile();
    let ctx = shared_context();

    let known_ja3: HashSet<&str> = [
        KNOWN_JA3_CHROME_120,
        KNOWN_JA3_FIREFOX_121,
        KNOWN_JA3_SAFARI_17,
        KNOWN_JA3_CURL_WGET,
    ]
    .into_iter()
    .collect();

    let tls_entries = make_tls(1000, &profile, &ctx, 99);

    for (i, entry) in tls_entries.iter().enumerate() {
        assert!(
            known_ja3.contains(entry.ja3_hash.as_str()),
            "TLS entry {i} has unknown JA3 hash '{}' for server '{}' \
             -- all hashes must match a known browser profile",
            entry.ja3_hash,
            entry.server_name,
        );
    }

    // Additionally, verify that we see multiple browser profiles
    // (not all traffic from one browser)
    let unique_ja3: HashSet<&str> = tls_entries
        .iter()
        .map(|e| e.ja3_hash.as_str())
        .collect();
    assert!(
        unique_ja3.len() >= 3,
        "TLS entries should use at least 3 different browser profiles, \
         got {}: {:?}",
        unique_ja3.len(),
        unique_ja3,
    );
}

// ============================================================================
// Test 4: HTTP timing ordering: DNS < TCP < TLS < TTFB < total
// ============================================================================
//
// The HTTP request lifecycle has a strict phase ordering. Cumulative
// sums must be monotonically increasing:
//   dns_lookup <= dns+tcp <= dns+tcp+tls <= dns+tcp+tls+ttfb <= total

#[test]
fn test_http_timing_phase_ordering() {
    let profile = shared_profile();
    let ctx = shared_context();

    let http_entries = make_http(1000, &profile, &ctx, 55);

    for (i, entry) in http_entries.iter().enumerate() {
        let t = &entry.timing;

        // Cumulative phase sums must be monotonically non-decreasing
        let after_dns = t.dns_lookup_ms;
        let after_tcp = after_dns + t.tcp_connect_ms;
        let after_tls = after_tcp + t.tls_handshake_ms;
        let after_ttfb = after_tls + t.ttfb_ms;
        let total = after_ttfb + t.content_transfer_ms;

        assert!(
            after_dns <= after_tcp,
            "entry {i}: DNS ({after_dns}ms) > DNS+TCP ({after_tcp}ms)",
        );
        assert!(
            after_tcp <= after_tls,
            "entry {i}: DNS+TCP ({after_tcp}ms) > DNS+TCP+TLS ({after_tls}ms)",
        );
        assert!(
            after_tls <= after_ttfb,
            "entry {i}: DNS+TCP+TLS ({after_tls}ms) > DNS+TCP+TLS+TTFB ({after_ttfb}ms)",
        );
        assert!(
            after_ttfb <= total,
            "entry {i}: pre-transfer ({after_ttfb}ms) > total ({total}ms)",
        );

        // total_ms() helper must agree with manual sum
        assert_eq!(
            t.total_ms(),
            total,
            "entry {i}: total_ms() disagrees with component sum",
        );

        // Each non-DNS phase must be > 0 (TCP, TLS, TTFB, transfer are always positive)
        assert!(t.tcp_connect_ms > 0, "entry {i}: TCP connect is 0");
        assert!(t.tls_handshake_ms > 0, "entry {i}: TLS handshake is 0");
        assert!(t.ttfb_ms > 0, "entry {i}: TTFB is 0");
        assert!(t.content_transfer_ms > 0, "entry {i}: content transfer is 0");
    }
}

// ============================================================================
// Test 5: Status code 304 must have zero body size
// ============================================================================
//
// HTTP 304 Not Modified means the server says "use your cache." The
// response body MUST be empty per RFC 7232. Any non-zero body on a 304
// is a protocol violation that forensic tools would flag.

#[test]
fn test_status_304_has_zero_body_size() {
    let profile = shared_profile();
    let ctx = shared_context();

    let http_entries = make_http(5000, &profile, &ctx, 88);

    let mut found_304 = false;
    for (i, entry) in http_entries.iter().enumerate() {
        if entry.status_code == 304 {
            found_304 = true;
            assert_eq!(
                entry.body_size_bytes, 0,
                "entry {i}: HTTP 304 must have zero body size, got {} bytes",
                entry.body_size_bytes,
            );
        }
    }

    // With ~10% 304 rate and 5000 samples, we must find at least one
    assert!(
        found_304,
        "no 304 responses found in 5000 HTTP entries -- distribution is broken",
    );
}

// ============================================================================
// Test 6: HTTP Referer URLs should be valid HTTPS URLs
// ============================================================================
//
// The Referer header (when present) must be a well-formed HTTPS URL.
// An invalid or HTTP-only referrer on an HTTPS request would be a
// forensic anomaly (browsers strip referrers when downgrading to HTTP).

#[test]
fn test_http_referer_urls_are_valid_https() {
    let profile = shared_profile();
    let ctx = shared_context();

    let http_entries = make_http(1000, &profile, &ctx, 33);

    let mut referer_count = 0u32;
    for (i, entry) in http_entries.iter().enumerate() {
        if let Some(referer) = entry.request_headers.get("Referer") {
            referer_count += 1;

            // Must start with https://
            assert!(
                referer.starts_with("https://"),
                "entry {i}: Referer must be HTTPS, got '{referer}'",
            );

            // Must have a valid host after the scheme
            let after_scheme = referer.strip_prefix("https://").unwrap();
            let host = after_scheme.split('/').next().unwrap_or("");
            assert!(
                !host.is_empty() && host.contains('.'),
                "entry {i}: Referer has invalid host: '{host}' (from '{referer}')",
            );
        }
    }

    // Referer is present ~60% of the time, so with 1000 entries we
    // should see a substantial number
    assert!(
        referer_count > 300,
        "too few Referer headers: {referer_count}/1000 (expected ~600)",
    );
}

// ============================================================================
// Test 7: DNS cache hits should have response_ms < 5ms
// ============================================================================
//
// Cached DNS responses come from the OS resolver cache, not the network.
// They must complete in under 5ms. Slow "cached" responses would be a
// dead giveaway of synthetic data.

#[test]
fn test_dns_cache_hits_are_fast() {
    let profile = shared_profile();
    let ctx = shared_context();

    let dns_entries = make_dns(1000, &profile, &ctx, 44);

    let mut cached_count = 0u32;
    let mut non_cached_count = 0u32;

    for (i, entry) in dns_entries.iter().enumerate() {
        if entry.cached {
            cached_count += 1;
            assert!(
                entry.response_ms <= 5,
                "entry {i}: cached DNS response must be <=5ms, \
                 got {}ms for domain '{}'",
                entry.response_ms,
                entry.domain,
            );
        } else {
            non_cached_count += 1;
            // Uncached responses should be >= 5ms (real network latency)
            assert!(
                entry.response_ms >= 5,
                "entry {i}: uncached DNS response must be >=5ms, \
                 got {}ms for domain '{}'",
                entry.response_ms,
                entry.domain,
            );
        }
    }

    // Both cached and non-cached entries should be present
    assert!(
        cached_count > 0,
        "no cached DNS entries found in 1000 samples",
    );
    assert!(
        non_cached_count > 0,
        "no non-cached DNS entries found in 1000 samples",
    );

    // Cache hit ratio should be roughly 60% per the generator
    let cache_pct = (cached_count as f64 / (cached_count + non_cached_count) as f64) * 100.0;
    assert!(
        cache_pct > 40.0 && cache_pct < 80.0,
        "DNS cache hit rate should be ~60%, got {cache_pct:.1}%",
    );
}

// ============================================================================
// Test 8: All timestamps across DNS/HTTP/TLS should be UTC and within
//         the same time window
// ============================================================================
//
// Mixed timezones within a single profile are an obvious synthetic data
// tell. All three generators must produce UTC timestamps. Additionally,
// since all share the same GenerationContext.now, their timestamps must
// fall within the same jitter window (0-300s before context.now).

#[test]
fn test_all_timestamps_utc_and_same_window() {
    let profile = shared_profile();
    let ctx = shared_context();

    let dns_entries = make_dns(200, &profile, &ctx, 66);
    let http_entries = make_http(200, &profile, &ctx, 66);
    let tls_entries = make_tls(200, &profile, &ctx, 66);

    // Verify all DNS timestamps are UTC
    for entry in &dns_entries {
        assert_eq!(
            entry.query_time.timezone(),
            Utc,
            "DNS query_time has non-UTC timezone: {:?}",
            entry.query_time,
        );
        assert_eq!(
            entry.meta.created_at.timezone(),
            Utc,
            "DNS meta.created_at has non-UTC timezone",
        );
    }

    // Verify all HTTP timestamps are UTC
    for entry in &http_entries {
        assert_eq!(
            entry.timestamp.timezone(),
            Utc,
            "HTTP timestamp has non-UTC timezone: {:?}",
            entry.timestamp,
        );
        assert_eq!(
            entry.meta.created_at.timezone(),
            Utc,
            "HTTP meta.created_at has non-UTC timezone",
        );
    }

    // Verify all TLS timestamps are UTC
    for entry in &tls_entries {
        assert_eq!(
            entry.timestamp.timezone(),
            Utc,
            "TLS timestamp has non-UTC timezone: {:?}",
            entry.timestamp,
        );
        assert_eq!(
            entry.meta.created_at.timezone(),
            Utc,
            "TLS meta.created_at has non-UTC timezone",
        );
    }

    // All timestamps should fall within [context.now - 301s, context.now].
    // Each generator applies jitter of Uniform(0, 300) seconds.
    let now_ts = ctx.now.timestamp();
    let max_jitter = 301i64; // 300s jitter + 1s tolerance

    let all_timestamps: Vec<(&str, i64)> = dns_entries
        .iter()
        .map(|e| ("DNS", e.query_time.timestamp()))
        .chain(http_entries.iter().map(|e| ("HTTP", e.timestamp.timestamp())))
        .chain(tls_entries.iter().map(|e| ("TLS", e.timestamp.timestamp())))
        .collect();

    for (source, ts) in &all_timestamps {
        assert!(
            *ts <= now_ts + 1,
            "{source} timestamp in the future: {ts} > {now_ts}",
        );
        assert!(
            now_ts - *ts <= max_jitter,
            "{source} timestamp too old: {ts} ({} seconds before now, max jitter is {max_jitter}s)",
            now_ts - ts,
        );
    }

    // Cross-artifact window check: the span of all timestamps should be
    // at most ~300s (the jitter range). A wider span would indicate
    // generators using different time bases.
    let min_ts = all_timestamps.iter().map(|(_, ts)| *ts).min().unwrap();
    let max_ts = all_timestamps.iter().map(|(_, ts)| *ts).max().unwrap();
    let span = max_ts - min_ts;

    assert!(
        span <= max_jitter,
        "cross-artifact timestamp span ({span}s) exceeds max jitter window ({max_jitter}s) \
         -- generators may be using different time bases",
    );
}
