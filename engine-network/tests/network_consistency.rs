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
use engine_network::dns::{DnsQuery, DnsQueryGenerator};
use engine_network::http::{HttpEntry, HttpGenerator};
use engine_network::http_timing::{HttpTiming, HttpTimingGenerator};
use engine_network::tls::{TlsEntry, TlsGenerator};
use engine_network::tls_fingerprint::{TlsFingerprint, TlsFingerprintGenerator};

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

/// Generate N DNS query entries.
fn make_dns(n: usize, profile: &UserProfile, ctx: &GenerationContext, seed: u64) -> Vec<DnsQuery> {
    let dns_gen = DnsQueryGenerator::new();
    let mut rng = seeded_rng(seed);
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let artifact = dns_gen.generate(profile, ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: DnsQuery = serde_json::from_slice(&bytes).unwrap();
        entries.push(entry);
    }
    entries
}

/// Generate N HTTP entries (full detail).
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

/// Generate N HTTP timing entries.
fn make_http_timing(
    n: usize,
    profile: &UserProfile,
    ctx: &GenerationContext,
    seed: u64,
) -> Vec<HttpTiming> {
    let http_timing_gen = HttpTimingGenerator::new();
    let mut rng = seeded_rng(seed);
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let artifact = http_timing_gen.generate(profile, ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: HttpTiming = serde_json::from_slice(&bytes).unwrap();
        entries.push(entry);
    }
    entries
}

/// Generate N TLS entries (old-style with JA4).
fn make_tls(n: usize, profile: &UserProfile, ctx: &GenerationContext, seed: u64) -> Vec<TlsEntry> {
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

/// Generate N TLS fingerprint entries.
fn make_tls_fingerprint(
    n: usize,
    profile: &UserProfile,
    ctx: &GenerationContext,
    seed: u64,
) -> Vec<TlsFingerprint> {
    let tls_fp_gen = TlsFingerprintGenerator::new();
    let mut rng = seeded_rng(seed);
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let artifact = tls_fp_gen.generate(profile, ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: TlsFingerprint = serde_json::from_slice(&bytes).unwrap();
        entries.push(entry);
    }
    entries
}

// ============================================================================
// Test 1: HTTP requests should have corresponding DNS lookups for their domains
// ============================================================================

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
    let http_hosts: HashSet<String> = http_entries.iter().map(|e| host_from_url(&e.url)).collect();

    let mut matched = 0u32;
    for host in &http_hosts {
        let bare = host.strip_prefix("www.").unwrap_or(host);
        let has_dns = dns_domains.contains(host)
            || dns_domains.contains(bare)
            || dns_domains
                .iter()
                .any(|d: &String| d.contains(bare) || bare.contains(d.as_str()));
        if has_dns {
            matched += 1;
        }
    }

    let coverage_pct = if http_hosts.is_empty() {
        0.0
    } else {
        (matched as f64 / http_hosts.len() as f64) * 100.0
    };

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

#[test]
fn test_https_requests_have_tls_handshakes() {
    let profile = shared_profile();
    let ctx = shared_context();

    let http_entries = make_http(200, &profile, &ctx, 77);
    let tls_entries = make_tls(300, &profile, &ctx, 77);

    // All HTTP entries use https:// scheme
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
    let https_hosts: HashSet<String> = http_entries.iter().map(|e| host_from_url(&e.url)).collect();

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

    assert!(
        coverage_pct > 50.0,
        "HTTPS hosts should have TLS handshake coverage >50%: got {coverage_pct:.1}% \
         ({matched}/{} HTTPS hosts, {} TLS SNI domains)",
        https_hosts.len(),
        tls_domains.len(),
    );
}

// ============================================================================
// Test 3: TLS fingerprint JA3 hashes are 32 hex chars and deterministic
// ============================================================================

#[test]
fn test_tls_fingerprint_ja3_format() {
    let profile = shared_profile();
    let ctx = shared_context();

    let tls_entries = make_tls_fingerprint(1000, &profile, &ctx, 99);

    let mut unique_ja3: HashSet<String> = HashSet::new();
    for (i, entry) in tls_entries.iter().enumerate() {
        assert_eq!(
            entry.ja3_hash.len(),
            32,
            "entry {i}: JA3 hash must be 32 hex chars, got '{}'",
            entry.ja3_hash,
        );
        assert!(
            entry.ja3_hash.chars().all(|c| c.is_ascii_hexdigit()),
            "entry {i}: JA3 hash must be hex, got '{}'",
            entry.ja3_hash,
        );
        unique_ja3.insert(entry.ja3_hash.clone());
    }

    // Should see multiple browser profiles
    assert!(
        unique_ja3.len() >= 3,
        "TLS fingerprints should use at least 3 different browser profiles, \
         got {}: {:?}",
        unique_ja3.len(),
        unique_ja3,
    );
}

// ============================================================================
// Test 4: HTTP timing phase ordering: dns < tcp < tls < ttfb < total
// ============================================================================

#[test]
fn test_http_timing_phase_ordering() {
    let profile = shared_profile();
    let ctx = shared_context();

    let http_entries = make_http(1000, &profile, &ctx, 55);

    for (i, entry) in http_entries.iter().enumerate() {
        let t = &entry.timing;

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

        assert_eq!(
            t.total_ms(),
            total,
            "entry {i}: total_ms() disagrees with component sum",
        );

        assert!(t.tcp_connect_ms > 0, "entry {i}: TCP connect is 0");
        assert!(t.tls_handshake_ms > 0, "entry {i}: TLS handshake is 0");
        assert!(t.ttfb_ms > 0, "entry {i}: TTFB is 0");
        assert!(
            t.content_transfer_ms > 0,
            "entry {i}: content transfer is 0"
        );
    }
}

// ============================================================================
// Test 5: HttpTiming response times follow log-normal distribution
// ============================================================================

#[test]
fn test_http_timing_response_times_skewed() {
    let profile = shared_profile();
    let ctx = shared_context();

    let entries = make_http_timing(2000, &profile, &ctx, 88);
    let mut times: Vec<u32> = entries.iter().map(|e| e.response_time_ms).collect();
    times.sort();

    let median = times[times.len() / 2];
    let mean = times.iter().map(|&t| t as f64).sum::<f64>() / times.len() as f64;

    // Log-normal: mean > median (right-skewed)
    assert!(
        mean > median as f64,
        "mean ({mean:.1}ms) should exceed median ({median}ms) for log-normal distribution",
    );

    // Median should be fast (under 300ms)
    assert!(
        median < 300,
        "median response time should be <300ms, got {median}ms",
    );
}

// ============================================================================
// Test 6: HTTP full detail -- Referer URLs should be valid HTTPS
// ============================================================================

#[test]
fn test_http_referer_urls_are_valid_https() {
    let profile = shared_profile();
    let ctx = shared_context();

    let http_entries = make_http(1000, &profile, &ctx, 33);

    let mut referer_count = 0u32;
    for (i, entry) in http_entries.iter().enumerate() {
        if let Some(referer) = entry.request_headers.get("Referer") {
            referer_count += 1;

            assert!(
                referer.starts_with("https://"),
                "entry {i}: Referer must be HTTPS, got '{referer}'",
            );

            let after_scheme = referer.strip_prefix("https://").unwrap();
            let host = after_scheme.split('/').next().unwrap_or("");
            assert!(
                !host.is_empty() && host.contains('.'),
                "entry {i}: Referer has invalid host: '{host}' (from '{referer}')",
            );
        }
    }

    assert!(
        referer_count > 300,
        "too few Referer headers: {referer_count}/1000 (expected ~600)",
    );
}

// ============================================================================
// Test 7: DNS latency values are plausible
// ============================================================================

#[test]
fn test_dns_latency_plausible() {
    let profile = shared_profile();
    let ctx = shared_context();

    let dns_entries = make_dns(1000, &profile, &ctx, 44);

    let mut fast_count = 0u32;
    let mut slow_count = 0u32;

    for entry in &dns_entries {
        assert!(
            entry.latency_ms <= 5000,
            "DNS latency {}ms exceeds 5s limit for domain '{}'",
            entry.latency_ms,
            entry.domain,
        );
        if entry.latency_ms <= 3 {
            fast_count += 1;
        } else {
            slow_count += 1;
        }
    }

    // Both fast (cached) and slow (recursive) queries should be present
    assert!(fast_count > 0, "no fast DNS queries found in 1000 samples");
    assert!(slow_count > 0, "no slow DNS queries found in 1000 samples");
}

// ============================================================================
// Test 8: All timestamps across DNS/HTTP/TLS should be UTC and same window
// ============================================================================

#[test]
fn test_all_timestamps_utc_and_same_window() {
    let profile = shared_profile();
    let ctx = shared_context();

    let dns_entries = make_dns(200, &profile, &ctx, 66);
    let http_entries = make_http_timing(200, &profile, &ctx, 66);
    let tls_entries = make_tls_fingerprint(200, &profile, &ctx, 66);

    // Verify all DNS timestamps are UTC
    for entry in &dns_entries {
        assert_eq!(
            entry.timestamp.timezone(),
            Utc,
            "DNS timestamp has non-UTC timezone: {:?}",
            entry.timestamp,
        );
    }

    // Verify all HTTP timing timestamps are UTC
    for entry in &http_entries {
        assert_eq!(
            entry.timestamp.timezone(),
            Utc,
            "HTTP timing timestamp has non-UTC timezone: {:?}",
            entry.timestamp,
        );
    }

    // Verify all TLS fingerprint timestamps are UTC
    for entry in &tls_entries {
        assert_eq!(
            entry.timestamp.timezone(),
            Utc,
            "TLS fingerprint timestamp has non-UTC timezone: {:?}",
            entry.timestamp,
        );
    }

    // All timestamps should fall within [context.now - 601s, context.now].
    // DNS infrastructure queries use up to 600s jitter.
    let now_ts = ctx.now.timestamp();
    let max_jitter = 601i64;

    let all_timestamps: Vec<(&str, i64)> = dns_entries
        .iter()
        .map(|e| ("DNS", e.timestamp.timestamp()))
        .chain(
            http_entries
                .iter()
                .map(|e| ("HTTP", e.timestamp.timestamp())),
        )
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

    // Cross-artifact window check
    let min_ts = all_timestamps.iter().map(|(_, ts)| *ts).min().unwrap();
    let max_ts = all_timestamps.iter().map(|(_, ts)| *ts).max().unwrap();
    let span = max_ts - min_ts;

    assert!(
        span <= max_jitter,
        "cross-artifact timestamp span ({span}s) exceeds max jitter window ({max_jitter}s) \
         -- generators may be using different time bases",
    );
}

// ============================================================================
// Test 9: Status code 304 must have zero body size (full HTTP generator)
// ============================================================================

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

    assert!(
        found_304,
        "no 304 responses found in 5000 HTTP entries -- distribution is broken",
    );
}

// ============================================================================
// Test 10: TLS fingerprint extensions include server_name
// ============================================================================

#[test]
fn test_tls_fingerprint_has_sni_extension() {
    let profile = shared_profile();
    let ctx = shared_context();

    let entries = make_tls_fingerprint(200, &profile, &ctx, 111);

    for (i, entry) in entries.iter().enumerate() {
        assert!(
            entry.extensions.contains(&"server_name".to_string()),
            "entry {i}: TLS fingerprint must include server_name extension",
        );
    }
}
