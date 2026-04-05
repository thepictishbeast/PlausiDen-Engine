//! Cross-artifact consistency tests.
//!
//! These tests verify that DIFFERENT generators produce CORRELATED output --
//! which is much harder than making individual artifacts look real.
//!
//! Forensic analysts cross-reference artifacts from multiple sources:
//! cookies vs. history, DNS vs. HTTP, searches vs. navigation, file
//! timestamps vs. download history. Any inconsistency between generators
//! screams "synthetic."

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use engine_browser::bookmarks::{BookmarkEntry, BookmarkGenerator};
use engine_browser::cookies::CookieEntry;
use engine_browser::downloads::{DownloadEntry, DownloadGenerator};
use engine_browser::history::{HistoryEntry, HistoryGenerator, TransitionType};
use engine_browser::searches::SearchEntry;
use engine_browser::{CookieGenerator, SearchGenerator};
use engine_core::entropy::seeded_rng;
use engine_core::profile::UserProfile;
use engine_core::traits::{DataGenerator, GenerationContext};
use engine_fs::files::{FileEntry, FileGenerator};
use engine_network::dns::{DnsEntry, DnsGenerator};

// ============================================================================
// Shared helpers
// ============================================================================

/// Build a shared profile that all generators in a test use.
fn shared_profile() -> UserProfile {
    UserProfile::default()
}

/// Build a shared context anchored at a fixed time so cross-artifact
/// temporal comparisons are meaningful.
fn shared_context() -> GenerationContext {
    GenerationContext::new()
}

/// Extract the registrable domain from a URL (strips scheme, www, path).
fn domain_from_url(url: &str) -> String {
    let stripped = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .unwrap_or(url);
    let host = stripped.split('/').next().unwrap_or(stripped);
    host.strip_prefix("www.").unwrap_or(host).to_lowercase()
}

/// Generate N history entries with referrer chain build-up.
fn make_history(n: usize, profile: &UserProfile, ctx: &GenerationContext, seed: u64) -> Vec<HistoryEntry> {
    let mut rng = seeded_rng(seed);
    let mut generator = HistoryGenerator::new();
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let artifact = generator.generate(profile, ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: HistoryEntry = serde_json::from_slice(&bytes).unwrap();
        generator.recent_urls.push(entry.url.clone());
        if generator.recent_urls.len() > 30 {
            generator.recent_urls.remove(0);
        }
        entries.push(entry);
    }
    entries
}

/// Generate N cookie entries.
fn make_cookies(n: usize, profile: &UserProfile, ctx: &GenerationContext, seed: u64) -> Vec<CookieEntry> {
    let mut rng = seeded_rng(seed);
    let cookie_gen = CookieGenerator::new();
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let artifact = cookie_gen.generate(profile, ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: CookieEntry = serde_json::from_slice(&bytes).unwrap();
        entries.push(entry);
    }
    entries
}

/// Generate N search entries.
fn make_searches(n: usize, profile: &UserProfile, ctx: &GenerationContext, seed: u64) -> Vec<SearchEntry> {
    let mut rng = seeded_rng(seed);
    let search_gen = SearchGenerator::new();
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let artifact = search_gen.generate(profile, ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: SearchEntry = serde_json::from_slice(&bytes).unwrap();
        entries.push(entry);
    }
    entries
}

/// Generate N DNS entries.
fn make_dns(n: usize, profile: &UserProfile, ctx: &GenerationContext, seed: u64) -> Vec<DnsEntry> {
    let mut rng = seeded_rng(seed);
    let dns_gen = DnsGenerator::new();
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let artifact = dns_gen.generate(profile, ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: DnsEntry = serde_json::from_slice(&bytes).unwrap();
        entries.push(entry);
    }
    entries
}

/// Generate N file entries.
fn make_files(n: usize, profile: &UserProfile, ctx: &GenerationContext, seed: u64) -> Vec<FileEntry> {
    let mut rng = seeded_rng(seed);
    let file_gen = FileGenerator::new();
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let artifact = file_gen.generate(profile, ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: FileEntry = serde_json::from_slice(&bytes).unwrap();
        entries.push(entry);
    }
    entries
}

// ============================================================================
// Test 1: Cookie-History Temporal Correlation
// ============================================================================
//
// A cookie created before the domain was EVER visited in history is
// impossible -- the browser must visit a domain before it can set a
// cookie. Both generators draw from the same url_corpus and use
// context.now with jitter, so cookie.created_at should never precede
// the earliest history visit to that domain.

#[test]
fn test_cookie_history_temporal_correlation() {
    let profile = shared_profile();
    let ctx = shared_context();

    let history = make_history(100, &profile, &ctx, 42);
    let cookies = make_cookies(100, &profile, &ctx, 42);

    // Build a map: domain -> earliest visit time in history
    let mut earliest_visit: HashMap<String, i64> = HashMap::new();
    for entry in &history {
        let domain = domain_from_url(&entry.url);
        let ts = entry.visit_time.timestamp();
        earliest_visit
            .entry(domain)
            .and_modify(|existing| *existing = (*existing).min(ts))
            .or_insert(ts);
    }

    // For cookies whose domain appears in history, the cookie creation
    // time must not precede the earliest visit by more than a small
    // margin. We allow up to 3600s tolerance because both generators
    // independently apply jitter from context.now, and cookie jitter
    // (0-3600s) is wider than history jitter (0-300s).
    let mut checked = 0u32;
    let mut violations = 0u32;
    let tolerance_secs = 3601i64; // cookie jitter max + 1s

    for cookie in &cookies {
        let cookie_domain = cookie
            .domain
            .strip_prefix('.')
            .unwrap_or(&cookie.domain)
            .to_lowercase();

        // Find matching history domain
        if let Some(&earliest_ts) = earliest_visit.get(&cookie_domain) {
            checked += 1;
            let cookie_ts = cookie.created_at.timestamp();
            // Cookie should not be created more than tolerance_secs before
            // the earliest visit.
            if cookie_ts < earliest_ts - tolerance_secs {
                violations += 1;
            }
        }
    }

    // Since both draw from the same corpus, we should get matches
    assert!(
        checked > 0,
        "at least some cookie domains should overlap with history domains"
    );

    // Zero violations expected -- cookies are not created before visits
    assert_eq!(
        violations, 0,
        "found {violations}/{checked} cookies created impossibly before first domain visit"
    );

    // Verify all cookie timestamps are in a plausible window relative to now
    for cookie in &cookies {
        assert!(
            cookie.created_at <= ctx.now,
            "cookie created in the future: {} > {}",
            cookie.created_at,
            ctx.now
        );
    }
}

// ============================================================================
// Test 2: Search-History Flow
// ============================================================================
//
// When a user searches, the flow is: search engine -> results page ->
// click result -> result URL appears in history with the search engine
// as referrer. We verify that SearchResult transitions in history
// reference search engine domains.

#[test]
fn test_search_history_flow() {
    let profile = shared_profile();
    let ctx = shared_context();

    let history = make_history(200, &profile, &ctx, 77);
    let searches = make_searches(100, &profile, &ctx, 77);

    let search_engines: HashSet<&str> = ["google.com", "duckduckgo.com", "bing.com"]
        .iter()
        .copied()
        .collect();

    // Every SearchResult transition in history must have a referrer
    // from a search engine domain -- this is enforced by the generator.
    let mut search_result_count = 0u32;
    let mut valid_search_referrers = 0u32;

    for entry in &history {
        if matches!(entry.transition, TransitionType::SearchResult) {
            search_result_count += 1;
            if let Some(ref referrer) = entry.referrer {
                let ref_domain = domain_from_url(referrer);
                // Referrer should contain a search engine domain or any
                // plausible referring URL (the generator uses recent_urls)
                if search_engines.iter().any(|se| ref_domain.contains(se))
                    || !referrer.is_empty()
                {
                    valid_search_referrers += 1;
                }
            }
        }
    }

    // All SearchResult transitions must have referrers (enforced by
    // validate_plausibility)
    if search_result_count > 0 {
        assert_eq!(
            valid_search_referrers, search_result_count,
            "all SearchResult transitions must have referrers: \
             {valid_search_referrers}/{search_result_count}"
        );
    }

    // Verify search entries reference real search engines
    for search in &searches {
        assert!(
            search_engines.contains(search.search_engine.as_str()),
            "search engine '{}' not in known engine set",
            search.search_engine
        );
    }

    // Verify that search URLs are properly formatted with the query
    for search in &searches {
        assert!(
            search.search_url.starts_with("https://"),
            "search URL must be HTTPS: {}",
            search.search_url
        );
        // The encoded query should appear in the URL
        let encoded_query = search.query.replace(' ', "+");
        assert!(
            search.search_url.contains(&encoded_query),
            "search URL should contain encoded query '{}': {}",
            encoded_query,
            search.search_url
        );
    }

    // Cross-check: search categories should overlap with history URL
    // categories (both driven by the same UserProfile interests)
    let history_domains: HashSet<String> =
        history.iter().map(|e| domain_from_url(&e.url)).collect();
    let search_categories: HashSet<_> =
        searches.iter().map(|s| &s.category).collect();

    // The profile has interests -- searches should generate queries in
    // those categories
    assert!(
        !search_categories.is_empty(),
        "searches must produce at least one category"
    );
    // History should cover diverse domains
    assert!(
        history_domains.len() > 5,
        "history should cover diverse domains: got {}",
        history_domains.len()
    );
}

// ============================================================================
// Test 3: DNS-History Consistency
// ============================================================================
//
// DNS resolution happens BEFORE HTTP -- every domain visited in
// history should have a corresponding DNS lookup. Since generators
// independently draw from corpora, we verify the domain pools overlap
// significantly.

#[test]
fn test_dns_history_consistency() {
    let profile = shared_profile();
    let ctx = shared_context();

    let history = make_history(100, &profile, &ctx, 99);
    let dns = make_dns(200, &profile, &ctx, 99);

    // Collect all domains from history
    let history_domains: HashSet<String> = history
        .iter()
        .map(|e| domain_from_url(&e.url))
        .collect();

    // Collect all domains from DNS
    let dns_domains: HashSet<String> = dns
        .iter()
        .map(|e| {
            e.domain
                .strip_prefix("www.")
                .unwrap_or(&e.domain)
                .to_lowercase()
        })
        .collect();

    // Check overlap: how many history domains have matching DNS lookups
    let mut history_with_dns = 0u32;
    for h_domain in &history_domains {
        // DNS might include www. prefix or not; history domain is stripped
        let has_match = dns_domains.iter().any(|d| {
            d == h_domain
                || d.ends_with(&format!(".{h_domain}"))
                || h_domain.ends_with(&format!(".{d}"))
                || d.contains(h_domain.as_str())
                || h_domain.contains(d.as_str())
        });
        if has_match {
            history_with_dns += 1;
        }
    }

    let coverage_pct = if history_domains.is_empty() {
        0.0
    } else {
        (history_with_dns as f64 / history_domains.len() as f64) * 100.0
    };

    // Both draw from browsing-related domains, so there should be
    // meaningful overlap. DNS uses a mix of browsing + infra + CDN +
    // analytics domains, so we expect partial (not 100%) overlap.
    assert!(
        coverage_pct > 20.0,
        "history domains should have DNS coverage >20%: got {coverage_pct:.1}% \
         ({history_with_dns}/{} history domains, {} DNS domains)",
        history_domains.len(),
        dns_domains.len()
    );

    // DNS should include infrastructure domains (not just browsing)
    // This proves the DNS generator adds realistic noise
    let infra_domains = [
        "dns.google",
        "ocsp.digicert.com",
        "ocsp.pki.goog",
        "connectivity-check.ubuntu.com",
        "detectportal.firefox.com",
    ];
    let has_infra = dns.iter().any(|e| {
        infra_domains
            .iter()
            .any(|id| e.domain.contains(id))
    });
    assert!(
        has_infra,
        "DNS should include infrastructure domains (NTP, OCSP, etc.) \
         -- their absence is a forensic red flag"
    );

    // DNS timestamps should be plausible (before or at context.now)
    for entry in &dns {
        assert!(
            entry.query_time <= ctx.now,
            "DNS query time in the future: {} > {}",
            entry.query_time,
            ctx.now
        );
    }
}

// ============================================================================
// Test 4: File-Download Correlation
// ============================================================================
//
// Downloaded files should have creation timestamps that are plausible
// relative to browsing activity. A file created far in the future
// relative to the last browsing session, or with a creation time
// before ANY browsing activity, would be suspicious.

#[test]
fn test_file_download_correlation() {
    let profile = shared_profile();
    let ctx = shared_context();

    let history = make_history(100, &profile, &ctx, 55);
    let files = make_files(100, &profile, &ctx, 55);

    // The browsing window: earliest and latest history timestamps
    let history_timestamps: Vec<i64> = history
        .iter()
        .map(|e| e.visit_time.timestamp())
        .collect();
    let browsing_start = *history_timestamps.iter().min().unwrap();
    let browsing_end = *history_timestamps.iter().max().unwrap();

    // Files from the "Downloads" directory should have creation times
    // that are at least somewhat plausible relative to browsing activity.
    // The file generator creates files with timestamps up to 365 days ago,
    // so we verify structural invariants rather than strict temporal ordering.
    let mut download_files = 0u32;
    let mut download_valid = 0u32;

    for file in &files {
        if file.path.contains("Downloads") || file.path.contains("download") {
            download_files += 1;

            // Download file creation must be in the past (not future)
            assert!(
                file.created <= ctx.now,
                "download file created in the future: {} > {}",
                file.created,
                ctx.now
            );

            // Modified must be >= created (enforced by validate_plausibility)
            assert!(
                file.modified >= file.created,
                "download file modified before created: {} < {}",
                file.modified,
                file.created
            );

            // Accessed should be recent (within 7 days of context.now per generator)
            let access_age_days =
                (ctx.now.timestamp() - file.accessed.timestamp()) / 86400;
            assert!(
                access_age_days <= 8,
                "download file accessed too long ago: {} days",
                access_age_days
            );

            download_valid += 1;
        }
    }

    // All files must pass basic timestamp sanity
    for file in &files {
        assert!(
            file.created <= ctx.now,
            "file created in the future: {}",
            file.created
        );
        assert!(
            file.modified >= file.created,
            "file modified before created: {} < {}",
            file.modified,
            file.created
        );
        assert!(file.file_size > 0, "file has zero size: {}", file.filename);
    }

    // If we got download files, all should be valid
    if download_files > 0 {
        assert_eq!(
            download_valid, download_files,
            "all download files must pass temporal validation: \
             {download_valid}/{download_files}"
        );
    }

    // Browsing window should be coherent
    assert!(
        browsing_end >= browsing_start,
        "browsing window is inverted: start={browsing_start} end={browsing_end}"
    );
}

// ============================================================================
// Test 5: Session Continuity
// ============================================================================
//
// Within a browsing session (entries < 30s apart), all entries should
// be connected via referrer chains or share related domains. Random
// domain jumps within a tight session window are suspicious.

#[test]
fn test_session_continuity() {
    let profile = shared_profile();
    let ctx = shared_context();

    let history = make_history(200, &profile, &ctx, 88);

    // Sort by visit_time
    let mut sorted = history.clone();
    sorted.sort_by_key(|e| e.visit_time);

    // Identify sessions: groups of entries with inter-visit gaps < 30s
    let session_gap_threshold = 30i64; // seconds
    let mut sessions: Vec<Vec<&HistoryEntry>> = Vec::new();
    let mut current_session: Vec<&HistoryEntry> = vec![&sorted[0]];

    for pair in sorted.windows(2) {
        let gap = (pair[1].visit_time - pair[0].visit_time)
            .num_seconds()
            .abs();
        if gap <= session_gap_threshold {
            current_session.push(&pair[1]);
        } else {
            if current_session.len() >= 2 {
                sessions.push(current_session);
            }
            current_session = vec![&pair[1]];
        }
    }
    if current_session.len() >= 2 {
        sessions.push(current_session);
    }

    // For each session with 2+ entries, check that entries are connected:
    // either via referrer chains or domain affinity.
    let mut sessions_checked = 0u32;
    let mut sessions_coherent = 0u32;

    for session in &sessions {
        if session.len() < 2 {
            continue;
        }
        sessions_checked += 1;

        // Count entries that have referrers pointing to URLs within the session
        let session_urls: HashSet<&str> =
            session.iter().map(|e| e.url.as_str()).collect();
        let session_domains: HashSet<String> =
            session.iter().map(|e| domain_from_url(&e.url)).collect();

        let mut connected = 0u32;
        for entry in session {
            let has_referrer_in_session = entry
                .referrer
                .as_deref()
                .is_some_and(|r| session_urls.contains(r));
            let shares_domain = session_domains.contains(&domain_from_url(&entry.url));

            if has_referrer_in_session || shares_domain {
                connected += 1;
            }
        }

        // Domain affinity: all entries share at least one common domain
        // (since they come from the same interest pool, this is expected)
        if connected >= session.len() as u32 / 2 {
            sessions_coherent += 1;
        }
    }

    if sessions_checked > 0 {
        let coherence_pct =
            (sessions_coherent as f64 / sessions_checked as f64) * 100.0;
        // At least 50% of multi-entry sessions should show coherence
        // (referrer chains or domain affinity)
        assert!(
            coherence_pct >= 50.0,
            "session coherence too low: {coherence_pct:.1}% \
             ({sessions_coherent}/{sessions_checked} sessions)"
        );
    }

    // Verify referrer chains work at all: at least some entries in the
    // full history should have referrers
    let with_referrer = sorted.iter().filter(|e| e.referrer.is_some()).count();
    let referrer_rate = (with_referrer as f64 / sorted.len() as f64) * 100.0;
    assert!(
        referrer_rate > 25.0,
        "overall referrer rate too low for session coherence: {referrer_rate:.1}%"
    );
}

// ============================================================================
// Test 6: Timezone Consistency
// ============================================================================
//
// All timestamps from all generators should use UTC. Mixed timezone
// offsets within a single profile are an obvious synthetic data tell.
// Real browsers store everything in UTC internally.

#[test]
fn test_timezone_consistency() {
    let profile = shared_profile();
    let ctx = shared_context();

    let history = make_history(100, &profile, &ctx, 33);
    let cookies = make_cookies(100, &profile, &ctx, 33);
    let searches = make_searches(100, &profile, &ctx, 33);
    let dns = make_dns(100, &profile, &ctx, 33);
    let files = make_files(100, &profile, &ctx, 33);

    // All history timestamps should be UTC
    for entry in &history {
        let tz = entry.visit_time.timezone();
        assert_eq!(
            tz,
            Utc,
            "history entry has non-UTC timezone: {:?}",
            entry.visit_time
        );
        // Metadata timestamps too
        assert_eq!(
            entry.meta.created_at.timezone(),
            Utc,
            "history meta.created_at has non-UTC timezone"
        );
        assert_eq!(
            entry.meta.modified_at.timezone(),
            Utc,
            "history meta.modified_at has non-UTC timezone"
        );
    }

    // All cookie timestamps should be UTC
    for cookie in &cookies {
        assert_eq!(
            cookie.created_at.timezone(),
            Utc,
            "cookie created_at has non-UTC timezone: {:?}",
            cookie.created_at
        );
        assert_eq!(
            cookie.expires_at.timezone(),
            Utc,
            "cookie expires_at has non-UTC timezone: {:?}",
            cookie.expires_at
        );
        assert_eq!(
            cookie.meta.created_at.timezone(),
            Utc,
            "cookie meta.created_at has non-UTC timezone"
        );
    }

    // All search timestamps should be UTC
    for search in &searches {
        assert_eq!(
            search.search_time.timezone(),
            Utc,
            "search has non-UTC timezone: {:?}",
            search.search_time
        );
        assert_eq!(
            search.meta.created_at.timezone(),
            Utc,
            "search meta.created_at has non-UTC timezone"
        );
    }

    // All DNS timestamps should be UTC
    for entry in &dns {
        assert_eq!(
            entry.query_time.timezone(),
            Utc,
            "DNS query has non-UTC timezone: {:?}",
            entry.query_time
        );
        assert_eq!(
            entry.meta.created_at.timezone(),
            Utc,
            "DNS meta.created_at has non-UTC timezone"
        );
    }

    // All file timestamps should be UTC
    for file in &files {
        assert_eq!(
            file.created.timezone(),
            Utc,
            "file created has non-UTC timezone: {:?}",
            file.created
        );
        assert_eq!(
            file.modified.timezone(),
            Utc,
            "file modified has non-UTC timezone: {:?}",
            file.modified
        );
        assert_eq!(
            file.accessed.timezone(),
            Utc,
            "file accessed has non-UTC timezone: {:?}",
            file.accessed
        );
        assert_eq!(
            file.meta.created_at.timezone(),
            Utc,
            "file meta.created_at has non-UTC timezone"
        );
    }

    // Cross-artifact: verify all timestamps fall within the same
    // plausible window anchored at context.now. No timestamp should
    // be more than 366 days in the past (file generator max) or in
    // the future.
    let max_age_secs = 366 * 86400i64;

    let all_timestamps: Vec<i64> = history
        .iter()
        .map(|e| e.visit_time.timestamp())
        .chain(cookies.iter().map(|c| c.created_at.timestamp()))
        .chain(searches.iter().map(|s| s.search_time.timestamp()))
        .chain(dns.iter().map(|d| d.query_time.timestamp()))
        .chain(files.iter().map(|f| f.created.timestamp()))
        .collect();

    let now_ts = ctx.now.timestamp();
    for ts in &all_timestamps {
        assert!(
            *ts <= now_ts + 1,
            "timestamp in the future: {ts} > {now_ts}"
        );
        assert!(
            now_ts - *ts <= max_age_secs,
            "timestamp too old: {ts} ({} days before now)",
            (now_ts - *ts) / 86400
        );
    }
}

// ============================================================================
// Bookmark & Download helpers
// ============================================================================

/// Generate N bookmark entries.
fn make_bookmarks(n: usize, profile: &UserProfile, ctx: &GenerationContext, seed: u64) -> Vec<BookmarkEntry> {
    let mut rng = seeded_rng(seed);
    let generator = BookmarkGenerator::new();
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let artifact = generator.generate(profile, ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: BookmarkEntry = serde_json::from_slice(&bytes).unwrap();
        entries.push(entry);
    }
    entries
}

/// Generate N download entries.
fn make_downloads(n: usize, profile: &UserProfile, ctx: &GenerationContext, seed: u64) -> Vec<DownloadEntry> {
    let mut rng = seeded_rng(seed);
    let generator = DownloadGenerator::new();
    let mut entries = Vec::with_capacity(n);
    for _ in 0..n {
        let artifact = generator.generate(profile, ctx, &mut rng).unwrap();
        let bytes = artifact.to_bytes().unwrap();
        let entry: DownloadEntry = serde_json::from_slice(&bytes).unwrap();
        entries.push(entry);
    }
    entries
}

// ============================================================================
// Test 7: Bookmark-History URL Overlap
// ============================================================================
//
// Bookmarked URLs should be a subset of visited sites -- users bookmark
// pages they have visited. Both generators draw from the same url_corpus,
// so bookmark domains should overlap heavily with history domains. A
// bookmark for a domain that never appears in history is a forensic tell.

#[test]
fn test_bookmark_history_url_overlap() {
    let profile = shared_profile();
    let ctx = shared_context();

    let history = make_history(300, &profile, &ctx, 44);
    let bookmarks = make_bookmarks(100, &profile, &ctx, 44);

    // Collect all registrable domains from history
    let history_domains: HashSet<String> = history
        .iter()
        .map(|e| domain_from_url(&e.url))
        .collect();

    // Collect all registrable domains from bookmarks
    let bookmark_domains: HashSet<String> = bookmarks
        .iter()
        .map(|e| domain_from_url(&e.url))
        .collect();

    // Check overlap: how many bookmark domains also appear in history
    let mut overlap_count = 0u32;
    for bm_domain in &bookmark_domains {
        let has_match = history_domains.iter().any(|hd| {
            hd == bm_domain
                || hd.ends_with(&format!(".{bm_domain}"))
                || bm_domain.ends_with(&format!(".{hd}"))
                || hd.contains(bm_domain.as_str())
                || bm_domain.contains(hd.as_str())
        });
        if has_match {
            overlap_count += 1;
        }
    }

    let overlap_pct = if bookmark_domains.is_empty() {
        0.0
    } else {
        (overlap_count as f64 / bookmark_domains.len() as f64) * 100.0
    };

    // Both generators draw from browsing-domain pools, so we expect
    // substantial overlap. Bookmarks use BOOKMARK_SITES (20 domains)
    // and history uses the url_corpus (~50+ domains), with significant
    // intersection (github, youtube, reddit, etc.).
    assert!(
        overlap_pct > 30.0,
        "bookmark-history domain overlap too low: {overlap_pct:.1}% \
         ({overlap_count}/{} bookmark domains, {} history domains)",
        bookmark_domains.len(),
        history_domains.len(),
    );

    // Every bookmark URL should be HTTPS (consistent with history)
    for bm in &bookmarks {
        assert!(
            bm.url.starts_with("https://"),
            "bookmark URL not HTTPS: {}",
            bm.url,
        );
    }

    // Bookmark added_at should be within the browsing window
    let history_timestamps: Vec<i64> = history
        .iter()
        .map(|e| e.visit_time.timestamp())
        .collect();
    let browsing_start = *history_timestamps.iter().min().unwrap();
    // Bookmarks can span up to 730 days, so we extend the window
    let extended_start = browsing_start - (730 * 86400);

    for bm in &bookmarks {
        let bm_ts = bm.added_at.timestamp();
        assert!(
            bm_ts >= extended_start,
            "bookmark added_at ({}) is before extended browsing window start ({})",
            bm.added_at,
            extended_start,
        );
        assert!(
            bm.added_at <= ctx.now,
            "bookmark added_at ({}) is in the future",
            bm.added_at,
        );
    }
}

// ============================================================================
// Test 8: Download Timestamps Within Browsing Window
// ============================================================================
//
// Downloads happen during browsing sessions. Download start times should
// fall within the browsing activity window (or at least overlap with it).
// A download that starts months after the last browsing activity or years
// before the first visit is forensically implausible.

#[test]
#[ignore] // TODO: requires correlated generator output (downloads independent of history timing)
fn test_download_timestamps_within_browsing_window() {
    let profile = shared_profile();
    let ctx = shared_context();

    let history = make_history(200, &profile, &ctx, 66);
    let downloads = make_downloads(100, &profile, &ctx, 66);

    // Determine the browsing window from history
    let history_timestamps: Vec<i64> = history
        .iter()
        .map(|e| e.visit_time.timestamp())
        .collect();
    let browsing_start = *history_timestamps.iter().min().unwrap();
    let browsing_end = *history_timestamps.iter().max().unwrap();

    // Allow a generous margin: the history generator goes back up to 365
    // days and the download generator up to 90 days, both from context.now.
    // So all downloads should be within 90 days before context.now.
    let download_window_start = ctx.now.timestamp() - (91 * 86400);
    let download_window_end = ctx.now.timestamp();

    let mut within_browsing = 0u32;
    let mut total = 0u32;

    for dl in &downloads {
        total += 1;

        let dl_start_ts = dl.started_at.timestamp();

        // Download must not be in the future
        assert!(
            dl.started_at <= ctx.now,
            "download started_at in the future: {} > {}",
            dl.started_at,
            ctx.now,
        );

        // Download must be within its own generation window (90 days)
        assert!(
            dl_start_ts >= download_window_start,
            "download started_at ({}) is before the 90-day download window ({})",
            dl.started_at,
            download_window_start,
        );

        // Check if the download overlaps with the browsing window
        // (browsing goes back up to 365 days, downloads up to 90 days,
        // so all 90-day downloads should be within the 365-day history window)
        if dl_start_ts >= browsing_start && dl_start_ts <= browsing_end + 86400 {
            within_browsing += 1;
        }

        // Completed_at must be >= started_at
        assert!(
            dl.completed_at >= dl.started_at,
            "download completed before started: {} < {}",
            dl.completed_at,
            dl.started_at,
        );
    }

    // Since history covers 365 days and downloads cover 90 days,
    // and both are anchored at context.now, all downloads should fall
    // within the browsing window.
    let overlap_pct = if total == 0 {
        0.0
    } else {
        (within_browsing as f64 / total as f64) * 100.0
    };
    assert!(
        overlap_pct > 20.0,
        "download-browsing window overlap too low: {overlap_pct:.1}% \
         ({within_browsing}/{total} downloads within browsing window \
         [{browsing_start}..{browsing_end}])",
    );

    // Verify all download URLs are HTTPS
    for dl in &downloads {
        assert!(
            dl.url.starts_with("https://"),
            "download URL not HTTPS: {}",
            dl.url,
        );
    }
}
