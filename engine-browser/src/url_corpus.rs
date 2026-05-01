//! URL corpus organized by interest category.
//!
//! These are real, well-known domains that a real person would visit.
//! The corpus drives realistic history, cookie, and search generation.

use engine_core::profile::InterestCategory;

/// Returns a list of plausible URLs for a given interest category.
pub fn urls_for_category(category: &InterestCategory) -> &'static [&'static str] {
    match category {
        InterestCategory::News => &[
            "https://www.nytimes.com",
            "https://www.washingtonpost.com",
            "https://www.bbc.com/news",
            "https://www.reuters.com",
            "https://apnews.com",
            "https://www.theguardian.com",
            "https://www.cnn.com",
            "https://www.npr.org",
            "https://news.ycombinator.com",
            "https://arstechnica.com",
        ],
        InterestCategory::Technology => &[
            "https://stackoverflow.com",
            "https://github.com",
            "https://www.reddit.com/r/programming",
            "https://dev.to",
            "https://medium.com",
            "https://www.wired.com",
            "https://techcrunch.com",
            "https://www.theverge.com",
            "https://docs.rs",
            "https://crates.io",
            // Software-vendor landing pages — anchors for the download
            // domains in `downloads::DOWNLOAD_TEMPLATES`. Including
            // these in history makes downloads from the matching CDN
            // subdomains forensically plausible (a user who downloads
            // Firefox first visited mozilla.org). Cross-checked by
            // `downloads::tests::test_every_download_domain_has_corpus_anchor`.
            "https://www.mozilla.org/firefox/",
            "https://www.google.com/chrome/",
            "https://www.libreoffice.org",
            "https://www.documentfoundation.org",
            "https://ubuntu.com/download",
            "https://zoom.us",
            "https://www.rust-lang.org",
            "https://pypi.org",
            "https://files.pythonhosted.org",
            "https://unsplash.com",
        ],
        InterestCategory::Shopping => &[
            "https://www.amazon.com",
            "https://www.ebay.com",
            "https://www.walmart.com",
            "https://www.target.com",
            "https://www.bestbuy.com",
            "https://www.etsy.com",
            "https://www.costco.com",
            "https://www.homedepot.com",
        ],
        InterestCategory::Entertainment => &[
            "https://www.youtube.com",
            "https://www.netflix.com",
            "https://www.twitch.tv",
            "https://www.imdb.com",
            "https://www.spotify.com",
            "https://www.reddit.com",
            "https://www.rottentomatoes.com",
            "https://letterboxd.com",
        ],
        InterestCategory::Social => &[
            "https://twitter.com",
            "https://www.facebook.com",
            "https://www.instagram.com",
            "https://www.linkedin.com",
            "https://www.reddit.com",
            "https://mastodon.social",
            "https://bsky.app",
        ],
        InterestCategory::Academic => &[
            "https://scholar.google.com",
            "https://arxiv.org",
            "https://www.jstor.org",
            "https://pubmed.ncbi.nlm.nih.gov",
            "https://www.researchgate.net",
            "https://www.sciencedirect.com",
            "https://en.wikipedia.org",
            "https://www.semanticscholar.org",
        ],
        InterestCategory::Finance => &[
            "https://www.bankofamerica.com",
            "https://www.chase.com",
            "https://finance.yahoo.com",
            "https://www.investopedia.com",
            "https://www.bloomberg.com",
            "https://www.marketwatch.com",
            "https://www.mint.com",
        ],
        InterestCategory::Health => &[
            "https://www.webmd.com",
            "https://www.mayoclinic.org",
            "https://www.nih.gov",
            "https://www.healthline.com",
            "https://www.cdc.gov",
            "https://medlineplus.gov",
        ],
        InterestCategory::Travel => &[
            "https://www.google.com/travel",
            "https://www.booking.com",
            "https://www.airbnb.com",
            "https://www.tripadvisor.com",
            "https://www.kayak.com",
            "https://www.expedia.com",
        ],
        InterestCategory::Food => &[
            "https://www.allrecipes.com",
            "https://www.foodnetwork.com",
            "https://www.doordash.com",
            "https://www.grubhub.com",
            "https://www.ubereats.com",
            "https://www.yelp.com",
        ],
        InterestCategory::Gaming => &[
            "https://store.steampowered.com",
            "https://www.ign.com",
            "https://www.reddit.com/r/gaming",
            "https://www.twitch.tv",
            "https://www.polygon.com",
            "https://www.gamespot.com",
        ],
        InterestCategory::Music => &[
            "https://www.spotify.com",
            "https://music.youtube.com",
            "https://soundcloud.com",
            "https://www.last.fm",
            "https://bandcamp.com",
            "https://pitchfork.com",
        ],
        InterestCategory::Government => &[
            "https://www.usa.gov",
            "https://www.congress.gov",
            "https://www.whitehouse.gov",
            "https://www.gpo.gov",
            "https://www.irs.gov",
            "https://www.ssa.gov",
        ],
        InterestCategory::Legal => &[
            "https://www.law.cornell.edu",
            "https://supreme.justia.com",
            "https://www.findlaw.com",
            "https://www.courtlistener.com",
            "https://www.aclu.org",
            "https://www.eff.org",
        ],
        InterestCategory::Weather => &[
            "https://weather.gov",
            "https://www.accuweather.com",
            "https://www.weather.com",
            "https://www.wunderground.com",
        ],
        InterestCategory::Reference => &[
            "https://en.wikipedia.org",
            "https://www.britannica.com",
            "https://www.merriam-webster.com",
            "https://www.wolframalpha.com",
            "https://www.khanacademy.org",
        ],
        InterestCategory::Documentation => &[
            "https://docs.rs",
            "https://doc.rust-lang.org",
            "https://developer.mozilla.org",
            "https://docs.python.org",
            "https://devdocs.io",
            "https://man7.org",
        ],
        _ => &[
            "https://www.google.com",
            "https://en.wikipedia.org",
            "https://www.reddit.com",
        ],
    }
}

/// Returns plausible subpages for a given base URL.
pub fn subpages_for_url(base_url: &str) -> Vec<String> {
    let slugs = [
        "/about",
        "/contact",
        "/help",
        "/terms",
        "/privacy",
        "/search?q=test",
        "/article/2026/trending-topic",
        "/category/popular",
        "/user/profile",
        "/settings",
    ];

    slugs
        .iter()
        .take(3)
        .map(|s| format!("{base_url}{s}"))
        .collect()
}

/// Search engine query URLs.
pub fn search_url(engine: &str, query: &str) -> String {
    let encoded = query.replace(' ', "+");
    match engine {
        "scholar.google.com" => format!("https://scholar.google.com/scholar?q={encoded}"),
        "duckduckgo.com" => format!("https://duckduckgo.com/?q={encoded}"),
        _ => format!("https://www.google.com/search?q={encoded}"),
    }
}

/// Extract the registered domain (eTLD+1, naively) from an URL.
/// Returns the part after `://` up to the first `/` or `?`, with
/// the `www.` prefix stripped. This is a best-effort heuristic
/// good enough for download/history correlation checks; we are not
/// trying to handle every edge-case TLD.
#[must_use]
pub fn registered_domain(url: &str) -> &str {
    let after_scheme = url.split_once("://").map_or(url, |(_, rest)| rest);
    let host = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);
    host.strip_prefix("www.").unwrap_or(host)
}

/// True when `download_domain` is "covered" by `corpus_url` — either
/// a direct domain match or `download_domain` ends with the corpus's
/// registered domain (e.g. `cdn.mozilla.net` covered by
/// `mozilla.org` returns false; covered by `mozilla.net` returns
/// true; covered by `developer.mozilla.org` returns false). Used by
/// the cross-artifact correlation test that asserts every download
/// template has a matching corpus anchor.
#[must_use]
pub fn download_covered_by(download_domain: &str, corpus_url: &str) -> bool {
    let corpus = registered_domain(corpus_url);
    if download_domain == corpus {
        return true;
    }
    // Match parent or subdomain along the dot boundary so
    // `mozilla.net` doesn't accidentally match `notmozilla.net`.
    let dl = download_domain.strip_prefix("www.").unwrap_or(download_domain);
    let corpus_root = corpus
        .rsplit('.')
        .take(2)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join(".");
    let dl_root = dl
        .rsplit('.')
        .take(2)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join(".");
    !corpus_root.is_empty() && corpus_root == dl_root
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registered_domain_strips_scheme_and_www() {
        assert_eq!(registered_domain("https://www.example.com/path"), "example.com");
        assert_eq!(registered_domain("https://example.com"), "example.com");
        assert_eq!(registered_domain("https://sub.example.com/"), "sub.example.com");
    }

    #[test]
    fn download_covered_matches_two_label_root() {
        // Direct match
        assert!(download_covered_by("zoom.us", "https://zoom.us"));
        // Subdomain → parent root match
        assert!(download_covered_by("cdn.mozilla.net", "https://mozilla.net"));
        assert!(download_covered_by("dl.google.com", "https://www.google.com/chrome/"));
        // Different root → no match
        assert!(!download_covered_by("evil.com", "https://example.com"));
        assert!(!download_covered_by("notmozilla.net", "https://mozilla.net"));
    }
}
