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
        "/about", "/contact", "/help", "/terms", "/privacy",
        "/search?q=test", "/article/2026/trending-topic",
        "/category/popular", "/user/profile", "/settings",
    ];

    slugs.iter().take(3).map(|s| format!("{base_url}{s}")).collect()
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
