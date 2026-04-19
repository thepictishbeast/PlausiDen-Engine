//! Bookmark generation — realistic bookmarks matching browsing profile.

use chrono::{DateTime, Duration, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext, ResourceCost,
};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct BookmarkEntry {
    pub meta: ArtifactMetadata,
    pub url: String,
    pub title: String,
    pub folder: String,
    pub added_at: DateTime<Utc>,
}

impl Artifact for BookmarkEntry {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }
    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.url.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty bookmark URL".into(),
            });
        }
        if self.title.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty bookmark title".into(),
            });
        }
        Ok(())
    }
    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

const BOOKMARK_SITES: &[(&str, &str, &str)] = &[
    ("https://github.com", "GitHub", "Development"),
    ("https://stackoverflow.com", "Stack Overflow", "Development"),
    ("https://docs.rs", "Docs.rs", "Development"),
    ("https://news.ycombinator.com", "Hacker News", "News"),
    ("https://www.reuters.com", "Reuters", "News"),
    ("https://www.wikipedia.org", "Wikipedia", "Reference"),
    ("https://www.wolframalpha.com", "Wolfram Alpha", "Reference"),
    ("https://mail.google.com", "Gmail", "Email"),
    ("https://drive.google.com", "Google Drive", "Cloud"),
    ("https://www.dropbox.com", "Dropbox", "Cloud"),
    ("https://www.amazon.com", "Amazon", "Shopping"),
    ("https://www.youtube.com", "YouTube", "Entertainment"),
    ("https://www.netflix.com", "Netflix", "Entertainment"),
    ("https://www.reddit.com", "Reddit", "Social"),
    ("https://twitter.com", "X (Twitter)", "Social"),
    ("https://www.linkedin.com", "LinkedIn", "Professional"),
    (
        "https://calendar.google.com",
        "Google Calendar",
        "Productivity",
    ),
    ("https://trello.com", "Trello", "Productivity"),
    ("https://www.notion.so", "Notion", "Productivity"),
    ("https://weather.com", "Weather", "Utilities"),
];

pub struct BookmarkGenerator;
impl BookmarkGenerator {
    pub fn new() -> Self {
        Self
    }
}
impl Default for BookmarkGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for BookmarkGenerator {
    fn generate(
        &self,
        _profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        // SAFETY: BOOKMARK_SITES is a non-empty const slice — choose()
        // only returns None on empty input. Annotated per AVP-2.
        let (url, title, folder) = BOOKMARK_SITES
            .choose(rng)
            .expect("BOOKMARK_SITES is a non-empty const slice");
        let days_ago = Uniform::new_inclusive(1i64, 730).sample(rng);
        let added_at = context.now - Duration::days(days_ago);
        let meta = ArtifactMetadata::new(DataCategory::BrowserActivity, added_at, added_at, 256)?;

        let entry = BookmarkEntry {
            meta,
            url: url.to_string(),
            title: title.to_string(),
            folder: folder.to_string(),
            added_at,
        };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }
    fn category(&self) -> DataCategory {
        DataCategory::BrowserActivity
    }
    fn forensic_weight(&self) -> u32 {
        60
    }
    fn resource_cost(&self) -> ResourceCost {
        ResourceCost {
            cpu_us: 10,
            disk_bytes: 128,
            network_bytes: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_bookmark() {
        let g = BookmarkGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);
        let a = g.generate(&p, &c, &mut r).unwrap();
        a.validate_plausibility().unwrap();
        let b = a.to_bytes().unwrap();
        let e: BookmarkEntry = serde_json::from_slice(&b).unwrap();
        assert!(!e.url.is_empty());
        assert!(!e.title.is_empty());
        assert!(!e.folder.is_empty());
    }

    #[test]
    fn test_200_bookmarks_valid() {
        let g = BookmarkGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..200 {
            let mut r = seeded_rng(s);
            g.generate(&p, &c, &mut r)
                .unwrap()
                .validate_plausibility()
                .unwrap();
        }
    }

    #[test]
    fn test_bookmarks_have_folders() {
        let g = BookmarkGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut folders = std::collections::HashSet::new();
        for s in 0..100 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: BookmarkEntry = serde_json::from_slice(&b).unwrap();
            folders.insert(e.folder);
        }
        assert!(folders.len() > 3, "should have multiple bookmark folders");
    }
}
