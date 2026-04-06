//! Social media post content generation — tweets, captions, view counts, shares.
//!
//! Generates plausible social media post content: short text posts within
//! platform character limits, photo captions with hashtags, story/reel view
//! counts, and share/repost metadata.

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

/// A generated social media post with content and engagement metadata.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ContentPost {
    /// Artifact metadata.
    pub meta: ArtifactMetadata,
    /// Platform the post belongs to.
    pub platform: String,
    /// Timestamp of the post.
    pub timestamp: DateTime<Utc>,
    /// The type of content posted.
    pub content_type: ContentType,
    /// Post body text (max 280 chars for tweet-length posts).
    pub body: String,
    /// Hashtags attached to the post.
    pub hashtags: Vec<String>,
    /// View count for stories/reels (if applicable).
    pub view_count: Option<u64>,
    /// Share/repost metadata (if this is a share).
    pub share_meta: Option<ShareMetadata>,
}

/// The kind of social media content.
#[derive(Debug, Clone, Serialize, serde::Deserialize, PartialEq)]
pub enum ContentType {
    /// Short text post (tweet-length, 280 chars max).
    TextPost,
    /// Photo with caption and hashtags.
    PhotoCaption,
    /// Story or reel with view counts.
    StoryReel,
    /// Share/repost of another user's content.
    ShareRepost,
}

/// Metadata for a shared or reposted piece of content.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct ShareMetadata {
    /// Username of the original author.
    pub original_author: String,
    /// Platform of the original post.
    pub original_platform: String,
    /// Whether the share includes added commentary.
    pub quote: bool,
}

impl Artifact for ContentPost {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.platform.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty platform".into(),
            });
        }
        // Text posts must respect the 280-character limit.
        if self.content_type == ContentType::TextPost && self.body.len() > 280 {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!(
                    "text post exceeds 280 chars ({} chars)",
                    self.body.len()
                ),
            });
        }
        // Story/reel view counts should exist and be positive.
        if self.content_type == ContentType::StoryReel {
            match self.view_count {
                None => {
                    return Err(EngineError::ImplausibleArtifact {
                        reason: "story/reel missing view count".into(),
                    });
                }
                Some(0) => {
                    return Err(EngineError::ImplausibleArtifact {
                        reason: "story/reel with zero views is implausible".into(),
                    });
                }
                _ => {}
            }
        }
        // Share/repost must have share metadata.
        if self.content_type == ContentType::ShareRepost && self.share_meta.is_none() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "share/repost missing share metadata".into(),
            });
        }
        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

const PLATFORMS: &[&str] = &[
    "Twitter/X",
    "Instagram",
    "Facebook",
    "Reddit",
    "LinkedIn",
    "TikTok",
    "Mastodon",
    "Threads",
];

const TEXT_TEMPLATES: &[&str] = &[
    "Just discovered something fascinating about",
    "Monday mood. Back at it.",
    "This week has been absolutely wild",
    "Finally got around to trying",
    "Anyone else feel like time is moving faster lately?",
    "Hot take: pineapple on pizza is actually good",
    "Can we talk about how underrated",
    "Today I learned that",
    "Not sure how I feel about the new update",
    "Appreciate the little things",
    "Grateful for this community",
    "Working from home has its perks",
    "Throwback to that time",
    "A reminder to be kind today",
    "What a great start to the week!",
];

const CAPTION_TEMPLATES: &[&str] = &[
    "Golden hour never disappoints",
    "Views from the top",
    "Just another beautiful day",
    "Weekend vibes only",
    "Making memories worth keeping",
    "Life is better outside",
    "Found my new favorite spot",
    "Sunday reset in progress",
    "Living for moments like these",
    "Chasing light and good vibes",
];

const HASHTAGS: &[&str] = &[
    "#photography",
    "#nofilter",
    "#instagood",
    "#travel",
    "#nature",
    "#food",
    "#fitness",
    "#ootd",
    "#love",
    "#life",
    "#weekendvibes",
    "#sunset",
    "#explore",
    "#motivation",
    "#techlife",
    "#mindfulness",
    "#photooftheday",
    "#blessed",
    "#summer",
    "#goals",
];

const TOPICS: &[&str] = &[
    "machine learning",
    "the latest phone release",
    "remote work culture",
    "that new restaurant downtown",
    "this show on Netflix",
    "sustainable living",
    "mechanical keyboards",
    "the housing market",
];

/// Generates social media post content.
pub struct ContentGenerator;

impl ContentGenerator {
    /// Create a new content generator.
    pub fn new() -> Self {
        Self
    }
}

impl Default for ContentGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for ContentGenerator {
    fn generate(
        &self,
        _profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        // SAFETY: PLATFORMS is a non-empty const slice.
        let platform = PLATFORMS
            .choose(rng)
            .copied()
            .expect("PLATFORMS is a non-empty const slice");

        // Content type distribution: text (40%), photo (30%), story (20%), share (10%).
        let roll = Uniform::new_inclusive(0u32, 99).sample(rng);
        let content_type = match roll {
            0..=39 => ContentType::TextPost,
            40..=69 => ContentType::PhotoCaption,
            70..=89 => ContentType::StoryReel,
            _ => ContentType::ShareRepost,
        };

        let body = match content_type {
            ContentType::TextPost => build_text_post(rng),
            ContentType::PhotoCaption => CAPTION_TEMPLATES
                .choose(rng)
                .copied()
                .expect("CAPTION_TEMPLATES is a non-empty const slice")
                .to_string(),
            ContentType::StoryReel => String::new(),
            ContentType::ShareRepost => {
                let quote_roll = Uniform::new_inclusive(0u32, 1).sample(rng);
                if quote_roll == 1 {
                    "This is worth reading".to_string()
                } else {
                    String::new()
                }
            }
        };

        // Hashtags: photo captions get 2–6, text posts get 0–2, others get 0.
        let hashtags = match content_type {
            ContentType::PhotoCaption => pick_hashtags(rng, 2, 6),
            ContentType::TextPost => pick_hashtags(rng, 0, 2),
            _ => Vec::new(),
        };

        // View count only for stories/reels.
        let view_count = if content_type == ContentType::StoryReel {
            Some(Uniform::new_inclusive(5u64, 5000).sample(rng))
        } else {
            None
        };

        // Share metadata only for shares/reposts.
        let share_meta = if content_type == ContentType::ShareRepost {
            let orig_user_id = Uniform::new_inclusive(1000u32, 9999).sample(rng);
            let orig_platform = PLATFORMS
                .choose(rng)
                .copied()
                .expect("PLATFORMS is a non-empty const slice");
            let quote = !body.is_empty();
            Some(ShareMetadata {
                original_author: format!("user_{orig_user_id}"),
                original_platform: orig_platform.to_string(),
                quote,
            })
        } else {
            None
        };

        let jitter = Uniform::new_inclusive(0i64, 3600).sample(rng);
        let timestamp = context.now - Duration::seconds(jitter);

        let meta = ArtifactMetadata::new(DataCategory::Social, timestamp, timestamp, 256)?;

        let post = ContentPost {
            meta,
            platform: platform.to_string(),
            timestamp,
            content_type,
            body,
            hashtags,
            view_count,
            share_meta,
        };
        post.validate_plausibility()?;
        Ok(Box::new(post))
    }

    fn category(&self) -> DataCategory {
        DataCategory::Social
    }

    fn forensic_weight(&self) -> u32 {
        50
    }
}

/// Build a short text post by combining a template with an optional topic.
/// Always stays within 280 characters.
fn build_text_post(rng: &mut (impl RngCore + CryptoRng)) -> String {
    // SAFETY: TEXT_TEMPLATES and TOPICS are non-empty const slices.
    let template = TEXT_TEMPLATES
        .choose(rng)
        .copied()
        .expect("TEXT_TEMPLATES is a non-empty const slice");
    // Half the time, append a topic if the template ends with a preposition-like word.
    let needs_topic = template.ends_with("about")
        || template.ends_with("with")
        || template.ends_with("trying")
        || template.ends_with("underrated")
        || template.ends_with("that");
    if needs_topic {
        let topic = TOPICS
            .choose(rng)
            .copied()
            .expect("TOPICS is a non-empty const slice");
        let candidate = format!("{template} {topic}.");
        // Truncate to 280 chars if somehow too long.
        if candidate.len() <= 280 {
            return candidate;
        }
    }
    template.to_string()
}

/// Pick between `lo` and `hi` unique hashtags from the pool.
fn pick_hashtags(rng: &mut (impl RngCore + CryptoRng), lo: usize, hi: usize) -> Vec<String> {
    let count = Uniform::new_inclusive(lo, hi).sample(rng);
    let mut pool: Vec<&&str> = HASHTAGS.iter().collect();
    pool.shuffle(rng);
    pool.into_iter().take(count).map(|h| (*h).to_string()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_content() {
        let g = ContentGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);
        let a = g.generate(&p, &c, &mut r).unwrap();
        a.validate_plausibility().unwrap();
    }

    #[test]
    fn test_500_content_valid() {
        let g = ContentGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..500 {
            let mut r = seeded_rng(s);
            g.generate(&p, &c, &mut r)
                .unwrap()
                .validate_plausibility()
                .unwrap();
        }
    }

    #[test]
    fn test_text_posts_under_280_chars() {
        let g = ContentGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..1000 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let post: ContentPost = serde_json::from_slice(&b).unwrap();
            if post.content_type == ContentType::TextPost {
                assert!(
                    post.body.len() <= 280,
                    "text post body {} chars at seed {s}",
                    post.body.len()
                );
            }
        }
    }

    #[test]
    fn test_content_type_distribution() {
        let g = ContentGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut text = 0u32;
        let mut photo = 0u32;
        let mut story = 0u32;
        let mut share = 0u32;
        for s in 0..1000 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let post: ContentPost = serde_json::from_slice(&b).unwrap();
            match post.content_type {
                ContentType::TextPost => text += 1,
                ContentType::PhotoCaption => photo += 1,
                ContentType::StoryReel => story += 1,
                ContentType::ShareRepost => share += 1,
            }
        }
        assert!(text > 300 && text < 500, "text ~40%, got {text}/1000");
        assert!(photo > 200 && photo < 400, "photo ~30%, got {photo}/1000");
        assert!(story > 100 && story < 300, "story ~20%, got {story}/1000");
        assert!(share > 50 && share < 200, "share ~10%, got {share}/1000");
    }

    #[test]
    fn test_content_roundtrip() {
        let g = ContentGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(7);
        let a = g.generate(&p, &c, &mut r).unwrap();
        let bytes = a.to_bytes().unwrap();
        let post: ContentPost = serde_json::from_slice(&bytes).unwrap();
        assert!(!post.platform.is_empty());
    }
}
