//! Social media activity generation — posts, likes, shares, follows.

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

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct SocialEntry {
    pub meta: ArtifactMetadata,
    pub platform: String,
    pub action: SocialAction,
    pub timestamp: DateTime<Utc>,
    pub content: Option<String>,
    pub target_user: Option<String>,
}

#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub enum SocialAction {
    Post,
    Like,
    Share,
    Comment,
    Follow,
    Unfollow,
    ViewProfile,
    ScrollFeed,
}

impl Artifact for SocialEntry {
    fn metadata(&self) -> &ArtifactMetadata { &self.meta }
    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.platform.is_empty() {
            return Err(EngineError::ImplausibleArtifact { reason: "empty platform".into() });
        }
        Ok(())
    }
    fn to_bytes(&self) -> Result<Vec<u8>> { serde_json::to_vec(self).map_err(EngineError::Serialization) }
}

const PLATFORMS: &[&str] = &["Twitter/X", "Instagram", "Facebook", "Reddit", "LinkedIn", "TikTok", "Mastodon", "Threads"];

const POST_TEMPLATES: &[&str] = &[
    "Just finished reading an amazing article about",
    "Anyone else having issues with",
    "Great weather today!",
    "Can't believe what happened at",
    "Working on something exciting",
    "This is a really interesting perspective on",
    "Happy birthday to my friend",
    "Just got back from a wonderful trip",
    "Loving the new update to",
    "Does anyone have recommendations for",
];

pub struct SocialGenerator;
impl SocialGenerator { pub fn new() -> Self { Self } }
impl Default for SocialGenerator { fn default() -> Self { Self::new() } }

impl DataGenerator for SocialGenerator {
    fn generate(&self, _profile: &UserProfile, context: &GenerationContext, rng: &mut (impl RngCore + CryptoRng)) -> Result<Box<dyn Artifact>> {
        let platform = PLATFORMS.choose(rng).unwrap();

        // Action distribution: scrolling (40%), likes (25%), posts (10%), comments (10%), shares (5%), other (10%)
        let roll = Uniform::new_inclusive(0u32, 99).sample(rng);
        let action = match roll {
            0..=39 => SocialAction::ScrollFeed,
            40..=64 => SocialAction::Like,
            65..=74 => SocialAction::Post,
            75..=84 => SocialAction::Comment,
            85..=89 => SocialAction::Share,
            90..=94 => SocialAction::Follow,
            95..=97 => SocialAction::ViewProfile,
            _ => SocialAction::Unfollow,
        };

        let content = match &action {
            SocialAction::Post => Some(POST_TEMPLATES.choose(rng).unwrap().to_string()),
            SocialAction::Comment => Some("Great post!".to_string()),
            _ => None,
        };

        let target_user = match &action {
            SocialAction::Like | SocialAction::Follow | SocialAction::Unfollow | SocialAction::ViewProfile => {
                Some(format!("user_{}", Uniform::new_inclusive(1000u32, 9999).sample(rng)))
            }
            _ => None,
        };

        let jitter = Uniform::new_inclusive(0i64, 3600).sample(rng);
        let timestamp = context.now - Duration::seconds(jitter);

        let meta = ArtifactMetadata::new(DataCategory::Social, timestamp, timestamp, 256)?;

        let entry = SocialEntry { meta, platform: platform.to_string(), action, timestamp, content, target_user };
        entry.validate_plausibility()?;
        Ok(Box::new(entry))
    }

    fn category(&self) -> DataCategory { DataCategory::Social }
    fn forensic_weight(&self) -> u32 { 50 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_social() {
        let g = SocialGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);
        let a = g.generate(&p, &c, &mut r).unwrap();
        a.validate_plausibility().unwrap();
    }

    #[test]
    fn test_500_social_valid() {
        let g = SocialGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..500 { let mut r = seeded_rng(s); g.generate(&p, &c, &mut r).unwrap().validate_plausibility().unwrap(); }
    }

    #[test]
    fn test_action_distribution() {
        let g = SocialGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut scrolls = 0u32;
        for s in 0..1000 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let e: SocialEntry = serde_json::from_slice(&b).unwrap();
            if matches!(e.action, SocialAction::ScrollFeed) { scrolls += 1; }
        }
        assert!(scrolls > 300 && scrolls < 500, "scrolling should be ~40%, got {scrolls}/1000");
    }
}
