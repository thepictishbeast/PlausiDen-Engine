//! Social media engagement metric generation — followers, likes, engagement rates.
//!
//! Generates plausible engagement snapshots that mirror real platform analytics:
//! follower/following counts, per-post engagement metrics, engagement rates, and
//! growth trends over configurable periods.

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

/// A snapshot of social media engagement metrics at a point in time.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct EngagementSnapshot {
    /// Artifact metadata.
    pub meta: ArtifactMetadata,
    /// Platform this snapshot was taken from.
    pub platform: String,
    /// Timestamp of the snapshot.
    pub timestamp: DateTime<Utc>,
    /// Follower/following counts.
    pub audience: AudienceMetrics,
    /// Engagement on a recent post.
    pub post_engagement: PostEngagement,
    /// Calculated engagement rate (interactions / followers).
    pub engagement_rate: f64,
    /// Follower growth over the measurement period.
    pub growth: GrowthTrend,
}

/// Follower and following counts for a platform.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct AudienceMetrics {
    /// Total follower count.
    pub followers: u64,
    /// Total following count.
    pub following: u64,
}

/// Engagement metrics for a single post.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct PostEngagement {
    /// Number of likes/favorites on the post.
    pub likes: u64,
    /// Number of retweets/reposts/shares.
    pub retweets: u64,
    /// Number of replies/comments.
    pub replies: u64,
}

/// Follower growth trend over a measurement period.
#[derive(Debug, Clone, Serialize, serde::Deserialize)]
pub struct GrowthTrend {
    /// Net followers gained (positive) or lost (negative) during the period.
    pub net_change: i64,
    /// Duration of the measurement period in days.
    pub period_days: u32,
}

impl Artifact for EngagementSnapshot {
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
        // Engagement rate should be between 0% and 100%.
        if self.engagement_rate < 0.0 || self.engagement_rate > 1.0 {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!(
                    "engagement rate {:.4} outside [0.0, 1.0]",
                    self.engagement_rate
                ),
            });
        }
        // Following should not vastly exceed followers for a real account
        // (spam-follow ratio > 50:1 is implausible for normal users).
        if self.audience.followers > 0
            && self.audience.following > self.audience.followers * 50
        {
            return Err(EngineError::ImplausibleArtifact {
                reason: "following-to-follower ratio implausibly high".into(),
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

/// Generates social media engagement snapshots.
pub struct EngagementGenerator;

impl EngagementGenerator {
    /// Create a new engagement generator.
    pub fn new() -> Self {
        Self
    }
}

impl Default for EngagementGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for EngagementGenerator {
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

        // Follower counts: most users have 50–5000 followers.
        let followers = Uniform::new_inclusive(50u64, 5000).sample(rng);
        // Following is typically 0.3x–2x of follower count.
        let follow_lo = followers * 3 / 10;
        let follow_hi = followers * 2;
        let following = Uniform::new_inclusive(follow_lo, follow_hi).sample(rng);

        // Post engagement scales with follower count.
        // Likes: 1–10% of followers.
        let like_ceil = (followers / 10).max(1);
        let likes = Uniform::new_inclusive(1u64, like_ceil).sample(rng);
        // Retweets: 0–20% of likes.
        let rt_ceil = (likes / 5).max(1);
        let retweets = Uniform::new_inclusive(0u64, rt_ceil).sample(rng);
        // Replies: 0–10% of likes.
        let reply_ceil = (likes / 10).max(1);
        let replies = Uniform::new_inclusive(0u64, reply_ceil).sample(rng);

        let total_interactions = likes + retweets + replies;
        let engagement_rate = if followers > 0 {
            total_interactions as f64 / followers as f64
        } else {
            0.0
        };

        // Growth trend: -20..+50 followers per period (7–30 day window).
        let period_days = Uniform::new_inclusive(7u32, 30).sample(rng);
        let net_change = Uniform::new_inclusive(-20i64, 50).sample(rng);

        let jitter = Uniform::new_inclusive(0i64, 3600).sample(rng);
        let timestamp = context.now - Duration::seconds(jitter);

        let meta = ArtifactMetadata::new(DataCategory::Social, timestamp, timestamp, 512)?;

        let snapshot = EngagementSnapshot {
            meta,
            platform: platform.to_string(),
            timestamp,
            audience: AudienceMetrics {
                followers,
                following,
            },
            post_engagement: PostEngagement {
                likes,
                retweets,
                replies,
            },
            engagement_rate,
            growth: GrowthTrend {
                net_change,
                period_days,
            },
        };
        snapshot.validate_plausibility()?;
        Ok(Box::new(snapshot))
    }

    fn category(&self) -> DataCategory {
        DataCategory::Social
    }

    fn forensic_weight(&self) -> u32 {
        50
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_engagement() {
        let g = EngagementGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(42);
        let a = g.generate(&p, &c, &mut r).unwrap();
        a.validate_plausibility().unwrap();
    }

    #[test]
    fn test_500_engagement_valid() {
        let g = EngagementGenerator::new();
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
    fn test_engagement_rate_bounded() {
        let g = EngagementGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        for s in 0..1000 {
            let mut r = seeded_rng(s);
            let a = g.generate(&p, &c, &mut r).unwrap();
            let b = a.to_bytes().unwrap();
            let snap: EngagementSnapshot = serde_json::from_slice(&b).unwrap();
            assert!(
                snap.engagement_rate >= 0.0 && snap.engagement_rate <= 1.0,
                "engagement rate {:.4} out of bounds at seed {s}",
                snap.engagement_rate
            );
        }
    }

    #[test]
    fn test_engagement_roundtrip() {
        let g = EngagementGenerator::new();
        let p = UserProfile::default();
        let c = GenerationContext::new();
        let mut r = seeded_rng(99);
        let a = g.generate(&p, &c, &mut r).unwrap();
        let bytes = a.to_bytes().unwrap();
        let snap: EngagementSnapshot = serde_json::from_slice(&bytes).unwrap();
        assert!(!snap.platform.is_empty());
        assert!(snap.audience.followers >= 50);
    }
}
