//! Social media activity generation -- posts, likes, shares, follows.
//!
//! Generates plausible social media activity artifacts across generic platforms.
//! Activity follows circadian patterns: heavier in evenings and weekends,
//! lighter during work hours. Platforms use generic names to avoid trademark issues.

use chrono::{DateTime, Datelike, Duration, Timelike, Utc};
use engine_core::error::{EngineError, Result};
use engine_core::profile::UserProfile;
use engine_core::traits::{
    Artifact, ArtifactMetadata, DataCategory, DataGenerator, GenerationContext, ResourceCost,
};
use rand::distributions::{Distribution, Uniform};
use rand::seq::SliceRandom;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};

/// A single social media activity event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialActivity {
    /// Artifact metadata.
    pub meta: ArtifactMetadata,
    /// Generic platform name (no trademarks).
    pub platform: String,
    /// The type of action performed.
    pub action_type: ActionType,
    /// Short content snippet (for posts/comments).
    pub content_snippet: Option<String>,
    /// Timestamp of the activity.
    pub timestamp: DateTime<Utc>,
    /// Engagement count (likes, views, etc.) accumulated.
    pub engagement_count: u64,
}

/// Types of social media actions a user can perform.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType {
    /// Creating a new post or status update.
    Post,
    /// Liking or favoriting content.
    Like,
    /// Commenting on existing content.
    Comment,
    /// Sharing or reposting content.
    Share,
    /// Following another user.
    Follow,
}

impl Artifact for SocialActivity {
    fn metadata(&self) -> &ArtifactMetadata {
        &self.meta
    }

    fn validate_plausibility(&self) -> Result<()> {
        self.meta.validate_timestamps()?;
        if self.platform.is_empty() {
            return Err(EngineError::ImplausibleArtifact {
                reason: "empty platform name".into(),
            });
        }
        // Posts and comments should have content.
        if matches!(self.action_type, ActionType::Post | ActionType::Comment)
            && self.content_snippet.is_none()
        {
            return Err(EngineError::ImplausibleArtifact {
                reason: format!("{:?} action missing content snippet", self.action_type),
            });
        }
        Ok(())
    }

    fn to_bytes(&self) -> Result<Vec<u8>> {
        serde_json::to_vec(self).map_err(EngineError::Serialization)
    }
}

/// Generic platform names -- no trademark issues.
const PLATFORMS: &[&str] = &[
    "microblog",
    "photoshare",
    "videotube",
    "linkboard",
    "chatroom",
];

/// Content snippets about daily life.
const DAILY_LIFE_SNIPPETS: &[&str] = &[
    "Finally got around to cleaning the apartment",
    "Spent the morning reading on the balcony",
    "Trying a new coffee shop today",
    "Long day but feeling productive",
    "Just finished a good book, need recommendations",
    "Woke up early and it was actually worth it",
    "Reorganized my desk and it feels great",
    "Taking a walk to clear my head",
];

/// Content snippets about food.
const FOOD_SNIPPETS: &[&str] = &[
    "Made pasta from scratch for the first time",
    "This ramen place is incredible",
    "Tried baking sourdough, results were okay",
    "Farmers market haul was amazing today",
    "Homemade pizza night is the best",
    "Found the perfect avocado toast recipe",
    "Meal prepping for the week ahead",
    "Breakfast burritos are underrated",
];

/// Content snippets about weather.
const WEATHER_SNIPPETS: &[&str] = &[
    "Beautiful sunset tonight",
    "Rain all day, perfect for staying in",
    "Finally warm enough to eat outside",
    "Snow is pretty but I am ready for spring",
    "That breeze is exactly what we needed",
    "Foggy morning, love the atmosphere",
    "Clear skies and good vibes",
    "Storm rolling in, looks dramatic",
];

/// Content snippets about events.
const EVENT_SNIPPETS: &[&str] = &[
    "Great turnout at the local market today",
    "Caught a live show last night, so good",
    "Community cleanup was a success",
    "Fun run this weekend, who is joining?",
    "Art exhibit downtown was worth the visit",
    "Board game night with friends was hilarious",
    "Neighborhood block party was a blast",
    "Open mic night did not disappoint",
];

/// Short comment snippets.
const COMMENT_SNIPPETS: &[&str] = &[
    "This is great!",
    "Totally agree with this",
    "Ha, so true",
    "Love this",
    "Needed to hear this today",
    "Where is this?",
    "Can you share more details?",
    "Adding this to my list",
    "Same here!",
    "Well said",
];

/// Compute a circadian activity multiplier for a given hour and weekday.
///
/// Returns a value between 0.1 (deep night / work hours) and 1.0 (peak evening / weekend).
/// Pattern: low overnight (0-6), moderate morning (7-9), low workday (10-17),
/// peak evening (18-23). Weekends boost all hours.
fn circadian_multiplier(hour: u32, weekday: chrono::Weekday) -> f64 {
    let is_weekend = matches!(weekday, chrono::Weekday::Sat | chrono::Weekday::Sun);
    let base = match hour {
        0..=5 => 0.1,
        6..=8 => 0.4,
        9..=11 => {
            if is_weekend {
                0.6
            } else {
                0.25
            }
        }
        12..=13 => 0.45, // lunch break bump
        14..=16 => {
            if is_weekend {
                0.6
            } else {
                0.2
            }
        }
        17..=18 => 0.6,
        19..=22 => 0.9,
        23 => 0.5,
        _ => 0.3,
    };
    if is_weekend {
        (base * 1.3_f64).min(1.0)
    } else {
        base
    }
}

/// Generates social media activity artifacts with circadian patterns.
pub struct ActivityGenerator;

impl ActivityGenerator {
    /// Create a new activity generator.
    pub fn new() -> Self {
        Self
    }
}

impl Default for ActivityGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl DataGenerator for ActivityGenerator {
    fn generate(
        &self,
        profile: &UserProfile,
        context: &GenerationContext,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<Box<dyn Artifact>> {
        let platform = PLATFORMS
            .choose(rng)
            .ok_or_else(|| EngineError::InvalidContext("empty platform list".into()))?;

        // Compute time offset with circadian weighting.
        // Generate a candidate hour offset and accept/reject based on circadian weight.
        let max_offset_secs = 86400i64; // 24 hours
        let tz_offset = i64::from(profile.activity_schedule.timezone_offset_hours) * 3600;
        let offset_secs = sample_circadian_offset(rng, context.now, tz_offset, max_offset_secs);
        let timestamp = context.now - Duration::seconds(offset_secs);

        // Action distribution: Like (35%), Post (15%), Comment (20%), Share (15%), Follow (15%)
        let roll = Uniform::new_inclusive(0u32, 99).sample(rng);
        let action_type = match roll {
            0..=34 => ActionType::Like,
            35..=49 => ActionType::Post,
            50..=69 => ActionType::Comment,
            70..=84 => ActionType::Share,
            _ => ActionType::Follow,
        };

        let content_snippet = match action_type {
            ActionType::Post => {
                let category_roll = Uniform::new_inclusive(0u32, 3).sample(rng);
                let pool = match category_roll {
                    0 => DAILY_LIFE_SNIPPETS,
                    1 => FOOD_SNIPPETS,
                    2 => WEATHER_SNIPPETS,
                    _ => EVENT_SNIPPETS,
                };
                pool.choose(rng).map(|s| (*s).to_string())
            }
            ActionType::Comment => COMMENT_SNIPPETS.choose(rng).map(|s| (*s).to_string()),
            _ => None,
        };

        // Engagement scales with risk level multiplier.
        let base_engagement = Uniform::new_inclusive(0u64, 200).sample(rng);
        let engagement_count =
            (base_engagement as f64 * profile.risk_level.rate_multiplier()) as u64;

        let meta = ArtifactMetadata::new(DataCategory::Social, timestamp, timestamp, 256)?;

        let activity = SocialActivity {
            meta,
            platform: (*platform).to_string(),
            action_type,
            content_snippet,
            timestamp,
            engagement_count,
        };
        activity.validate_plausibility()?;
        Ok(Box::new(activity))
    }

    fn category(&self) -> DataCategory {
        DataCategory::Social
    }

    fn forensic_weight(&self) -> u32 {
        50
    }

    fn resource_cost(&self) -> ResourceCost {
        ResourceCost {
            cpu_us: 50,
            disk_bytes: 256,
            network_bytes: 0,
        }
    }
}

/// Sample a time offset in seconds, biased by circadian patterns.
///
/// Uses rejection sampling: propose a random offset, compute the local hour,
/// check the circadian multiplier, and accept with that probability.
fn sample_circadian_offset(
    rng: &mut (impl RngCore + CryptoRng),
    now: DateTime<Utc>,
    tz_offset_secs: i64,
    max_offset: i64,
) -> i64 {
    let offset_dist = Uniform::new_inclusive(0i64, max_offset);
    let accept_dist = Uniform::new_inclusive(0.0f64, 1.0);

    // Try up to 20 times, then just accept the last sample (avoids infinite loop).
    for _ in 0..20 {
        let candidate = offset_dist.sample(rng);
        let candidate_time = now - Duration::seconds(candidate);
        let local_hour =
            ((candidate_time.hour() as i64 + tz_offset_secs / 3600) % 24 + 24) as u32 % 24;
        let weekday = candidate_time.weekday();
        let weight = circadian_multiplier(local_hour, weekday);
        if accept_dist.sample(rng) < weight {
            return candidate;
        }
    }
    // Fallback: return a random offset without circadian bias.
    offset_dist.sample(rng)
}

#[cfg(test)]
mod tests {
    use super::*;
    use engine_core::entropy::seeded_rng;

    #[test]
    fn test_generate_activity_basic() {
        let generator = ActivityGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(42);
        let artifact = generator
            .generate(&profile, &ctx, &mut rng)
            .expect("generation failed");
        artifact
            .validate_plausibility()
            .expect("plausibility check failed");
    }

    #[test]
    fn test_500_activities_all_valid() {
        let generator = ActivityGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        for seed in 0..500 {
            let mut rng = seeded_rng(seed);
            let artifact = generator
                .generate(&profile, &ctx, &mut rng)
                .unwrap_or_else(|e| panic!("seed {seed} failed generation: {e}"));
            artifact
                .validate_plausibility()
                .unwrap_or_else(|e| panic!("seed {seed} failed plausibility: {e}"));
        }
    }

    #[test]
    fn test_action_type_distribution() {
        let generator = ActivityGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut likes = 0u32;
        let mut posts = 0u32;
        let mut comments = 0u32;
        let mut shares = 0u32;
        let mut follows = 0u32;

        for seed in 0..1000 {
            let mut rng = seeded_rng(seed);
            let artifact = generator.generate(&profile, &ctx, &mut rng).expect("gen");
            let bytes = artifact.to_bytes().expect("serialize");
            let act: SocialActivity = serde_json::from_slice(&bytes).expect("deserialize");
            match act.action_type {
                ActionType::Like => likes += 1,
                ActionType::Post => posts += 1,
                ActionType::Comment => comments += 1,
                ActionType::Share => shares += 1,
                ActionType::Follow => follows += 1,
            }
        }
        // Like ~35%, Post ~15%, Comment ~20%, Share ~15%, Follow ~15%
        assert!(likes > 250 && likes < 450, "likes ~35%, got {likes}/1000");
        assert!(posts > 80 && posts < 250, "posts ~15%, got {posts}/1000");
        assert!(
            comments > 120 && comments < 300,
            "comments ~20%, got {comments}/1000"
        );
        assert!(
            shares > 80 && shares < 250,
            "shares ~15%, got {shares}/1000"
        );
        assert!(
            follows > 80 && follows < 250,
            "follows ~15%, got {follows}/1000"
        );
    }

    #[test]
    fn test_platforms_are_generic() {
        let generator = ActivityGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let generic_names = [
            "microblog",
            "photoshare",
            "videotube",
            "linkboard",
            "chatroom",
        ];

        for seed in 0..200 {
            let mut rng = seeded_rng(seed);
            let artifact = generator.generate(&profile, &ctx, &mut rng).expect("gen");
            let bytes = artifact.to_bytes().expect("serialize");
            let act: SocialActivity = serde_json::from_slice(&bytes).expect("deserialize");
            assert!(
                generic_names.contains(&act.platform.as_str()),
                "platform '{}' is not generic at seed {seed}",
                act.platform
            );
        }
    }

    #[test]
    fn test_posts_and_comments_have_content() {
        let generator = ActivityGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();

        for seed in 0..500 {
            let mut rng = seeded_rng(seed);
            let artifact = generator.generate(&profile, &ctx, &mut rng).expect("gen");
            let bytes = artifact.to_bytes().expect("serialize");
            let act: SocialActivity = serde_json::from_slice(&bytes).expect("deserialize");
            if matches!(act.action_type, ActionType::Post | ActionType::Comment) {
                assert!(
                    act.content_snippet.is_some(),
                    "action {:?} missing content at seed {seed}",
                    act.action_type
                );
            }
        }
    }

    #[test]
    fn test_circadian_multiplier_values() {
        // Deep night should be low.
        assert!(circadian_multiplier(3, chrono::Weekday::Tue) < 0.2);
        // Peak evening should be high.
        assert!(circadian_multiplier(20, chrono::Weekday::Wed) > 0.8);
        // Weekend evening should be at or near max.
        assert!(circadian_multiplier(20, chrono::Weekday::Sat) > 0.9);
        // Workday midday should be low.
        assert!(circadian_multiplier(14, chrono::Weekday::Mon) < 0.3);
        // Weekend midday should be higher.
        assert!(circadian_multiplier(14, chrono::Weekday::Sun) > 0.5);
    }

    #[test]
    fn test_roundtrip_serialization() {
        let generator = ActivityGenerator::new();
        let profile = UserProfile::default();
        let ctx = GenerationContext::new();
        let mut rng = seeded_rng(77);
        let artifact = generator.generate(&profile, &ctx, &mut rng).expect("gen");
        let bytes = artifact.to_bytes().expect("to_bytes");
        let deserialized: SocialActivity = serde_json::from_slice(&bytes).expect("deserialize");
        assert!(!deserialized.platform.is_empty());
        assert!(deserialized.engagement_count <= 2000);
    }
}
